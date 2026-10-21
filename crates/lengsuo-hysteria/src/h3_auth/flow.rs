//! 认证请求/应答的**流程**：建三条 HTTP/3 单向流 → 写 HEADERS →
//! 读响应 → QPACK 解码 → 解析响应头 → 校验状态码。

use quinn::{Connection, RecvStream};

use crate::qpack::{self, HeaderField};
use crate::varint;

use super::constants::{
    CLOSE_ERR_CODE_PROTOCOL_ERROR, COMMON_HEADER_CC_RX, COMMON_HEADER_PADDING, FRAME_HEADERS,
    FRAME_SETTINGS, MAX_RESPONSE_BYTES, REQUEST_HEADER_AUTH, STATUS_AUTH_OK, STREAM_TYPE_QPACK_ENCODER,
    URL_HOST, URL_PATH,
};
use super::datagram::SeedFiller;
use super::error::AuthError;
use super::outcome::{AuthOutcome, H3ControlStreams};

/// QPACK encoder 流缓冲上限。
const MAX_ENCODER_BUFFER: usize = 1024 * 1024;

/// 执行 H3 认证。成功返回响应信息与需保活的控制流。
///
/// `cc_rx` 是 `Hysteria-CC-RX` 请求头取值（0 = 未设置，与参考实现
/// `quicParams.BrutalDown` 默认一致）。`auth` 是认证密码，不得出现在
/// 任何日志或错误文本中。
pub async fn authenticate(
    conn: &Connection,
    auth: &str,
    cc_rx: u64,
) -> Result<(AuthOutcome, H3ControlStreams), AuthError> {
    match authenticate_inner(conn, auth, cc_rx).await {
        Ok(v) => Ok(v),
        Err(e) => {
            // 0-RTT 被拒不是协议错误：连接仍可用于 1-RTT，调用方需在同一
            // 连接上显式重放认证请求；此时绝不能按协议错误关闭连接。
            if !e.is_zero_rtt_rejected() {
                // 对齐 dialer.go：RoundTrip 失败与状态码非 233 都以 0x101 关闭
                conn.close(quinn::VarInt::from_u32(CLOSE_ERR_CODE_PROTOCOL_ERROR), b"");
            }
            Err(e)
        }
    }
}

async fn authenticate_inner(
    conn: &Connection,
    auth: &str,
    cc_rx: u64,
) -> Result<(AuthOutcome, H3ControlStreams), AuthError> {
    let mut streams = open_h3_streams(conn).await?;
    let mut seeds = Vec::new();

    let (mut send, mut recv) = conn.open_bi().await?;
    let stream_id = u64::from(send.id());
    let padding = super::random::random_padding(crate::padding::Range::AUTH_REQUEST);
    let field = |name: &str, value: &str| HeaderField {
        name: name.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    };
    let fields = vec![
        field(":method", "POST"),
        field(":scheme", "https"),
        field(":authority", URL_HOST),
        field(":path", URL_PATH),
        field(REQUEST_HEADER_AUTH, auth),
        field(COMMON_HEADER_CC_RX, &cc_rx.to_string()),
        field(COMMON_HEADER_PADDING, &padding),
    ];
    let block = qpack::encode_field_block(&fields);
    let mut frame = Vec::with_capacity(block.len() + 9);
    varint::append(FRAME_HEADERS, &mut frame)?;
    varint::append(block.len() as u64, &mut frame)?;
    frame.extend_from_slice(&block);
    send.write_all(&frame).await?;
    send.finish()?;

    // 认证响应只有一个 HEADERS（其后可能跟 masquerade 页面），读到流 FIN；
    // 顺路把每个 chunk 变成 UDP 层的发送种子。
    let response = read_stream_to_end(&mut recv, MAX_RESPONSE_BYTES, &mut seeds).await?;
    let block = extract_headers_block(&response)?;

    // 解码头部块；RIC>0 时先消费对端 QPACK encoder 流的插入指令。
    let mut decoder = qpack::Decoder::default();
    let fields = loop {
        match decoder.decode_field_section(&block) {
            Ok(fields) => break fields,
            Err(qpack::QpackError::InsertCount { required, .. }) => {
                feed_decoder_from_encoder_stream(conn, &mut decoder, required).await?;
            }
            Err(e) => return Err(e.into()),
        }
    };
    // QPACK decoder 流反馈（RFC 9204 §4.4）：Section Acknowledgment 与
    // Insert Count Increment；不反馈在对端驱逐表项时会阻塞。
    let mut feedback = Vec::with_capacity(9);
    qpack::append_section_acknowledgment(stream_id, &mut feedback);
    qpack::append_insert_count_increment(decoder.insert_count(), &mut feedback);
    streams.qpack_decoder.write_all(&feedback).await?;

    let mut status: Option<u16> = None;
    let mut udp_enabled = false;
    let mut server_cc_rx = 0u64;
    for f in &fields {
        let value = String::from_utf8_lossy(&f.value);
        match f.name.as_slice() {
            b":status" => {
                status = Some(
                    value
                        .parse()
                        .map_err(|_| AuthError::Protocol("状态码不是十进制数".into()))?,
                );
            }
            b"hysteria-udp" => {
                // strconv.ParseBool 的接受集；解析失败按 false（Go 忽略错误）
                udp_enabled = matches!(value.as_ref(), "1" | "t" | "T" | "true" | "TRUE" | "True");
            }
            b"hysteria-cc-rx" => {
                server_cc_rx = value.parse().unwrap_or(0);
            }
            _ => {}
        }
    }
    let status = status.ok_or_else(|| AuthError::Protocol("响应缺少 :status".into()))?;
    if status != STATUS_AUTH_OK {
        return Err(AuthError::Rejected { status });
    }
    streams.seeds = seeds;
    Ok((
        AuthOutcome {
            udp_enabled,
            server_cc_rx,
        },
        streams,
    ))
}

/// 本端三条 HTTP/3 单向流：控制流首帧必须是 SETTINGS（发送空设置，
/// QPACK 各参数取默认：动态表容量 0、不阻塞流——但解码侧仍完整支持
/// 对端使用动态表，见模块文档）。
async fn open_h3_streams(conn: &Connection) -> Result<H3ControlStreams, AuthError> {
    let mut control = conn.open_uni().await?;
    let mut qpack_encoder = conn.open_uni().await?;
    let mut qpack_decoder = conn.open_uni().await?;

    let mut head = Vec::with_capacity(4);
    varint::append(0x0u64, &mut head)?; // 流类型：控制流
    varint::append(FRAME_SETTINGS, &mut head)?;
    varint::append(0u64, &mut head)?; // 空 SETTINGS
    control.write_all(&head).await?;

    let mut enc = Vec::with_capacity(1);
    varint::append(STREAM_TYPE_QPACK_ENCODER, &mut enc)?;
    qpack_encoder.write_all(&enc).await?;

    let mut dec = Vec::with_capacity(1);
    varint::append(0x3u64, &mut dec)?; // 流类型：QPACK 解码器
    qpack_decoder.write_all(&dec).await?;

    Ok(H3ControlStreams {
        control,
        qpack_encoder,
        qpack_decoder,
        seeds: Vec::new(),
    })
}

/// 从响应字节序列中抽出第一个 HEADERS 帧的载荷；DATA/未知帧跳过载荷。
fn extract_headers_block(response: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut pos = 0usize;
    while pos < response.len() {
        let (frame_type, n1) =
            varint::decode(&response[pos..]).map_err(|e| AuthError::Protocol(e.to_string()))?;
        pos += n1;
        let (len, n2) =
            varint::decode(&response[pos..]).map_err(|e| AuthError::Protocol(e.to_string()))?;
        pos += n2;
        let len =
            usize::try_from(len).map_err(|_| AuthError::Protocol("帧长度超出 usize".into()))?;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| AuthError::Protocol("帧长度溢出".into()))?;
        let payload = response
            .get(pos..end)
            .ok_or_else(|| AuthError::Protocol("帧载荷不完整".into()))?;
        if frame_type == FRAME_HEADERS {
            return Ok(payload.to_vec());
        }
        pos = end;
    }
    Err(AuthError::Protocol("响应结束仍未出现 HEADERS 帧".into()))
}

/// 把 `required` 条插入指令喂进解码器。对端 encoder 流（uni type 0x2）
/// 尚未接收时先 `accept_uni` 找它；其间遇到的其他对端 uni 流（control /
/// qpack decoder / grease）交给守夜协程读空——对它们 STOP_SENDING 会触发
/// `H3_CLOSED_CRITICAL_STREAM`，只能读到对端 FIN。
async fn feed_decoder_from_encoder_stream(
    conn: &Connection,
    decoder: &mut qpack::Decoder,
    required: u64,
) -> Result<(), AuthError> {
    let mut encoder_stream: Option<RecvStream> = None;
    let mut buf: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    while decoder.insert_count() < required {
        let stream = match encoder_stream.as_mut() {
            Some(s) => s,
            None => {
                let s = loop {
                    let mut s = conn.accept_uni().await?;
                    if stream_type(&mut s).await? == STREAM_TYPE_QPACK_ENCODER {
                        break s;
                    }
                    keepalive_one(s);
                };
                encoder_stream.insert(s)
            }
        };
        let Some(chunk) = stream.read_chunk(usize::MAX, true).await? else {
            return Err(AuthError::Protocol(
                "QPACK encoder 流在满足 Required Insert Count 前结束".into(),
            ));
        };
        buf.extend_from_slice(&chunk.bytes);
        if buf.len() - offset > MAX_ENCODER_BUFFER {
            return Err(AuthError::Protocol("QPACK encoder 流缓冲超限".into()));
        }
        let consumed = decoder.apply_encoder_stream(&buf[offset..])?;
        offset += consumed;
    }
    Ok(())
}

/// 读对端 uni 流的类型 varint（流上第一个字节序列）。
async fn stream_type(stream: &mut RecvStream) -> Result<u64, AuthError> {
    let mut probe = Vec::with_capacity(8);
    loop {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| AuthError::Protocol(format!("读取 uni 流类型失败: {e}")))?;
        probe.push(byte[0]);
        if let Ok((value, _)) = varint::decode(&probe) {
            return Ok(value);
        }
        if probe.len() == 8 {
            return Err(AuthError::Protocol("uni 流类型 varint 非法".into()));
        }
    }
}

/// 单条对端 uni 流的守夜：读空直到 EOF，避免流控堆积，也不触发
/// 关键流错误。
fn keepalive_one(mut stream: RecvStream) {
    tokio::spawn(async move {
        let mut sink = [0u8; 4096];
        loop {
            match stream.read(&mut sink).await {
                Ok(Some(_)) => {}
                _ => return,
            }
        }
    });
}

/// 读整条流直到 FIN（上限 `cap`），每个 chunk 顺路转成 `SeedFiller`。
async fn read_stream_to_end(
    recv: &mut RecvStream,
    cap: usize,
    seeds: &mut Vec<SeedFiller>,
) -> Result<Vec<u8>, AuthError> {
    let mut buf = Vec::with_capacity(4096);
    loop {
        // quinn 0.11 语义：Ok(None) = 流 FIN（正常结束，返回已读缓冲）
        let Some(chunk) = recv.read_chunk(usize::MAX, true).await? else {
            return Ok(buf);
        };
        if buf.len() + chunk.bytes.len() > cap {
            return Err(AuthError::Protocol("响应超出大小上限".into()));
        }
        buf.extend_from_slice(&chunk.bytes);
        if let Ok(mut m) = chunk.bytes.try_into_mut() {
            seeds.push(Box::new(move |conn, payload| {
                m.clear();
                m.extend_from_slice(payload);
                conn.send_datagram(std::mem::take(&mut m).freeze())
            }));
        }
    }
}
