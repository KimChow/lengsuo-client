//! Hysteria2 的 HTTP/3 认证（对齐 Xray `transport/internet/hysteria/dialer.go`
//! `client.dial` 的 RoundTrip 部分与 `config.go` 常量）。
//!
//! 认证在 QUIC 握手完成后、任何业务流之前进行，走一条双向请求流上的
//! `POST https://hysteria/auth`：
//!
//! ```text
//! 请求头:  Hysteria-Auth: <密码>            （机密，错误信息/日志不回显）
//!          Hysteria-CC-RX: <BrutalDown 十进制>
//!          Hysteria-Padding: <[256,2048) 随机字母数字>
//! 响应:    状态码 233 = 认证通过
//!          Hysteria-UDP: <bool，是否开放 UDP datagram>
//!          Hysteria-CC-RX: <服务端 BrutalDown>
//!          Hysteria-Padding: <随机填充>
//! ```
//!
//! 非 233（如 masquerade 的 404）一律 [`AuthError::Rejected`]；任何失败都会
//! 以错误码 0x101（HTTP/3 GeneralProtocolError，参考 `closeErrCodeProtocolError`）
//! 关闭 QUIC 连接。HTTP/3 帧（RFC 9114）与 QPACK 头部块（RFC 9204，含动态表、
//! RIC 回绕与 Huffman 解码，能解 quic-go/qpack 的任意合规输出）由本 crate 手写，
//! 原因见 `qpack` 模块文档（依赖冻结拿不到 `http` crate）。
//!
//! ## datagram 发送缓冲（Bytes 桥）
//!
//! 依赖冻结拿不到 `bytes` crate，而 `quinn::Connection::send_datagram` 只接受
//! `bytes::Bytes`。两条互补路径，均无需命名该 crate：
//!
//! 1. **直接构造**（[`send_datagram_direct`]）：`Bytes: From<Vec<u8>>`，用一个
//!    返回类型由调用点推断的泛型函数（`make_datagram_buffer`）即可从 `&[u8]`
//!    造出 `Bytes`——类型经 `send_datagram` 的入参唯一确定。这是服务端与
//!    客户端的常规发送路径（每调用一次分配）。
//! 2. **复用接收缓冲**（[`SeedFiller`] / [`seed_filler_from_chunk`]）：
//!    `read_chunk` 有时返回独占引用计数的 `Bytes`，`try_into_mut` → 写入 →
//!    `freeze` 可复用该缓冲，省一次分配。属于可选优化，池空时回退路径 1。
//!
//! 认证期间读到的响应 chunk 会顺手生成一次性「种子发送器」
//! （[`H3ControlStreams::take_seeds`]）交给 `quic::client` 的 UDP 层做首包发送。

use crate::padding::Range;
use crate::qpack::{self, HeaderField};
use crate::varint;
use quinn::{Connection, ReadError, RecvStream, WriteError};

/// 认证请求的伪主机名与路径（`config.go` `URLHost`/`URLPath`）。
pub const URL_HOST: &str = "hysteria";
pub const URL_PATH: &str = "/auth";
/// 请求头：认证密码。Go 侧常量是 `Hysteria-Auth`（http.Header 的
/// canonical 形式），但 RFC 9114 §4.2 要求线上字段名一律小写，Go 的
/// Header.Add/Get 双向 canonical 化恰好兜住；本 crate 手写编码，
/// 线上直接用小写。
pub const REQUEST_HEADER_AUTH: &str = "hysteria-auth";
/// 响应头：服务端是否支持 UDP datagram（线上小写，同上）。
pub const RESPONSE_HEADER_UDP_ENABLED: &str = "hysteria-udp";
/// 双向头：Brutal 拥塞控制的下行带宽（十进制 bps）。
pub const COMMON_HEADER_CC_RX: &str = "hysteria-cc-rx";
/// 双向头：随机填充字符串。
pub const COMMON_HEADER_PADDING: &str = "hysteria-padding";
/// 认证成功状态码。
pub const STATUS_AUTH_OK: u16 = 233;
/// 认证失败按参考走 masquerade 缺省处理器：`http.NotFoundHandler()` 的 404。
pub const STATUS_NOT_FOUND: u16 = 404;
/// 连接关闭码（`config.go`）。
pub const CLOSE_ERR_CODE_OK: u32 = 0x100;
pub const CLOSE_ERR_CODE_PROTOCOL_ERROR: u32 = 0x101;

/// 一次性 UDP datagram 发送器：向已独占的缓冲填入载荷并发送。
/// 依赖冻结下的 `bytes::Bytes` 桥，见模块文档。实现为 `FnMut`：
/// 调用方取走后独占使用。
pub type SeedFiller =
    Box<dyn FnMut(&Connection, &[u8]) -> Result<(), quinn::SendDatagramError> + Send>;

/// 从一块**独占**的 `Bytes`（`read_chunk` 或 `read_datagram →
/// try_into_mut` 的产物）造一个 [`SeedFiller`]；不独占时返回 `None`。
///
/// 服务端与客户端共用同一桥（见模块文档）：`SendStream`/datagram 发送只
/// 接受 `bytes::Bytes`，而依赖冻结拿不到该 crate，只能靠接收路径顺路产出的
/// 独占缓冲当作发送缓冲。`Chunk`/`Bytes` 的类型经 `quinn` 的类型推断与闭包
/// 捕获使用，无需在本 crate 命名 `bytes`。
#[must_use]
pub fn seed_filler_from_chunk(chunk: quinn::Chunk) -> Option<SeedFiller> {
    let mut buf = chunk.bytes.try_into_mut().ok()?;
    Some(Box::new(move |conn, payload| {
        buf.clear();
        buf.extend_from_slice(payload);
        conn.send_datagram(std::mem::take(&mut buf).freeze())
    }))
}

/// 把一段字节发成 QUIC datagram。`send_datagram` 要求 `bytes::Bytes`，而依赖
/// 冻结拿不到该 crate；这里借 `quinn::Chunk::bytes` 的公开字段**推断出**
/// `Bytes` 类型：用 `Chunk.bytes` 的 `split_off`/重赋值路径构造新内容，
/// 全程不写出 `bytes::Bytes`。
pub fn send_datagram_direct(
    conn: &Connection,
    payload: &[u8],
) -> Result<(), quinn::SendDatagramError> {
    // `make_bytes` 的返回类型由 `send_datagram` 的入参推断为 `Bytes`，
    // 其实现只用 `Bytes: From<Vec<u8>>` 这一公开约束。
    conn.send_datagram(make_datagram_buffer(payload.to_vec()))
}

/// 见 `send_datagram_direct`：`B` 由调用点（`send_datagram` 的入参类型）
/// 推断，函数体只用 `From<Vec<u8>>`。
fn make_datagram_buffer<B: From<Vec<u8>>>(bytes: Vec<u8>) -> B {
    B::from(bytes)
}

/// 认证失败类型。错误文本不携带密码本身。
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("QUIC 流打开/连接错误: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("帧编码失败: {0}")]
    Frame(#[from] crate::Error),
    #[error("流写入失败: {0}")]
    Write(#[from] WriteError),
    #[error("流读取失败: {0}")]
    Read(#[from] ReadError),
    #[error("流已关闭: {0}")]
    Closed(#[from] quinn::ClosedStream),
    #[error("QPACK 解码失败: {0}")]
    Qpack(#[from] qpack::QpackError),
    #[error("HTTP/3 帧序列不合法: {0}")]
    Protocol(String),
    #[error("认证被拒绝：HTTP 状态 {status}（期望 233）")]
    Rejected { status: u16 },
}

impl AuthError {
    /// 是否为「0-RTT 被服务端拒绝」导致的失败。此时连接仍可继续用于
    /// 1-RTT，调用方应在同一连接上重放认证请求（参考 quinn 文档：
    /// 早数据流上的读写返回 `ZeroRttRejected`）。
    #[must_use]
    pub fn is_zero_rtt_rejected(&self) -> bool {
        matches!(
            self,
            AuthError::Write(WriteError::ZeroRttRejected)
                | AuthError::Read(ReadError::ZeroRttRejected)
        )
    }
}

/// 认证成功后从响应头提取的信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOutcome {
    /// 服务端是否声明支持 UDP datagram（`Hysteria-UDP`）。
    pub udp_enabled: bool,
    /// 服务端 `Hysteria-CC-RX`（解析失败按 0，与 Go 忽略错误一致）。
    pub server_cc_rx: u64,
}

/// 认证期间必须保持打开的 HTTP/3 单向流（控制/QPACK 编码器/解码器，
/// 提前 FIN 等价于连接层错误），由 [`crate::quic::client::HysteriaClient`]
/// 持有到连接结束；`seeds` 是响应 chunk 派生的 UDP 发送种子。
pub struct H3ControlStreams {
    /// 三条流只持有不发 FIN——drop 即 FIN 会被对端判
    /// H3_CLOSED_CRITICAL_STREAM；control/encoder 建立后不再读写。
    #[allow(dead_code)]
    pub(super) control: quinn::SendStream,
    #[allow(dead_code)]
    pub(super) qpack_encoder: quinn::SendStream,
    pub(super) qpack_decoder: quinn::SendStream,
    seeds: Vec<SeedFiller>,
}

impl H3ControlStreams {
    /// 取走全部发送种子（一次性，交给 UDP 层的种子池）。
    pub fn take_seeds(&mut self) -> Vec<SeedFiller> {
        std::mem::take(&mut self.seeds)
    }
}

/// HTTP/3 帧：HEADERS；DATA 与未知帧跳过载荷（RFC 9114 §7.2）。
pub(crate) const FRAME_HEADERS: u64 = 0x1;
/// 设置帧类型（控制流上，本端发送空设置）。
pub(crate) const FRAME_SETTINGS: u64 = 0x4;
/// 单向流类型。
pub(crate) const STREAM_TYPE_QPACK_ENCODER: u64 = 0x2;
/// 响应整体（含 masquerade 页面）读取上限。
pub(crate) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
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
    let padding = random_padding(Range::AUTH_REQUEST);
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

/// 随机源：以 `RandomState`（每实例随机密钥）的 SipHash 输出充当随机字节。
/// 参考 Go 用 `math/rand`；此处只用于 padding 长度/内容与分片 packet id，
/// 不承担密码学职责（对齐参考实现同样非密码学随机的语义）。
pub fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(std::process::id() as u64);
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    h.finish()
}

/// 生成参考 `padding.Padding.String()` 的随机填充串：长度取 `[min,max)`
/// 均匀抽样，字符取 `[a-zA-Z0-9]`。
pub fn random_padding(range: Range) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let span = range.span();
    let len = if span == 0 {
        range.min
    } else {
        range.min + (random_u64() % span as u64) as usize
    };
    let mut out = String::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        for b in random_u64().wrapping_add(counter).to_le_bytes() {
            if out.len() == len {
                break;
            }
            out.push(CHARS[(b as usize) % CHARS.len()] as char);
        }
        counter += 1;
    }
    out
}

// 供服务端模块（`h3_server`）复用的类型别名（与客户端侧同一份语义）。
pub(crate) use crate::padding::Range as ServerPaddingRange;
pub(crate) use crate::qpack::HeaderField as ServerHeaderField;
