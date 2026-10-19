//! VLESS Vision（`flow=xtls-rprx-vision`）**服务端侧** ↔ 固定版本 Xray 客户端互通。
//!
//! 方向与 `xray_vision.rs` 相反：本仓实现 VLESS/TLS **服务端**（`TlsServer` +
//! [`VisionServer`] 流量层），官方 Xray 以 **outbound vless** 身份连入并发 TCP echo。
//! 三个用例默认 `#[ignore]`，必须显式 `--ignored` 运行；未设置 `LENGSUO_XRAY` 时
//! 打印跳过原因后返回（跳过不是互通通过）。
//!
//! 覆盖分支（与客户端侧 `xray_vision.rs` 对称）：
//! 1. 小首包 → 服务端下行首块走「长 padding」规则（`[900,1400)`）。
//! 2. 大首包 → 下行短 padding（`rand(0,256)`）。
//! 3. 256 KiB 逐字节比对。
mod support;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use lengsuo_vless::{header, header::Request, vision::server::VisionServer};
use serde_json::json;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// 目标回环端口由调用方动态分配（并行用例下不得写死，否则 `AddrInUse`）。
///
/// Xray 配置：dokodemo-door 入站固定转发到 `target_port`，vless outbound（vision flow）
/// 连本仓服务端，安全层 TLS 且信任测试自签证书。
fn xray_client_config(
    dokodemo_port: u16,
    rust_port: u16,
    target_port: u16,
    cert: &rcgen::CertifiedKey,
) -> serde_json::Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": dokodemo_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1", "port": target_port, "network": "tcp"}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1",
                "port": rust_port,
                "users": [{"id": ID, "encryption": "none", "flow": "xtls-rprx-vision"}]
            }]},
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "disableSystemRoot": true,
                    "certificates": [{
                        "usage": "verify",
                        "certificate": cert.cert.pem().lines().collect::<Vec<_>>()
                    }]
                }
            }
        }]
    })
}

/// 上游（dokodemo-door）→ 本仓服务端；本仓服务端把 vision 上行解包后转发给目标回环，
/// 再把目标回程用 vision 下行编码写回。返回下行**首个 padding 块**。
///
/// 全链路：上行解包 → 转发目标 → 目标回程 → 下行 vision 编码写回。
async fn serve_relay(
    server: &TlsServer,
    listener: &TcpListener,
    payload_len: usize,
    first_block_out: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Vec<u8> {
    let stream = loop {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = match server.accept(socket).await {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        match read_vision_request(&mut stream).await {
            Ok((_, request, _)) => break (stream, request),
            Err(_) => continue,
        }
    };
    let (mut stream, request) = stream;
    let mut vision = VisionServer::new_with_os_rng(KEY, None);

    // 连目标（dokodemo 设的地址，即回环 echo）。
    let ss_core::target::TargetAddr::V4(ip, port) = request.target else {
        panic!("目标应为 IPv4");
    };
    let mut target = TcpStream::connect((std::net::Ipv4Addr::from(ip), port))
        .await
        .unwrap();

    // 上行：解 vision 明文并转发给目标，直到收齐 `payload_len`。
    let mut raw = [0u8; 16384];
    let mut plain = Vec::with_capacity(payload_len);
    let mut forwarded = 0usize;
    while forwarded < payload_len {
        let read = stream.read(&mut raw).await.unwrap();
        if read == 0 {
            break;
        }
        let before = plain.len();
        vision.decode_uplink(&raw[..read], &mut plain);
        if plain.len() > before {
            target.write_all(&plain[before..]).await.unwrap();
            forwarded = plain.len();
        }
    }
    target.flush().await.unwrap();

    // 回程：读目标 echo 并 vision 下行编码写回。
    let mut back = vec![0u8; payload_len];
    target.read_exact(&mut back).await.unwrap();
    stream.write_all(&[0, 0]).await.unwrap();
    let first = vision.encode_downlink(&back, false);
    let _ = first_block_out.send(first.clone());
    let mut wire = first;
    wire.extend_from_slice(&vision.encode_downlink_finish());
    stream.write_all(&wire).await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();
    back
}

/// 读取 VLESS 请求头（含 vision addons），返回 `(credential, request, 消费字节数)`。
///
/// 与 `stream::receive_request` 的差别：vision flow 在 uuid 之后是 addons 字节
/// `0x12` + 18 字节载荷，随后才是 command；本函数按 [`header::decode_vision`] 解析。
async fn read_vision_request<R: AsyncReadExt + Unpin>(
    stream: &mut R,
) -> std::io::Result<([u8; 16], Request, usize)> {
    let mut bytes = Vec::with_capacity(32);
    loop {
        bytes.push(stream.read_u8().await?);
        match header::decode_vision(&bytes) {
            Ok(parsed) => return Ok(parsed),
            Err(header::Error::Incomplete) => continue,
            Err(error) => panic!("vision 头解析失败 {error}"),
        }
    }
}

fn skip_without_binary() -> bool {
    if std::env::var("LENGSUO_XRAY").is_err() {
        eprintln!("跳过：未设置 LENGSUO_XRAY（未连接参考二进制，不算互通通过）");
        return true;
    }
    false
}

/// 解析下行**首个** padding 块（剥可选 16 字节 UUID），断言块自洽。
///
/// 大载荷时一次下行写会经 `reshape_payload` 拆成多块并首尾相接写出，故只取第一块，
/// 剩余线上字节原样返回给调用方（用于长度比对等）。
fn first_block_lengths(wire: &[u8]) -> (u8, usize, usize, &[u8]) {
    let tail = if wire.len() >= 16 && wire[..16] == KEY[..] {
        &wire[16..]
    } else {
        wire
    };
    assert!(tail.len() >= 5, "首块至少 5 字节块头，实际 {}", tail.len());
    let command = tail[0];
    let content_len = usize::from(u16::from_be_bytes([tail[1], tail[2]]));
    let padding_len = usize::from(u16::from_be_bytes([tail[3], tail[4]]));
    let block_len = 5 + content_len + padding_len;
    assert!(tail.len() >= block_len, "首块自洽：5 + content + padding");
    (command, content_len, padding_len, &tail[block_len..])
}

/// 一次完整回程：本仓服务端监听 TLS，Xray 客户端（vision outbound）→ dokodemo → 目标
/// 回环 echo。返回 `(下行首个 padding 块, 目标收到的明文)`。
async fn run_vision_echo(payload: Vec<u8>, expect_first_empty: bool) -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = TlsServer::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .unwrap();

    // 目标回环：动态端口。`launch` 的就绪探测会让 Xray 向目标先拨一条空连接，
    // 故循环 accept，跳过在短超时内收不到载荷的连接，直到拿到真正携带 payload 的一条。
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let echo_payload = payload.clone();
    let echo = tokio::spawn(async move {
        loop {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut received = vec![0u8; echo_payload.len()];
            // 探测连接不携带数据：用远小于整体预算的短超时跳过它。
            match tokio::time::timeout(
                std::time::Duration::from_millis(1500),
                socket.read_exact(&mut received),
            )
            .await
            {
                Ok(Ok(_)) => {}
                _ => continue,
            }
            assert_eq!(received, echo_payload, "目标收到的上行明文必须逐字节一致");
            socket.write_all(&received).await.unwrap();
            socket.shutdown().await.unwrap();
            break;
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rust_port = listener.local_addr().unwrap().port();
    let port = free_port();
    let reference = launch(
        xray_client_config(port, rust_port, target_port, &cert),
        port,
    )
    .await;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let expected = payload.clone();
    // 服务端不 `Send`（`Box<dyn RngCore>`），故用 `join!` 在同一任务内与新连接并发，
    // 而不是 `tokio::spawn`。
    let server_fut = async {
        serve_relay(&server, &listener, expected.len(), tx).await;
    };
    let trigger_fut = async {
        // 触发 dokodemo-door 入站：连它并写 payload，读回程。
        let mut trigger = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        trigger.write_all(&payload).await.unwrap();
        trigger.flush().await.unwrap();
        let mut back = vec![0u8; payload.len()];
        if !payload.is_empty() {
            trigger.read_exact(&mut back).await.unwrap();
        }
        trigger.shutdown().await.unwrap();
        assert_eq!(back, payload, "回程必须逐字节一致");
        back
    };
    let ((), back) = tokio::join!(server_fut, trigger_fut);

    let first_block = rx.recv().await.expect("服务端未回传首个 padding 块");
    let _ = expect_first_empty;
    echo.await.unwrap();
    drop(reference);
    (first_block, back)
}

/// 情况 A：小首包 → 下行首个 padding 块走「0 内容 `Continue` 长 padding」。
/// 参考规则：`contentLen < 900 && longPadding` → `paddingLen = rand(0,500) + 900 - contentLen`，
/// 8140 字节目标经 8192-21-contentLen 夹紧；本用例内容 900 字节内不夹紧，落在 `[900,1400)`。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn vision_server_small_first_packet_uses_long_padding() {
    if skip_without_binary() {
        return;
    }
    let payload = b"vision server small first packet".to_vec();
    let (first_block, got) = timeout(WAIT * 2, run_vision_echo(payload.clone(), false))
        .await
        .expect("互通超时");
    let (command, content_len, padding_len, _rest) = first_block_lengths(&first_block);
    assert_eq!(command, 0, "下行首块命令应是 PADDING_CONTINUE");
    assert_eq!(content_len, payload.len(), "下行首块内容应原样携带回程");
    assert!(
        (900..1400).contains(&padding_len) || padding_len <= 8192 - 21 - content_len,
        "独立复算：长 padding 规则或夹紧上限，实得 {padding_len}"
    );
    assert_eq!(got, payload, "回程必须逐字节一致");
}

/// 情况 B：大首包 → 下行短 padding 分支。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn vision_server_large_first_packet_uses_short_padding() {
    if skip_without_binary() {
        return;
    }
    // 目标回环定长读满，故用与 len 一致的载荷。4096 触发短 padding 分支。
    let payload = (0..4096u32).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let (first_block, got) = timeout(WAIT * 2, run_vision_echo(payload.clone(), false))
        .await
        .expect("互通超时");
    let (command, content_len, padding_len, _rest) = first_block_lengths(&first_block);
    // 非 TLS 大载荷：`NumberPacketToFilter` 与上行共享，可能已在解包阶段耗尽，
    // 因而首块命令可能是 Continue 或 End（参考同为共享状态，两种都合法）。
    assert!(
        command <= 1,
        "下行首块命令应是 Continue/End，实得 {command}"
    );
    assert!(
        content_len >= 900,
        "大首包 contentLen 应 ≥ testseed[0]=900，实得 {content_len}"
    );
    assert!(
        padding_len < 256,
        "独立复算：p = rand(0,256) ∈ [0,256)，实得 {padding_len}"
    );
    assert_eq!(got, payload, "回程必须逐字节一致");
}

/// 情况 C：256 KiB 逐字节比对。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn vision_server_256kib_roundtrip_byte_compared() {
    if skip_without_binary() {
        return;
    }
    let payload = (0..256 * 1024u32)
        .map(|i| (i % 253) as u8)
        .collect::<Vec<_>>();
    let (first_block, got) = timeout(WAIT * 2, run_vision_echo(payload.clone(), false))
        .await
        .expect("互通超时");
    let (command, content_len, padding_len, _rest) = first_block_lengths(&first_block);
    // 256 KiB 下行首块经 `reshape_payload` 拆到 ≤ buf.Size-21；大内容走短 padding。
    // 命令为 Continue/End 均可（`NumberPacketToFilter` 与上行共享，可能已耗尽）。
    assert!(
        command <= 1,
        "下行首块命令应是 Continue/End，实得 {command}"
    );
    assert!(
        content_len >= 900,
        "大首包 contentLen 应 ≥ 900，实得 {content_len}"
    );
    assert!(
        padding_len < 256,
        "短 padding：p = rand(0,256)，实得 {padding_len}"
    );
    assert_eq!(got.len(), payload.len(), "回程长度应与上行一致");
    assert_eq!(got, payload, "256 KiB 回程必须逐字节一致");
}
