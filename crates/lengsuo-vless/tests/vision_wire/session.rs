//! `vision_wire::VisionSession` 的**端到端**用例（本仓客户端 ↔ 本仓服务端）。
//!
//! 这是「生产接线真的能跑」的证据：客户端用**新 API** 写 VLESS 请求头 + vision
//! 块、并**自己**解下行响应头 + vision 块；服务端用既有
//! [`VisionServer`] 原语解上行、写响应头 + 下行块。
//!
//! 覆盖：
//! 1. 正常往返：请求头 + 上行块 → 服务端解出明文；服务端响应头 + 下行块 →
//!    客户端解出明文（**逐字节**一致）；
//! 2. 下行响应头**版本不符** ⇒ 客户端显式报错（fail-closed），不把响应头字节
//!    当明文吐给上层；
//! 3. 下行响应头**截断** ⇒ 客户端显式报错（`UnexpectedEof`），不把残缺头当有效头；
//! 4. 客户端写出的**请求头**必须与参考 `EncodeRequestHeader` 的字节完全一致。
//!
//! 全部是本仓 Rust↔Rust 回环，**不是**与参考互通的证据（互通见
//! `tests/vision_wire_xray.rs`）。

use lengsuo_vless::header::{self, Command, Request};
use lengsuo_vless::vision::server::VisionServer;
use lengsuo_vless::vision_wire::{VisionSession, VisionWireError};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::common::{vision_config, CounterRng, LIMIT, PIPE, UUID};

/// 一条普通的 VLESS TCP 请求（目标为回环地址，不会真的被连接）。
fn request() -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], 80),
    }
}

/// 参考 `EncodeResponseHeader`：版本字节 + addons 长度字节（响应的 addons 恒为空）。
fn encode_response_header(version: u8) -> Vec<u8> {
    vec![version, 0u8]
}

/// 从承载流读出 VLESS 请求头，返回 `(请求头字节, 剩余的 vision 块字节)`。
///
/// 参考服务端 `DecodeRequestHeader`：先读版本、UUID、addons，再读 command 与地址。
async fn read_request_header(reader: &mut tokio::io::DuplexStream) -> (Vec<u8>, Vec<u8>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let read = tokio::time::timeout(LIMIT, reader.read(&mut chunk))
            .await
            .expect("读超时")
            .unwrap();
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Ok((_, _, consumed)) = header::decode_vision(&buffer) {
            let head = buffer[..consumed].to_vec();
            let rest = buffer[consumed..].to_vec();
            return (head, rest);
        }
    }
    panic!("请求头未读全");
}

/// 从 [`VisionWireError`] 里取底层 I/O 错误的 kind（非 I/O 错误直接失败）。
fn io_kind(error: &VisionWireError) -> std::io::ErrorKind {
    match error {
        VisionWireError::Io(inner) => inner.kind(),
        other => panic!("必须是 I/O 错误，实得 {other:?}"),
    }
}

/// 建一条客户端会话（确定性 RNG，便于逐字节复现）。
fn client_session(raw: tokio::io::DuplexStream) -> VisionSession<tokio::io::DuplexStream> {
    VisionSession::with_rng(raw, vision_config(), Box::new(CounterRng(0)))
}

/// 端到端：客户端（新 API）↔ 服务端（既有原语），上下行都逐字节一致。
#[tokio::test]
async fn vision_session_roundtrips_through_repo_server() {
    let (client_raw, mut server_raw) = tokio::io::duplex(PIPE);
    let request = request();
    let payload = b"application payload that must survive the wire".to_vec();
    let response = b"response payload from the server".to_vec();
    let expected_uplink = payload.clone();
    let expected_downlink = response.clone();
    let server_downlink = expected_downlink.clone();

    // 服务端：解请求头 → 解上行块 → 写响应头 + 下行块。
    let server = tokio::spawn(async move {
        let (head, rest) = read_request_header(&mut server_raw).await;
        // 参考服务端：请求头里的 vision addons 必须是 `xtls-rprx-vision`（长度 18）。
        assert_eq!(head.len(), 44, "请求头长度 = 1+16+1+18+1+7");
        assert_eq!(head[17], 18, "addons 长度字节");
        assert_eq!(&head[18..20], &[0x0A, 0x10], "addons 载荷头");
        assert_eq!(&head[20..36], b"xtls-rprx-vision", "flow 字符串");

        // `VisionServer` 的随机源没有 `Send` 边界（`vision/server.rs` 不在本卡
        // touches 内）⇒ 把它限制在**不含 await** 的作用域里，作用域结束即 drop，
        // 再 await 写回程（否则 `tokio::spawn` 要求 future 为 `Send`）。
        let out = {
            let mut reader = VisionServer::new(UUID, None, Box::new(CounterRng(0)));
            let mut uplink = Vec::new();
            reader.decode_uplink(&rest, &mut uplink);
            assert_eq!(
                uplink, expected_uplink,
                "服务端解出的上行明文必须逐字节一致"
            );

            // 写响应头（参考 `EncodeResponseHeader`）+ 下行 vision 块。
            let mut writer = VisionServer::new(UUID, None, Box::new(CounterRng(0)));
            let mut out = encode_response_header(0);
            out.extend_from_slice(&writer.encode_downlink(&server_downlink, false));
            out.extend_from_slice(&writer.encode_downlink_finish());
            out
        };
        server_raw.write_all(&out).await.unwrap();
        server_raw.shutdown().await.unwrap();
    });

    // 客户端：新 API（`VisionSession`）——自己写请求头、自己解响应头。
    let mut session = client_session(client_raw);
    session.start(&request, Some(&payload)).await.unwrap();
    session.finish().await.unwrap();

    let mut got = Vec::new();
    let mut raw = [0u8; 1024];
    loop {
        match tokio::time::timeout(LIMIT, session.read(&mut raw)).await {
            Err(_) => break,
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => got.extend_from_slice(&raw[..read]),
            Ok(Err(error)) => panic!("读下行失败：{error}"),
        }
    }
    assert_eq!(got, expected_downlink, "客户端解出的下行明文必须逐字节一致");

    // 响应头已被新 API 解出（参考响应的 addons 恒为空）。
    let header = session.response_header().expect("响应头必须已解出");
    assert_eq!(header.version, 0, "响应版本必须是 0");
    assert!(header.addons.is_empty(), "响应 addons 必须为空");

    server.await.unwrap();
}

/// 下行响应头**版本不符** ⇒ 客户端显式报错（fail-closed）。
#[tokio::test]
async fn vision_session_rejects_mismatched_response_version() {
    let (client_raw, mut server_raw) = tokio::io::duplex(PIPE);
    let request = request();

    let server = tokio::spawn(async move {
        let _ = read_request_header(&mut server_raw).await;
        // 版本字节写成 1（期望 0）。
        server_raw
            .write_all(&encode_response_header(1))
            .await
            .unwrap();
        server_raw
            .write_all(b"body that must never surface")
            .await
            .unwrap();
        server_raw.shutdown().await.unwrap();
    });

    let mut session = client_session(client_raw);
    session.start(&request, Some(b"ping")).await.unwrap();

    let mut raw = [0u8; 1024];
    let outcome = tokio::time::timeout(LIMIT, session.read(&mut raw)).await;
    server.await.unwrap();
    let outcome = outcome.expect("读超时");
    let error = outcome.expect_err("版本不符必须显式报错");
    assert_eq!(
        io_kind(&error),
        std::io::ErrorKind::InvalidData,
        "响应头版本不符必须是 InvalidData（fail-closed）"
    );
}

/// 下行响应头**截断** ⇒ 客户端显式报错（`UnexpectedEof`），不把残缺头当有效头。
#[tokio::test]
async fn vision_session_rejects_truncated_response_header() {
    let (client_raw, mut server_raw) = tokio::io::duplex(PIPE);
    let request = request();

    let server = tokio::spawn(async move {
        let _ = read_request_header(&mut server_raw).await;
        // 只写 1 个字节（半个响应头）后关闭。
        server_raw.write_all(&[0u8]).await.unwrap();
        server_raw.shutdown().await.unwrap();
    });

    let mut session = client_session(client_raw);
    session.start(&request, Some(b"ping")).await.unwrap();

    let mut raw = [0u8; 1024];
    let outcome = tokio::time::timeout(LIMIT, session.read(&mut raw)).await;
    server.await.unwrap();
    let outcome = outcome.expect("读超时");
    let error = outcome.expect_err("截断响应头必须显式报错");
    assert_eq!(
        io_kind(&error),
        std::io::ErrorKind::UnexpectedEof,
        "截断响应头必须是 UnexpectedEof（fail-closed）"
    );
}

/// 客户端写出的**请求头**必须与参考 `EncodeRequestHeader` 的字节完全一致。
///
/// 参考布局：`[version(1)][UUID(16)][addons 长度(1)][addons 载荷][command(1)][地址]`；
/// vision 的 addons 载荷 = `0x0A 0x10 + "xtls-rprx-vision"`（18 字节）。
#[tokio::test]
async fn vision_session_writes_reference_request_header_bytes() {
    let (client_raw, mut server_raw) = tokio::io::duplex(PIPE);
    let request = request();
    let mut session = client_session(client_raw);
    session.start(&request, None).await.unwrap();

    let expected = header::encode_with_flow(&request, &UUID, header::Flow::XtlsRprxVision).unwrap();
    // 读得比请求头长（首块 vision padding 跟在同一次写出里）⇒ 按请求头长度切。
    let mut head = vec![0u8; 256];
    let read = tokio::time::timeout(LIMIT, server_raw.read(&mut head))
        .await
        .expect("读超时")
        .unwrap();
    assert!(read >= expected.len(), "必须至少读到整个请求头");
    assert_eq!(
        &head[..expected.len()],
        &expected[..],
        "请求头字节必须与参考 EncodeRequestHeader 一致"
    );
    // 请求头之后紧跟首个 vision 块（首块携带 UUID）。
    assert_eq!(
        &head[expected.len()..expected.len() + 16],
        &UUID[..],
        "首个块携带 UUID"
    );
    // 独立复算参考布局（不依赖本仓 encode 实现）。
    assert_eq!(expected[0], 0, "版本字节");
    assert_eq!(&expected[1..17], &UUID[..], "UUID 位置");
    assert_eq!(expected[17], 18, "addons 长度字节");
    assert_eq!(&expected[18..20], &[0x0A, 0x10], "addons 载荷头");
    assert_eq!(&expected[20..36], b"xtls-rprx-vision", "flow 字符串");
    assert_eq!(expected[36], 1, "command = TCP");
    // 之后是地址：端口在前 + ATYP=1 + 4 字节 IPv4。
    assert_eq!(&expected[37..39], &80u16.to_be_bytes(), "端口在前");
    assert_eq!(expected[39], 1, "ATYP = IPv4");
    assert_eq!(&expected[40..44], &[127, 0, 0, 1], "目标地址");
}

/// 承载流 EOF 时，客户端不得把未读完的字节当明文交付（响应头未齐 ⇒ 报错）。
#[tokio::test]
async fn vision_session_eof_without_response_header_is_error() {
    let (client_raw, mut server_raw) = tokio::io::duplex(PIPE);
    let request = request();
    let server = tokio::spawn(async move {
        let _ = read_request_header(&mut server_raw).await;
        server_raw.shutdown().await.unwrap();
    });

    let mut session = client_session(client_raw);
    session.start(&request, Some(b"ping")).await.unwrap();

    let mut raw = [0u8; 1024];
    let outcome = tokio::time::timeout(LIMIT, session.read(&mut raw)).await;
    server.await.unwrap();
    let outcome = outcome.expect("读超时");
    // 参考 `ReadFullFrom` 的 `io.ErrUnexpectedEOF`：响应头一个字节都没到 ⇒ 截断。
    let error = outcome.expect_err("响应头缺失必须显式报错");
    assert_eq!(
        io_kind(&error),
        std::io::ErrorKind::UnexpectedEof,
        "响应头缺失必须是 UnexpectedEof（fail-closed）"
    );
}
