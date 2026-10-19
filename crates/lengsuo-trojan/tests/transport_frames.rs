//! 外层传输**帧层/握手**的非忽略自检（Rust↔Rust 回环）。**这不是 Xray 互通**——
//! 仅验证本仓 WS/HTTPUpgrade 客户端的线上字节与状态机自洽。与 Xray 的真实互通见
//! `tests/xray_transport.rs`（`#[ignore]`，必须 `--ignored` 实跑）。
//!
//! 覆盖：WS 升级请求逐字节（Host/Connection/Upgrade/Version/Key）、
//! `Sec-WebSocket-Accept` 校验（对/错两个方向）、二进制帧掩码与载荷、
//! 分片（continuation）拼接、`Close` 帧结束读侧、服务端掩码帧被拒、
//! HTTPUpgrade 升级后为裸字节流（无帧层）、路径归一化与 `Host` 回退。

use std::time::Duration;

use lengsuo_trojan::transport::sha1::accept_key;
use lengsuo_trojan::transport::{httpupgrade, ws};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

/// 读一个 HTTP 请求头（到 `\r\n\r\n`），返回原始文本。
async fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf).unwrap();
        }
    }
}

/// 从请求头里取某个头字段（大小写不敏感）。
fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

/// 起一个最小 WS 服务端：读升级请求，校验关键头，回 101（带正确 Accept），
/// 然后把 `frames`（已按 RFC 6455 编码的服务端→客户端帧）写给客户端。
async fn ws_server(frames: Vec<Vec<u8>>, bad_accept: bool) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        assert!(
            request.starts_with("GET /trojan HTTP/1.1\r\n"),
            "请求行必须是配置路径：{request}"
        );
        assert_eq!(header(&request, "Upgrade"), Some("websocket"));
        assert_eq!(header(&request, "Connection"), Some("Upgrade"));
        assert_eq!(header(&request, "Sec-WebSocket-Version"), Some("13"));
        assert_eq!(header(&request, "Host"), Some("example.test"));
        let key = header(&request, "Sec-WebSocket-Key").expect("必须带 Key");
        let accept = if bad_accept {
            "AAAA".to_owned()
        } else {
            accept_key(key)
        };
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        for frame in frames {
            socket.write_all(&frame).await.unwrap();
        }
        socket.flush().await.unwrap();
        // 保持连接直到客户端读完；用一个短读确认对端不再写，然后结束。
        let mut sink = [0u8; 1];
        let _ = timeout(WAIT, socket.read(&mut sink)).await;
    });
    (port, task)
}

/// 编码一个服务端→客户端帧（不掩码）：FIN + opcode + 长度 + 载荷。
fn server_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(if fin { 0x80 | opcode } else { opcode });
    let len = payload.len();
    if len < 126 {
        frame.push(len as u8);
    } else if len <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

/// 客户端 → 服务端：升级后写 trojan 形状的字节，服务端按帧解出并回显。
#[tokio::test]
async fn ws_client_handshake_and_frame_write() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        let key = header(&request, "Sec-WebSocket-Key").unwrap().to_owned();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(&key)
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        // 读一个客户端帧：必须掩码，解出载荷。
        let mut head = [0u8; 2];
        socket.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0] & 0x80, 0x80, "必须置 FIN");
        assert_eq!(head[0] & 0x0f, 0x2, "必须是二进制帧");
        assert_ne!(head[1] & 0x80, 0, "客户端帧必须掩码");
        let len = (head[1] & 0x7f) as usize;
        let mut mask = [0u8; 4];
        socket.read_exact(&mut mask).await.unwrap();
        let mut payload = vec![0u8; len];
        socket.read_exact(&mut payload).await.unwrap();
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
        payload
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client = ws::Client::new("/trojan", "example.test", "example.test");
    let mut conn = client.upgrade(tcp, WAIT).await.expect("WS 升级应成功");
    let header = crate::trojan_header(0x01, &[127, 0, 0, 1], 443);
    conn.write_all(&header).await.unwrap();
    conn.flush().await.unwrap();

    let seen = timeout(WAIT, server).await.unwrap().unwrap();
    assert_eq!(seen, header, "服务端解出的帧载荷必须与写入逐字节一致");
}

/// 客户端读到服务端的分片帧 + Close：载荷按 RFC 拼接，Close 使读侧 EOF。
#[tokio::test]
async fn ws_client_reads_fragmented_frames_then_close() {
    let first = server_frame(0x2, false, b"trojan-");
    let second = server_frame(0x0, true, b"header");
    let close = server_frame(0x8, true, &[]);
    let (port, _server) = ws_server(vec![first, second, close], false).await;

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client = ws::Client::new("/trojan", "example.test", "example.test");
    let mut conn = client.upgrade(tcp, WAIT).await.unwrap();
    let mut got = Vec::new();
    timeout(WAIT, conn.read_to_end(&mut got))
        .await
        .expect("读侧应在 Close 后 EOF")
        .unwrap();
    assert_eq!(got, b"trojan-header", "分片帧必须拼接后按序交付");
}

/// `Sec-WebSocket-Accept` 不匹配必须拒绝（对齐 gorilla `VerifyServerResponse`）。
#[tokio::test]
async fn ws_client_rejects_bad_accept() {
    let (port, _server) = ws_server(vec![], true).await;
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client = ws::Client::new("/trojan", "example.test", "example.test");
    match client.upgrade(tcp, WAIT).await {
        Err(lengsuo_trojan::transport::Error::UpgradeRejected(_)) => {}
        other => panic!("必须是 Accept 校验失败：{:?}", other.err()),
    }
}

/// 服务端掩码帧是协议错误（RFC 6455 §5.1），读侧必须报错而非静默接受。
#[tokio::test]
async fn ws_client_rejects_masked_server_frame() {
    let mut masked = Vec::new();
    masked.push(0x82);
    masked.push(0x80 | 3);
    masked.extend_from_slice(&[1, 2, 3, 4]);
    masked.extend_from_slice(&[0x61 ^ 1, 0x62 ^ 2, 0x63 ^ 3]);
    let (port, _server) = ws_server(vec![masked], false).await;

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client = ws::Client::new("/trojan", "example.test", "example.test");
    let mut conn = client.upgrade(tcp, WAIT).await.unwrap();
    let mut buf = [0u8; 16];
    let outcome = timeout(WAIT, conn.read(&mut buf)).await.unwrap();
    assert!(outcome.is_err(), "掩码服务端帧必须报错：{outcome:?}");
}

/// HTTPUpgrade：升级点之后没有帧层，裸字节直通。
#[tokio::test]
async fn httpupgrade_is_bare_stream_after_upgrade() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_request(&mut socket).await;
        assert_eq!(header(&request, "Upgrade"), Some("websocket"));
        // 参考 httpupgrade dialer 不发 Sec-WebSocket-Key。
        assert!(header(&request, "Sec-WebSocket-Key").is_none());
        let response =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
        // 升级点之后立刻是裸字节：直接读 6 字节再回写。
        let mut payload = [0u8; 6];
        socket.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"trojan");
        socket.write_all(b"REPLY!").await.unwrap();
    });

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client = httpupgrade::Client::new("/trojan", "example.test", "example.test");
    let mut conn = client.upgrade(tcp, WAIT).await.expect("HTTPUpgrade 应成功");
    conn.write_all(b"trojan").await.unwrap();
    conn.flush().await.unwrap();
    let mut reply = [0u8; 6];
    timeout(WAIT, conn.read_exact(&mut reply))
        .await
        .expect("回程应到达")
        .unwrap();
    assert_eq!(&reply, b"REPLY!");
    timeout(WAIT, server).await.unwrap().unwrap();
}

/// 路径归一化：不带前导 `/` 也要请求 `/<path>`；空则 `/`。
#[tokio::test]
async fn httpupgrade_normalizes_path_and_host_fallback() {
    for (path, expect) in [("trojan", "/trojan"), ("/trojan", "/trojan"), ("", "/")] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected = expect.to_owned();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_request(&mut socket).await;
            assert!(
                request.starts_with(&format!("GET {expected} HTTP/1.1\r\n")),
                "路径须归一化为 {expected}：{request}"
            );
            // host 为空 → 回退到 server_name。
            assert_eq!(header(&request, "Host"), Some("fallback.test"));
            socket
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
        });
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let client = httpupgrade::Client::new(path, "", "fallback.test");
        let _conn = client.upgrade(tcp, WAIT).await.unwrap();
        timeout(WAIT, server).await.unwrap().unwrap();
    }
}

/// 非 101 响应必须拒绝（以 404 为例）。
#[tokio::test]
async fn httpupgrade_rejects_non_101() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client = httpupgrade::Client::new("/trojan", "", "fallback.test");
    match client.upgrade(tcp, WAIT).await {
        Err(lengsuo_trojan::transport::Error::UpgradeRejected(_)) => {}
        other => panic!("非 101 必须拒绝：{:?}", other.err()),
    }
    timeout(WAIT, server).await.unwrap().unwrap();
}

/// 零时长直接拒绝，不触碰流。
#[tokio::test]
async fn zero_deadline_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let client = ws::Client::new("/trojan", "", "x");
    assert!(matches!(
        client.upgrade(tcp, Duration::ZERO).await,
        Err(lengsuo_trojan::transport::Error::InvalidDeadline)
    ));
}

/// 构造一个 trojan 形状的请求头字节（仅用于本文件的帧测试）。
pub fn trojan_header(command: u8, ip: &[u8; 4], port: u16) -> Vec<u8> {
    let mut header = vec![b'a'; 56];
    header.extend_from_slice(b"\r\n");
    header.push(command);
    header.push(0x01);
    header.extend_from_slice(ip);
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(b"\r\n");
    header
}
