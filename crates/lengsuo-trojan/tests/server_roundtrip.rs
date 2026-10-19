//! 本仓客户端 ↔ 本仓服务端：锁定服务端运行时逻辑，不依赖任何外部二进制。
//!
//! 覆盖正向 CONNECT 回环（明文与 TLS 两条路径）与失败矩阵（错误密码、截断头、
//! 非法命令字节）。失败判定不把“我方读超时”当证据：每条拒绝都要求服务端处理
//! 任务在界限内返回**可判别的错误变体**，并且连接对端观察得到主动关闭。

use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient};
use lengsuo_trojan::server::{Error, Inbound, Server, Timeouts, Validator};
use lengsuo_trojan::{codec, Command, Credential, Request, Session, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PASSWORD: &str = "server-roundtrip-test-password";
const WAIT: Duration = Duration::from_secs(5);

fn timeouts(handshake: Duration) -> Timeouts {
    Timeouts::new(handshake, WAIT).unwrap()
}

fn tcp_request(port: u16) -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], port),
    }
}

/// 流式回显后端：读到多少立刻回写多少，直到对端 EOF。返回其端口与连接任务。
async fn echo_once() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf).await.unwrap() {
                0 => break,
                n => sock.write_all(&buf[..n]).await.unwrap(),
            }
        }
        sock.shutdown().await.unwrap();
    });
    (port, task)
}

/// 一次性服务端处理器：accept 一条连接后交给 `handle_tcp`，返回其结果。
async fn accept_one(
    listener: TcpListener,
    server: Server,
) -> tokio::task::JoinHandle<Result<(), Error>> {
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server.handle_tcp(socket).await
    })
}

/// 认证请求头（正确密码）。
fn auth_header(target: u16) -> Vec<u8> {
    codec::encode(&tcp_request(target), &Credential::new(PASSWORD)).unwrap()
}

/// 手工构造含任意命令字节的请求头（`codec::encode` 只接受合法命令）。
fn raw_command_header(command: u8) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(Credential::new(PASSWORD).as_bytes());
    header.extend_from_slice(b"\r\n");
    header.push(command);
    header.extend_from_slice(&[0x01, 127, 0, 0, 1]);
    header.extend_from_slice(&9u16.to_be_bytes());
    header.extend_from_slice(b"\r\n");
    header
}

/// 断言对端在界限内主动结束连接，且不返回应答字节（观察超时本身不算通过）。
async fn assert_peer_closed(stream: &mut TcpStream, within: Duration) {
    let mut buf = [0u8; 16];
    let outcome = timeout(within, stream.read(&mut buf))
        .await
        .expect("对端必须在观察上限内主动结束连接");
    assert!(
        matches!(outcome, Ok(0) | Err(_)),
        "不能收到应答：{outcome:?}"
    );
}

#[tokio::test]
async fn rust_client_to_rust_server_echo_roundtrip_plain() {
    timeout(WAIT, async {
        let (echo_port, echo) = echo_once().await;

        let mut validator = Validator::new();
        validator.add("plain@example.com", PASSWORD).unwrap();
        let server = Server::new(validator, timeouts(WAIT));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let server_task = accept_one(listener, server).await;

        let payload = b"rust-to-rust CONNECT echo payload\0\xff\x00";
        let stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        let (read, write) = tokio::io::split(stream);
        let mut session = Session::connect(
            read,
            write,
            &tcp_request(echo_port),
            &Credential::new(PASSWORD),
            WAIT,
        )
        .await
        .unwrap();
        session.send(payload).await.unwrap();

        let mut reply = vec![0u8; payload.len()];
        let mut received = 0;
        while received < reply.len() {
            let n = session.read(&mut reply[received..]).await.unwrap();
            assert!(n > 0, "回程提前 EOF");
            received += n;
        }
        assert_eq!(reply, payload);
        session.close().await;

        echo.await.unwrap();
        server_task
            .await
            .unwrap()
            .expect("正常回环服务端应干净结束 CONNECT");
    })
    .await
    .expect("明文回环超时");
}

#[tokio::test]
async fn rust_tls_client_to_rust_tls_server_echo_roundtrip() {
    timeout(WAIT, async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let (echo_port, echo) = echo_once().await;

        let mut validator = Validator::new();
        validator.add("tls@example.com", PASSWORD).unwrap();
        let inbound = Inbound::new(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap();
        let server = Server::with_tls(validator, timeouts(WAIT), inbound);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let server_task = accept_one(listener, server).await;

        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        let stream = client
            .connect((std::net::Ipv4Addr::LOCALHOST, server_port).into())
            .await
            .unwrap();
        let (read, write) = tokio::io::split(stream);
        let mut session = Session::connect(
            read,
            write,
            &tcp_request(echo_port),
            &Credential::new(PASSWORD),
            WAIT,
        )
        .await
        .unwrap();
        let payload = b"rust-to-rust TLS CONNECT echo payload";
        session.send(payload).await.unwrap();
        let mut reply = vec![0u8; payload.len()];
        let mut received = 0;
        while received < reply.len() {
            let n = session.read(&mut reply[received..]).await.unwrap();
            assert!(n > 0, "TLS 回程提前 EOF");
            received += n;
        }
        assert_eq!(reply, payload);
        session.close().await;

        echo.await.unwrap();
        server_task
            .await
            .unwrap()
            .expect("TLS 回环服务端应干净结束 CONNECT");
    })
    .await
    .expect("TLS 回环超时");
}

#[tokio::test]
async fn wrong_password_is_rejected_without_dialing() {
    timeout(WAIT, async {
        let mut validator = Validator::new();
        validator.add("good@example.com", PASSWORD).unwrap();
        let server = Server::new(validator, timeouts(WAIT));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let server_task = accept_one(listener, server).await;

        let mut stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        let wrong = codec::encode(&tcp_request(9), &Credential::new("wrong-password")).unwrap();
        stream.write_all(&wrong).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, WAIT).await;
        drop(stream);

        match server_task.await.unwrap() {
            Err(Error::Authentication) => {}
            other => panic!("期望认证失败，得到 {other:?}"),
        }
    })
    .await
    .expect("错误密码用例超时");
}

#[tokio::test]
async fn invalid_command_byte_is_rejected() {
    timeout(WAIT, async {
        let mut validator = Validator::new();
        validator.add("cmd@example.com", PASSWORD).unwrap();
        let server = Server::new(validator, timeouts(WAIT));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let server_task = accept_one(listener, server).await;

        let mut stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        stream.write_all(&raw_command_header(0xff)).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, WAIT).await;
        drop(stream);

        match server_task.await.unwrap() {
            Err(Error::InvalidCommand(0xff)) => {}
            other => panic!("期望非法命令 0xff，得到 {other:?}"),
        }
    })
    .await
    .expect("非法命令用例超时");
}

#[tokio::test]
async fn truncated_header_short_is_rejected() {
    timeout(WAIT, async {
        let mut validator = Validator::new();
        validator.add("trunc@example.com", PASSWORD).unwrap();
        let server = Server::new(validator, timeouts(WAIT));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let server_task = accept_one(listener, server).await;

        // 不足 58 字节 → 参考 `server.go` 首块守卫判“不是 trojan 协议”。
        let header = auth_header(9);
        let mut stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        stream.write_all(&header[..57]).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, WAIT).await;
        drop(stream);

        match server_task.await.unwrap() {
            Err(Error::NotTrojanProtocol) => {}
            other => panic!("期望 NotTrojanProtocol，得到 {other:?}"),
        }
    })
    .await
    .expect("截断头（<58）用例超时");
}

#[tokio::test]
async fn truncated_header_silent_is_cut_by_handshake_deadline() {
    timeout(WAIT, async {
        let mut validator = Validator::new();
        validator.add("trunc2@example.com", PASSWORD).unwrap();
        // 短握手截止，用于观测“地址写了一半之后不再发送”的有界拒绝。
        let handshake = Duration::from_millis(400);
        let server = Server::new(validator, timeouts(handshake));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let server_task = accept_one(listener, server).await;

        // 哈希 + CRLF + 命令 + 地址首字节（ATYP），此后静默，必须由握手截止结束。
        let header = auth_header(9);
        assert!(header.len() > 60, "V4 目标头必须多于 60 字节");
        let mut stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        stream.write_all(&header[..60]).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, WAIT).await;
        drop(stream);

        match server_task.await.unwrap() {
            Err(Error::Timeout) => {}
            other => panic!("期望握手截止 Timeout，得到 {other:?}"),
        }
    })
    .await
    .expect("截断头（静默）用例超时");
}
