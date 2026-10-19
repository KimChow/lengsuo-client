//! 官方 Xray 客户端 → 本仓 Rocket2 服务端 的运行时互通与失败矩阵（默认忽略）。
//!
//! 正向用例：xray 以 socks 入站 + trojan 出站的身份把 HTTP 请求打到本仓 TLS
//! 服务端，由回环回显后端逐字节回传，断言回程与请求完全一致。
//! 失败用例不把“没读到”当通过：错误密码用“回显后端 accept 计数不变”作独立观测面，
//! 且必须观察到 xray 侧连接被主动断连；非法命令字节与截断头要求本仓拒绝并且
//! 服务端处理任务返回明确错误变体（不是 panic）。

mod support;

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient};
use lengsuo_trojan::server::{Error, Inbound, Server, Timeouts, Validator};
use lengsuo_trojan::{codec, Command, Credential, Request, TargetAddr};
use serde_json::{json, Value};
use support::{free_port, launch, WAIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PASSWORD: &str = "interop-trojan-password";
const BAD_PASSWORD: &str = "interop-trojan-wrong-password";
const HTTP_REQUEST: &[u8] = b"GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const TOTAL: Duration = Duration::from_secs(60);
const CLOSE_BOUND: Duration = Duration::from_secs(8);

struct Identity {
    cert: rcgen::CertifiedKey,
}

impl Identity {
    fn new() -> Self {
        Self {
            cert: rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap(),
        }
    }

    fn inbound(&self) -> Inbound {
        Inbound::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }

    fn client(&self) -> TlsClient {
        TlsClient::new("localhost", [self.cert.cert.der().clone()], WAIT).unwrap()
    }

    fn client_settings(&self) -> Value {
        json!({"security":"tls","tlsSettings":{"serverName":"localhost",
            "disableSystemRoot":true,"certificates":[{"usage":"verify",
            "certificate":self.cert.cert.pem().lines().collect::<Vec<_>>()}]}})
    }
}

/// 回显后端：每条连接读满 `payload_len` 字节后原样回写并关写端，accept 计数。
async fn spawn_echo(payload_len: usize) -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let echo_len = payload_len;
            tokio::spawn(async move {
                let mut buf = vec![0u8; echo_len];
                if socket.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let _ = socket.write_all(&buf).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, accepted, task)
}

/// 在一次回显连接上做完整 CONNECT 回环（socks → trojan → 回显），断言逐字节一致。
async fn socks_roundtrip(socks_port: u16, echo_port: u16) {
    let mut tunnel = socks5_tcp_connect(socks_port, echo_port)
        .await
        .expect("socks CONNECT 应成功");
    tunnel.write_all(HTTP_REQUEST).await.expect("写入请求失败");
    let mut reply = vec![0u8; HTTP_REQUEST.len()];
    timeout(WAIT, tunnel.read_exact(&mut reply))
        .await
        .expect("回程超时")
        .expect("回程读失败");
    assert_eq!(reply, HTTP_REQUEST);
}

/// 在某个回环端口跑本仓 TLS 服务端（accept 循环），供 xray 客户端接入。
async fn spawn_rust_tls_server(
    identity: &Identity,
    password: &str,
) -> (u16, tokio::task::JoinHandle<()>) {
    let mut validator = Validator::new();
    validator.add("interop@example.com", password).unwrap();
    let server = Server::with_tls(
        validator,
        Timeouts::new(WAIT, WAIT).unwrap(),
        identity.inbound(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let _ = server.accept_loop(listener).await;
    });
    (port, task)
}

/// xray 配置：本地 socks5 入站 + 指向本仓服务端的 trojan 出站。
fn xray_config(socks_port: u16, rust_port: u16, password: &str, identity: &Identity) -> Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks",
            "settings":{"auth":"noauth"}}],
        "outbounds":[{"protocol":"trojan","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"password":password}]},
            "streamSettings":identity.client_settings()}]})
}

/// 最小 SOCKS5 TCP CONNECT：只支持 no-auth 与 IPv4 目标，返回建好的隧道。
async fn socks5_tcp_connect(proxy_port: u16, target_port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::other("socks 协商失败"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "socks CONNECT 失败",
        ));
    }
    // 依 ATYP 读掉 bind 地址与端口；目标是否真的建立由上层读写结果判定。
    let extra = match head[3] {
        1 => 4 + 2,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0]) + 2
        }
        4 => 16 + 2,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "非法 bind ATYP")),
    };
    let mut tail = vec![0u8; extra];
    stream.read_exact(&mut tail).await?;
    Ok(stream)
}

/// 一次性 TLS 服务端：accept 一条连接交给 `handle_tcp`，返回其结果（用于拒绝矩阵）。
async fn accept_one_tls(
    listener: TcpListener,
    server: Server,
) -> tokio::task::JoinHandle<Result<(), Error>> {
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server.handle_tcp(socket).await
    })
}

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

async fn assert_peer_closed<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, within: Duration) {
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
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_trojan_client_http_echo_roundtrip() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted, echo_task) = spawn_echo(HTTP_REQUEST.len()).await;
        let (rust_port, rust_task) = spawn_rust_tls_server(&identity, PASSWORD).await;

        let socks = free_port();
        let reference = launch(xray_config(socks, rust_port, PASSWORD, &identity), socks).await;
        socks_roundtrip(socks, echo_port).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "回环必须抵达业务目标一次"
        );

        drop(reference);
        rust_task.abort();
        echo_task.abort();
        let _ = timeout(WAIT, rust_task).await;
        let _ = timeout(WAIT, echo_task).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_trojan_client_wrong_password_fails() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted, echo_task) = spawn_echo(HTTP_REQUEST.len()).await;
        let (rust_port, rust_task) = spawn_rust_tls_server(&identity, PASSWORD).await;

        // 对照：正确密码走通，证明观测面有效。
        let good_socks = free_port();
        let good = launch(
            xray_config(good_socks, rust_port, PASSWORD, &identity),
            good_socks,
        )
        .await;
        socks_roundtrip(good_socks, echo_port).await;
        drop(good);
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "对照组必须抵达业务目标");

        // 错误密码：连接必须被主动断开，且业务目标 accept 计数不增长。
        let before = accepted.load(Ordering::SeqCst);
        let bad_socks = free_port();
        let bad = launch(
            xray_config(bad_socks, rust_port, BAD_PASSWORD, &identity),
            bad_socks,
        )
        .await;
        let rejected = match socks5_tcp_connect(bad_socks, echo_port).await {
            Ok(mut tunnel) => {
                let _ = timeout(WAIT, tunnel.write_all(HTTP_REQUEST)).await;
                let mut reply = vec![0u8; HTTP_REQUEST.len()];
                match timeout(CLOSE_BOUND, tunnel.read(&mut reply)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => true,
                    Ok(Ok(n)) if n < HTTP_REQUEST.len() => true,
                    Ok(Ok(_)) => false,
                    Err(_) => panic!("错误密码连接必须在观察上限内被断"),
                }
            }
            Err(_) => true,
        };
        assert!(rejected, "错误密码必须被拒");
        drop(bad);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            before,
            "错误密码不得建立通往业务目标的连接"
        );

        rust_task.abort();
        echo_task.abort();
        let _ = timeout(WAIT, rust_task).await;
        let _ = timeout(WAIT, echo_task).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_server_rejects_invalid_command_byte_over_tls() {
    timeout(WAIT, async {
        let identity = Identity::new();
        let mut validator = Validator::new();
        validator.add("cmd@example.com", PASSWORD).unwrap();
        let server = Server::with_tls(
            validator,
            Timeouts::new(WAIT, WAIT).unwrap(),
            identity.inbound(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = accept_one_tls(listener, server).await;

        let mut stream = identity
            .client()
            .connect((std::net::Ipv4Addr::LOCALHOST, port).into())
            .await
            .unwrap();
        stream.write_all(&raw_command_header(0xff)).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, WAIT).await;

        match task.await.unwrap() {
            Err(Error::InvalidCommand(0xff)) => {}
            other => panic!("期望 InvalidCommand(0xff)，得到 {other:?}"),
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_server_rejects_truncated_header_over_tls() {
    timeout(WAIT, async {
        let identity = Identity::new();
        let mut validator = Validator::new();
        validator.add("trunc@example.com", PASSWORD).unwrap();
        let handshake = Duration::from_millis(400);
        let server = Server::with_tls(
            validator,
            Timeouts::new(handshake, WAIT).unwrap(),
            identity.inbound(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = accept_one_tls(listener, server).await;

        // 哈希 + CRLF + 命令 + 地址首字节，此后静默 → 由握手截止结束。
        let header = codec::encode(
            &Request {
                command: Command::Tcp,
                target: TargetAddr::V4([127, 0, 0, 1], 9),
            },
            &Credential::new(PASSWORD),
        )
        .unwrap();
        assert!(header.len() > 60, "V4 目标头必须多于 60 字节");
        let mut stream = identity
            .client()
            .connect((std::net::Ipv4Addr::LOCALHOST, port).into())
            .await
            .unwrap();
        stream.write_all(&header[..60]).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, WAIT).await;

        match task.await.unwrap() {
            Err(Error::Timeout) => {}
            other => panic!("期望握手截止 Timeout，得到 {other:?}"),
        }
    })
    .await
    .unwrap();
}
