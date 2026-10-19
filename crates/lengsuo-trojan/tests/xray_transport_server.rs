//! 反向：官方 Xray **客户端**（trojan 出站套 `network=ws|httpupgrade`）→ 本仓
//! 服务端（TLS 接入 → 外层传输升级 → trojan 处理）。默认忽略，必须 `--ignored` 实跑。
//!
//! 这是「外层传输」的服务端方向覆盖：本仓必须能作为对端，接受 Xray 客户端的
//! WS / HTTPUpgrade 升级并正确解码帧（服务端方向：收掩码帧、发不掩码帧）。
//! 目标由本仓服务端的 CONNECT 拨号抵达独立回环回显后端。
//!
//! 断言：回环回显逐字节一致，且后端 accept 计数 `== 1`（证明 trojan 头部与载荷
//! 确实穿过外层传输被本仓解出并转发）。错误 path 必须被本仓拒绝（升级失败）。

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use lengsuo_trojan::server::{Server, Timeouts, Validator};
use lengsuo_trojan::transport::server as transport_server;
use serde_json::{json, Value};
use support::{free_port, launch, WAIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PASSWORD: &str = "interop-trojan-transport-password";
const HTTP_REQUEST: &[u8] = b"GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const PATH: &str = "/lengsuo-trojan";
const TOTAL: Duration = Duration::from_secs(90);

struct Identity {
    cert: rcgen::CertifiedKey,
}

impl Identity {
    fn new() -> Self {
        Self {
            cert: rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap(),
        }
    }

    fn client_settings(&self) -> Value {
        json!({"security":"tls","tlsSettings":{"serverName":"localhost",
            "disableSystemRoot":true,"certificates":[{"usage":"verify",
            "certificate":self.cert.cert.pem().lines().collect::<Vec<_>>()}]}})
    }
}

/// 回显后端：读满 `len` 字节后原样回写并关写端；返回端口、accept 计数与句柄。
async fn spawn_echo(len: usize) -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
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
            tokio::spawn(async move {
                let mut buf = vec![0u8; len];
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

/// 本仓服务端：TLS 接入 → 外层传输升级（ws/httpupgrade）→ trojan `server::process`。
/// 返回端口与任务句柄。
async fn spawn_rust_transport_server(
    identity: &Identity,
    network: &'static str,
    path: &'static str,
) -> (u16, tokio::task::JoinHandle<()>) {
    let mut validator = Validator::new();
    validator.add("interop@example.com", PASSWORD).unwrap();
    let server = Server::new(validator, Timeouts::new(WAIT, WAIT).unwrap());
    let tls = TlsServer::new(
        vec![identity.cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(identity.cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .unwrap();
    let config = transport_server::Config::new(path, "");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tls = tls.clone();
            let server = server.clone();
            let config = config.clone();
            tokio::spawn(async move {
                let Ok(stream) = tls.accept(socket).await else {
                    return;
                };
                match network {
                    "ws" => {
                        if let Ok(conn) = transport_server::accept_ws(stream, &config, WAIT).await {
                            let _ = server.process(conn).await;
                        }
                    }
                    "httpupgrade" => {
                        if let Ok(conn) =
                            transport_server::accept_httpupgrade(stream, &config, WAIT).await
                        {
                            let _ = server.process(conn).await;
                        }
                    }
                    _ => unreachable!(),
                }
            });
        }
    });
    (port, task)
}

/// Xray 配置：本地 socks 入站 + trojan 出站（套外层传输）指向本仓服务端。
fn xray_config(
    socks: u16,
    rust_port: u16,
    identity: &Identity,
    network: &str,
    path: &str,
) -> Value {
    let mut stream = identity.client_settings();
    stream["network"] = json!(network);
    if network == "ws" {
        stream["wsSettings"] = json!({"path": path});
    } else {
        stream["httpupgradeSettings"] = json!({"path": path});
    }
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":socks,"protocol":"socks",
            "settings":{"auth":"noauth"}}],
        "outbounds":[{"protocol":"trojan","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"password":PASSWORD}]},
            "streamSettings":stream}]})
}

/// 最小 SOCKS5 TCP CONNECT（no-auth，IPv4）。
async fn socks5_connect(proxy_port: u16, target_port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::other("socks 协商失败"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "socks CONNECT 失败",
        ));
    }
    let extra = match head[3] {
        1 => 6,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0]) + 2
        }
        4 => 18,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "坏 ATYP",
            ))
        }
    };
    let mut tail = vec![0u8; extra];
    stream.read_exact(&mut tail).await?;
    Ok(stream)
}

async fn socks_roundtrip(socks_port: u16, echo_port: u16) {
    let mut tunnel = socks5_connect(socks_port, echo_port)
        .await
        .expect("socks CONNECT 应成功");
    tunnel.write_all(HTTP_REQUEST).await.unwrap();
    let mut reply = vec![0u8; HTTP_REQUEST.len()];
    timeout(WAIT, tunnel.read_exact(&mut reply))
        .await
        .expect("回程超时")
        .unwrap();
    assert_eq!(reply, HTTP_REQUEST, "回程必须逐字节一致");
}

async fn run_reverse(network: &'static str) {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted, echo_task) = spawn_echo(HTTP_REQUEST.len()).await;
        let (rust_port, rust_task) = spawn_rust_transport_server(&identity, network, PATH).await;

        let socks = free_port();
        let reference = launch(
            xray_config(socks, rust_port, &identity, network, PATH),
            socks,
        )
        .await;
        socks_roundtrip(socks, echo_port).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "必须抵达回显后端一次");

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
async fn xray_client_over_ws_to_rust_server() {
    run_reverse("ws").await;
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_over_httpupgrade_to_rust_server() {
    run_reverse("httpupgrade").await;
}

/// 错误 path：本仓服务端配置 `/lengsuo-trojan`，Xray 客户端配 `/wrong` —— 升级
/// 必须失败，Xray 的 socks CONNECT 拿不到隧道（连接被拒或读不到回程），
/// 且回显后端 accept 计数不增长。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_wrong_path_rejected_by_rust_server() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted, echo_task) = spawn_echo(HTTP_REQUEST.len()).await;
        let (rust_port, rust_task) = spawn_rust_transport_server(&identity, "ws", PATH).await;

        let socks = free_port();
        let reference = launch(
            xray_config(socks, rust_port, &identity, "ws", "/wrong-path"),
            socks,
        )
        .await;
        // 隧道建立或回程任一失败即视为被拒。
        let mut rejected = false;
        match socks5_connect(socks, echo_port).await {
            Ok(mut tunnel) => {
                let _ = timeout(WAIT, tunnel.write_all(HTTP_REQUEST)).await;
                let mut reply = vec![0u8; HTTP_REQUEST.len()];
                match timeout(Duration::from_secs(8), tunnel.read(&mut reply)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => rejected = true,
                    Ok(Ok(n)) if n < HTTP_REQUEST.len() => rejected = true,
                    Ok(Ok(_)) => {}
                    Err(_) => rejected = true,
                }
            }
            Err(_) => rejected = true,
        }
        assert!(rejected, "错误 path 必须被拒");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "错误 path 不得抵达业务目标"
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
