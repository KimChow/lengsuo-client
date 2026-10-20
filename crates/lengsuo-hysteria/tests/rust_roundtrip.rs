//! 本仓客户端 ↔ 本仓服务端的闭环验收（非 ignore，锁定服务端逻辑）。
//!
//! 服务端：`HysteriaServer::bind` + `accept_loop`（ALPN=h3、openssl 现场
//! 自签证书进临时目录、masquerade 缺省 404）。客户端：既有
//! `HysteriaClient`（`src/quic/client.rs`）。
//!
//! 用例：
//! 1. TCP echo 三档载荷（1B / 4KiB / 256KiB）逐字节比对；
//! 2. UDP 往返（超限报文走 `frag_udp_message` 分片 + 服务端重组）；
//! 3. 错误 auth → 认证被拒（masquerade 404）。
//!
//! 这是自闭环、**不冒充**与官方 Xray 的互通；真实互通见
//! `tests/xray_hysteria_server.rs`（`#[ignore]`）。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig};
use lengsuo_hysteria::quic::{ClientConfig, ConnectError, HysteriaClient};

const AUTH: &str = "lengsuo-rust-roundtrip";
const SERVER_NAME: &str = "localhost";

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hy-rs-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

/// openssl 现场自签（SAN=DNS:localhost），只用临时目录。
fn gen_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ])
        .output()
        .expect("执行 openssl");
    assert!(
        out.status.success(),
        "openssl 生成自签证书失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (cert, key)
}

fn cert_der(cert: &Path, dir: &Path) -> Vec<u8> {
    let der_path = dir.join("cert.der");
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-outform", "DER", "-out"])
        .arg(&der_path)
        .output()
        .expect("执行 openssl x509");
    assert!(out.status.success(), "openssl 转 DER 失败");
    std::fs::read(der_path).expect("读取 DER 证书")
}

fn key_der(key: &Path) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(key)
        .args(["-outform", "DER"])
        .output()
        .expect("执行 openssl pkey");
    assert!(out.status.success(), "openssl 转私钥 DER 失败");
    out.stdout
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// 起一个本仓服务端（UDP 端口由系统分配）+ 返回（地址、证书 DER 与保活的
/// accept 任务句柄）。
struct Server {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    #[allow(dead_code)]
    dir: PathBuf,
    #[allow(dead_code)]
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        // accept_loop 会在 endpoint 关闭后退出；不强杀。
    }
}

async fn start_server(tag: &str) -> Server {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let key_der = key_der(&key);
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let config = ServerConfig {
        listen_addr: listen,
        cert_chain_der: vec![der.clone()],
        key_der,
        auth: AUTH.to_string(),
        brutal_down: 0,
        brutal_up: 0,
        udp_enabled: true,
        udp_idle_timeout_secs: 60,
        congestion: String::new(),
    };
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let addr = server.local_addr().expect("读取监听地址");
    let srv = Arc::clone(&server);
    let task = tokio::spawn(async move { srv.accept_loop().await });
    Server {
        addr,
        cert_der: der,
        dir,
        task,
    }
}

fn client_config(server: &Server, auth: &str) -> ClientConfig {
    ClientConfig {
        server_addr: server.addr,
        server_name: SERVER_NAME.to_string(),
        auth: auth.to_string(),
        roots_der: vec![server.cert_der.clone()],
        brutal_down: 0,
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    }
}

async fn connect_with(server: &Server, auth: &str) -> Result<HysteriaClient, ConnectError> {
    HysteriaClient::connect(client_config(server, auth)).await
}

/// 本地 TCP echo（服务端直连出站的目标）。
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 echo 端口");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 用例 1：TCP echo 三档载荷逐字节比对（经本仓服务端直连出站）。
#[tokio::test]
async fn tcp_echo_rust_roundtrip() {
    let server = start_server("tcp").await;
    let client = connect_with(&server, AUTH).await.expect("建连失败");
    let echo_addr = spawn_tcp_echo().await;
    for size in [1usize, 4 * 1024, 256 * 1024] {
        let payload = pattern(size);
        let fut = async {
            let mut stream = proxy::tcp_connect(&client, &echo_addr.to_string())
                .await
                .expect("tcp_connect 失败");
            stream.write_all(&payload).await.expect("写入失败");
            stream.finish().expect("半关闭失败");
            let mut got = Vec::with_capacity(size);
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("读取失败");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            got
        };
        let got = tokio::time::timeout(Duration::from_secs(30), fut)
            .await
            .expect("echo 超时");
        assert_eq!(got.len(), payload.len(), "回包长度不符（size={size}）");
        assert_eq!(got, payload, "回包内容不符（size={size}）");
    }
}

/// 用例 2：UDP 往返（小报文直通 + 超限报文经分片重组）。
#[tokio::test]
async fn udp_echo_rust_roundtrip() {
    let server = start_server("udp").await;
    let client = connect_with(&server, AUTH).await.expect("建连失败");
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("绑定 UDP echo");
    let echo_addr = echo.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            if echo.send_to(&buf[..n], from).await.is_err() {
                return;
            }
        }
    });
    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    // 小报文（直通）与超限报文（分片）各一轮。超限用 3000 字节，远超
    // 典型 1200 的 datagram 上限，必然触发 frag_udp_message 分片路径。
    for size in [64usize, 3000] {
        let payload = pattern(size);
        let addr_bytes = echo_addr.to_string().into_bytes();
        let dgrams = proxy::udp_out_datagrams(session.id, &addr_bytes, &payload, 1200)
            .expect("组 UDP datagram");
        for d in &dgrams {
            session
                .send_raw(d)
                .expect("UDP 发送失败（种子耗尽或对端拒绝）");
        }
        let mut defrag = proxy::OwnedDefragger::default();
        let got = tokio::time::timeout(
            Duration::from_secs(10),
            proxy::udp_recv(&mut session, &mut defrag),
        )
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");
        assert_eq!(got.data, payload, "UDP 回包内容不符（size={size}）");
    }
}

/// 用例 3：错误 auth → 认证被拒（masquerade 缺省 404）。
#[tokio::test]
async fn wrong_auth_rust_roundtrip() {
    let server = start_server("auth").await;
    let err = match connect_with(&server, "definitely-wrong-password").await {
        Err(e) => e,
        Ok(_) => panic!("错误 auth 不应建连成功"),
    };
    let status = err
        .rejected_status()
        .unwrap_or_else(|| panic!("错误 auth 应表现为认证被拒，实际: {err:?}"));
    assert_eq!(status, 404, "masquerade 缺省应回 404，实际 {status}");
}
