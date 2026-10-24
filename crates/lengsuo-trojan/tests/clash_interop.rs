//! Clash/Mihomo（Mihomo Meta v1.19.20）参考互通 · Trojan。
//!
//! 独立测试实例：配置写在仓外（`LENGSUO_CLASH_TEST_DIR`，默认
//! `/home/ubuntu/lengsuo-network-dev/clash-test`），只绑 `127.0.0.1` 的高位临时端口，
//! `external-controller` 关闭，日志落测试目录；退出时**按 PID** 杀并删目录。
//! ⛔ 绝不触碰 47 上的 root 生产实例（`/opt/clash-for-linux/conf/config.yaml`）。
//!
//! 实跑（默认二进制 `/opt/clash-for-linux/bin/clash-linux-amd64`，可用 `LENGSUO_MIHOMO` 覆盖）：
//!   cargo test -p lengsuo-trojan --test clash_interop -- --nocapture
//!   cargo test -p lengsuo-trojan --test clash_interop -- --ignored --nocapture
//!
//! Trojan 的**线上传输恒为 TLS**（参考 `proxy/trojan` 不带明文监听）：本文件用
//! `rcgen` 现场自签证书，Mihomo 出站带 `skip-cert-verify`（方向 2），Rust 侧
//! `lengsuo_tls::TlsClient` 显式信任同一张证书（方向 .\）。
//!
//! 三向：
//!   1. Rust 客户端 -> Mihomo `trojan` 协议入站 -> Mihomo `direct` 出站 -> 本仓 echo 服务；
//!   2. Mihomo `trojan` 出站 -> 本仓 TLS 服务端（`server::Server::with_tls`，
//!      对齐参考 `proxy/trojan/server.go:Process`）-> 本仓 echo 服务；
//!   3. Rust<->Rust 基线（本仓 trojan 客户端 -> 同一 TLS 服务端，仅作方向 2 的
//!      对照，**不冒充互通**）。
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient};
use lengsuo_trojan::server::{Inbound, Server, Timeouts, Validator};
use lengsuo_trojan::{stream, Command, Credential, Request, TargetAddr};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Instant},
};

const DEFAULT_MIHOMO: &str = "/opt/clash-for-linux/bin/clash-linux-amd64";
const PASSWORD: &str = "clash-interop-fake";
const WAIT: Duration = Duration::from_secs(8);
const PAYLOAD: &[u8] = b"clash-interop trojan payload\0binary\xff";

// ---------------------------------------------------------------- Mihomo 实例

struct Mihomo {
    child: Child,
    directory: PathBuf,
}

impl Drop for Mihomo {
    fn drop(&mut self) {
        // 只按 PID 清理自己起的实例；⛔ 绝不 pkill/killall 按名杀（会命中 root 生产实例）。
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::env::var("LENGSUO_KEEP_REF_LOG").is_ok() {
            if let Ok(log) = std::fs::read_to_string(self.directory.join("mihomo.log")) {
                eprintln!("--- Mihomo 日志 {} ---\n{log}", self.directory.display());
            }
            return;
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn mihomo_binary() -> String {
    std::env::var("LENGSUO_MIHOMO").unwrap_or_else(|_| DEFAULT_MIHOMO.to_string())
}

/// 仓外测试目录（不进仓库、不提交）。`tag` 用协议名，`pid` 隔离并发测试进程。
fn test_directory(tag: &str) -> PathBuf {
    let base = std::env::var("LENGSUO_CLASH_TEST_DIR")
        .unwrap_or_else(|_| "/home/ubuntu/lengsuo-network-dev/clash-test".into());
    let directory = PathBuf::from(base).join(format!("{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// 启动独立 Mihomo 实例并等到 `probe_port` 可连。
async fn launch(config: Value, probe_port: u16, tag: &str) -> Mihomo {
    let binary = mihomo_binary();
    assert!(
        std::path::Path::new(&binary).exists(),
        "缺少 Mihomo 参考二进制：{binary}（设 LENGSUO_MIHOMO 覆盖）"
    );
    let version = Process::new(&binary).arg("-v").output().unwrap();
    let version = String::from_utf8_lossy(&version.stdout).into_owned();
    assert!(
        version.contains("Mihomo") && version.contains("v1.19.20"),
        "基线不匹配：{version}"
    );
    let directory = test_directory(tag);
    let path = directory.join("config.yaml");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = std::fs::File::create(directory.join("mihomo.log")).unwrap();
    let child = Process::new(&binary)
        .arg("-d")
        .arg(&directory)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut mihomo = Mihomo { child, directory };
    let end = Instant::now() + WAIT;
    loop {
        if let Some(status) = mihomo.child.try_wait().unwrap() {
            panic!(
                "Mihomo 提前退出 {status}：{}",
                std::fs::read_to_string(mihomo.directory.join("mihomo.log")).unwrap()
            );
        }
        if TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, probe_port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < end, "Mihomo 启动超时");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    println!("基线 Mihomo {version}测试端口 {probe_port}");
    mihomo
}

/// Mihomo 公共骨架：只回环、无控制接口、无 DNS 泄漏、MATCH 全走指定 proxy。
fn base_config(mixed_port: u16, proxy: Value) -> Value {
    json!({
        "mixed-port": mixed_port,
        "allow-lan": false,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "warning",
        "external-controller": "",
        "ipv6": false,
        "dns": {"enable": false},
        "proxies": [proxy],
        "proxy-groups": [{"name": "proxy", "type": "select", "proxies": ["rust"]}],
        "rules": ["MATCH,proxy"],
    })
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ------------------------------------------------------------------ 自签身份

/// 现场自签证书：`Identity` 同时供本仓 TLS 服务端（`server::Inbound`）与
/// 本仓 TLS 客户端（`TlsClient`）使用。写法照抄 `tests/xray_trojan_client.rs`。
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
}

// ------------------------------------------------------------------ 本仓端点

/// 本仓 echo 服务：读满 `PAYLOAD` 后原样回写（方向 1/2/3 的目的地）。
async fn echo(listener: TcpListener) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut received = vec![0; PAYLOAD.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, PAYLOAD);
    stream.write_all(&received).await.unwrap();
    stream.shutdown().await.unwrap();
}

/// 本仓 trojan TLS 服务端（方向 2/3 的被连端）：`Server::with_tls` + accept 循环。
async fn spawn_rust_server(
    identity: &Identity,
    password: &str,
) -> (u16, tokio::task::JoinHandle<()>) {
    let mut validator = Validator::new();
    validator
        .add("clash-interop@example.invalid", password)
        .unwrap();
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

/// Rust 客户端走 Mihomo 的 `mixed-port` 发一条 TCP 请求到 `target_port`。
///
/// ⚠️ Mihomo 的 mixed-port 在监听之后仍有一段初始化窗口：窗口内的 SOCKS5 握手会
/// 被接受、CONNECT 也回成功，但拨号被静默丢弃（实测表现为 payload 后立刻 EOF）。
/// 这是参考实现的时序行为，不是本仓缺陷 ⇒ 用重试跨过窗口，超次即 fail-closed。
async fn proxy_payload(mixed_port: u16, target_port: u16) {
    let mut last = String::from("未尝试");
    for _ in 0..20 {
        match proxy_payload_once(mixed_port, target_port).await {
            Ok(()) => return,
            Err(error) => {
                last = error;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("SOCKS5 拨号在 20 次重试内未成功（窗口期过长？）：{last}");
}

/// 单次 SOCKS5 拨号；无认证 + CONNECT 127.0.0.1:target_port。
async fn proxy_payload_once(mixed_port: u16, target_port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, mixed_port))
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&[5, 1, 0])
        .await
        .map_err(|e| e.to_string())?;
    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(choice, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|e| e.to_string())?;
    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT 被拒：{reply:?}");
    stream.write_all(PAYLOAD).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let mut response = vec![0; PAYLOAD.len()];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(response, PAYLOAD, "载荷未逐字节一致");
    stream.shutdown().await.map_err(|e| e.to_string())?;
    Ok(())
}

// ------------------------------------------------------------------ 用例

/// 方向 2：Mihomo `trojan` 出站（`skip-cert-verify`）-> 本仓 TLS 服务端 -> echo。
#[tokio::test]
async fn clash_outbound_to_rust_server_tcp() {
    timeout(WAIT, async {
        let identity = Identity::new();
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let (rust_port, server) = spawn_rust_server(&identity, PASSWORD).await;
        let mixed_port = free_port();
        let mihomo = launch(
            base_config(
                mixed_port,
                json!({
                    "name": "rust", "type": "trojan", "server": "127.0.0.1",
                    "port": rust_port, "password": PASSWORD, "skip-cert-verify": true,
                    "udp": false,
                }),
            ),
            mixed_port,
            "trojan-clash-out",
        )
        .await;
        let echo_task = tokio::spawn(echo(echo_listener));
        proxy_payload(mixed_port, echo_port).await;
        echo_task.await.unwrap();
        server.abort();
        drop(mihomo);
    })
    .await
    .unwrap();
}

/// 方向 3：Rust<->Rust 基线（本仓 trojan 客户端 -> 同一 TLS 服务端 -> echo）。
#[tokio::test]
async fn rust_roundtrip_baseline_tcp() {
    timeout(WAIT, async {
        let identity = Identity::new();
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let (rust_port, server) = spawn_rust_server(&identity, PASSWORD).await;
        let echo_task = tokio::spawn(echo(echo_listener));
        let mut stream = identity
            .client()
            .connect((std::net::Ipv4Addr::LOCALHOST, rust_port).into())
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], echo_port),
        };
        stream::send_request(&mut stream, &request, &Credential::new(PASSWORD), WAIT)
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
        echo_task.await.unwrap();
        server.abort();
    })
    .await
    .unwrap();
}

/// 方向 1：Rust 客户端 -> Mihomo `trojan` 协议入站 -> `direct` 出站 -> 本仓 echo。
#[tokio::test]
async fn rust_client_to_clash_listener_tcp() {
    timeout(WAIT, async {
        let identity = Identity::new();
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let in_port = free_port();
        let mixed_port = free_port();
        let mut config = base_config(
            mixed_port,
            json!({"name": "rust", "type": "trojan", "server": "127.0.0.1", "port": echo_port,
                   "password": PASSWORD, "skip-cert-verify": true}),
        );
        config["rules"] = json!(["MATCH,DIRECT"]);
        config["listeners"] = json!([{
            "name": "trojan-in", "type": "trojan", "port": in_port, "listen": "127.0.0.1",
            "users": [{"username": "u", "password": PASSWORD}],
            "certificate": identity.cert.cert.pem(),
            "private-key": identity.cert.key_pair.serialize_pem(),
        }]);
        let mihomo = launch(config, in_port, "trojan-clash-in").await;
        let echo_task = tokio::spawn(echo(echo_listener));
        let mut stream = identity
            .client()
            .connect((std::net::Ipv4Addr::LOCALHOST, in_port).into())
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], echo_port),
        };
        stream::send_request(&mut stream, &request, &Credential::new(PASSWORD), WAIT)
            .await
            .unwrap();
        // trojan-over-TLS：写半关闭即 close_notify，双向关停 ⇒ 读回显前不半关闭
        //（实测 Mihomo 会在半关闭后立即断链，回显拿不到）。
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
        echo_task.await.unwrap();
        drop(mihomo);
    })
    .await
    .unwrap();
}
