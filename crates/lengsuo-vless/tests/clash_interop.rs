//! Clash/Mihomo（Mihomo Meta v1.19.20）参考互通 · VLESS。
//!
//! 独立测试实例：配置写在仓外（`LENGSUO_CLASH_TEST_DIR`，默认
//! `/home/ubuntu/lengsuo-network-dev/clash-test`），只绑 `127.0.0.1` 的高位临时端口，
//! `external-controller` 关闭，日志落测试目录；退出时**按 PID** 杀并删目录。
//! ⛔ 绝不触碰 47 上的 root 生产实例（`/opt/clash-for-linux/conf/config.yaml`）。
//!
//! 实跑（默认二进制 `/opt/clash-for-linux/bin/clash-linux-amd64`，可用 `LENGSUO_MIHOMO` 覆盖）：
//!   cargo test -p lengsuo-vless --test clash_interop -- --nocapture
//!   cargo test -p lengsuo-vless --test clash_interop -- --ignored --nocapture
//!
//! 三向：
//!   1. Rust 客户端 -> Mihomo 协议入站 -> Mihomo `direct` 出站 -> 本仓 echo 服务；
//!   2. Mihomo `vless` 出站 -> 本仓服务端桩（`stream::receive_request` / `send_response`）；
//!   3. Rust<->Rust 基线（同一握手实现的回环，仅作方向 2 的对照，**不冒充互通**）。
use lengsuo_vless::{
    header::{Command, Request},
    stream::*,
};
use serde_json::{json, Value};
use ss_core::target::TargetAddr;
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
const ID: &str = "11111111-1111-1111-1111-111111111111";
const KEY: [u8; 16] = [0x11; 16];
const WAIT: Duration = Duration::from_secs(8);
const PAYLOAD: &[u8] = b"clash-interop vless payload\0binary\xff";

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
///
/// `tag` 同时决定测试目录与日志文件名；配置以 JSON 写盘（Mihomo 用 YAML 解析器，
/// YAML 是 JSON 的超集，故 JSON 合法）。
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

// ------------------------------------------------------------------ 本仓端点

/// 本仓 echo 服务：读满 `PAYLOAD` 后原样回写（方向 1 的目的地）。
async fn echo(listener: TcpListener) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut received = vec![0; PAYLOAD.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, PAYLOAD);
    stream.write_all(&received).await.unwrap();
    stream.shutdown().await.unwrap();
}

/// 本仓 VLESS 入站桩（方向 2/3 的被连端）：只做握手 + 原样回显。
///
/// 参考 Mihomo 客户端可能先建一条探测连接（无载荷），故循环到拿到真载荷为止。
async fn rust_vless_server(listener: TcpListener) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = match receive_request(&mut stream, &KEY, WAIT).await {
            Ok(request) => request,
            Err(Error::Io(_)) => continue,
            Err(error) => panic!("本仓入站握手失败 {error}"),
        };
        assert_eq!(request.command, Command::Tcp);
        let mut payload = vec![0; PAYLOAD.len()];
        if stream.read_exact(&mut payload).await.is_err() {
            continue;
        }
        assert_eq!(payload, PAYLOAD);
        send_response(&mut stream, WAIT).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        return;
    }
}

/// Rust 客户端走 Mihomo 的 `mixed-port` 发一条 TCP 请求到 `target_port`。
async fn proxy_payload(mixed_port: u16, target_port: u16) {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, mixed_port))
        .await
        .unwrap();
    // SOCKS5：无认证 + CONNECT 127.0.0.1:target_port。
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.unwrap();
    assert_eq!(choice, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT 被拒：{reply:?}");
    stream.write_all(PAYLOAD).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = vec![0; PAYLOAD.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, PAYLOAD, "载荷未逐字节一致");
    stream.shutdown().await.unwrap();
}

// ------------------------------------------------------------------ 用例

/// 方向 2：Mihomo `vless` 出站 -> 本仓服务端桩（TCP 主传输、无 TLS、flow 空）。
#[tokio::test]
async fn clash_outbound_to_rust_server_tcp() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let mixed_port = free_port();
        let mihomo = launch(
            base_config(
                mixed_port,
                json!({
                    "name": "rust", "type": "vless", "server": "127.0.0.1",
                    "port": rust_port, "uuid": ID, "network": "tcp", "udp": false,
                }),
            ),
            mixed_port,
            "vless-clash-out",
        )
        .await;
        let server = tokio::spawn(rust_vless_server(listener));
        proxy_payload(mixed_port, 18001).await;
        server.await.unwrap();
        drop(mihomo);
    })
    .await
    .unwrap();
}

/// 方向 3：Rust<->Rust 基线（对照方向 2 的本仓服务端桩是否自洽）。
#[tokio::test]
async fn rust_roundtrip_baseline_tcp() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(rust_vless_server(listener));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], 18001),
        };
        send_request(&mut stream, &request, &KEY, WAIT)
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        receive_response(&mut stream, WAIT).await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

/// 方向 1：Rust 客户端 -> Mihomo `vless` 协议入站 -> `direct` 出站 -> 本仓 echo。
///
/// TODO(对齐 Mihomo listener/vless)：确认入站是否强制 TLS（`InboundTLSOptions`）；
/// 若强制则本用例需带自签证书并让 Rust 侧走 TLS，否则按明文核对。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Mihomo 二进制；本用例待与 listener/vless 逐段对齐后实跑"]
async fn rust_client_to_clash_listener_tcp() {
    timeout(WAIT, async {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let in_port = free_port();
        let mixed_port = free_port();
        let mut config = base_config(
            mixed_port,
            json!({"name": "rust", "type": "vless", "server": "127.0.0.1", "port": echo_port, "uuid": ID}),
        );
        config["rules"] = json!(["MATCH,DIRECT"]);
        config["listeners"] = json!([{
            "name": "vless-in", "type": "vless", "port": in_port, "listen": "127.0.0.1",
            "users": [{"username": "u", "uuid": ID}],
        }]);
        let mihomo = launch(config, in_port, "vless-clash-in").await;
        let task = tokio::spawn(echo(echo_listener));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, in_port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], echo_port),
        };
        send_request(&mut stream, &request, &KEY, WAIT)
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        receive_response(&mut stream, WAIT).await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
        stream.shutdown().await.unwrap();
        task.await.unwrap();
        drop(mihomo);
    })
    .await
    .unwrap();
}

/// 负例：错误 UUID 必须被 Mihomo 入站拒掉（fail-closed，不得回退明文）。
///
/// TODO(对齐 Mihomo listener/vless)：入站 TLS 落地后补实跑。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Mihomo 二进制；本用例待与 listener/vless 逐段对齐后实跑"]
async fn wrong_uuid_is_rejected() {
    timeout(WAIT, async {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let in_port = free_port();
        let mixed_port = free_port();
        let mut config = base_config(
            mixed_port,
            json!({"name": "rust", "type": "vless", "server": "127.0.0.1", "port": echo_port, "uuid": ID}),
        );
        config["rules"] = json!(["MATCH,DIRECT"]);
        config["listeners"] = json!([{
            "name": "vless-in", "type": "vless", "port": in_port, "listen": "127.0.0.1",
            "users": [{"username": "u", "uuid": ID}],
        }]);
        let mihomo = launch(config, in_port, "vless-clash-deny").await;
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, in_port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], echo_port),
        };
        // 故意用错误 KEY；参考端必须不把连接落到 echo。
        send_request(&mut stream, &request, &[0x22; 16], WAIT)
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        assert!(
            timeout(Duration::from_millis(300), echo_listener.accept())
                .await
                .is_err(),
            "错误凭据不得连接目标"
        );
        drop(mihomo);
    })
    .await
    .unwrap();
}