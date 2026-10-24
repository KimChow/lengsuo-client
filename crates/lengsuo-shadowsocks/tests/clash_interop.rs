//! Clash/Mihomo（Mihomo Meta v1.19.20）参考互通 · Shadowsocks（AEAD `aes-128-gcm`）。
//!
//! 独立测试实例：配置写在仓外（`LENGSUO_CLASH_TEST_DIR`，默认
//! `/home/ubuntu/lengsuo-network-dev/clash-test`），只绑 `127.0.0.1` 的高位临时端口，
//! `external-controller` 关闭，日志落测试目录；退出时**按 PID** 杀并删目录。
//! ⛔ 绝不触碰 47 上的 root 生产实例（`/opt/clash-for-linux/conf/config.yaml`）。
//!
//! 实跑（默认二进制 `/opt/clash-for-linux/bin/clash-linux-amd64`，可用 `LENGSUO_MIHOMO` 覆盖）：
//!   cargo test -p lengsuo-shadowsocks --test clash_interop -- --nocapture
//!   cargo test -p lengsuo-shadowsocks --test clash_interop -- --ignored --nocapture
//!
//! 三向：
//!   1. Rust 客户端 -> Mihomo `ss` 协议入站 -> Mihomo `direct` 出站 -> 本仓 echo 服务；
//!   2. Mihomo `ss` 出站 -> 本仓中继服务（`relay::RelayService`，对齐参考
//!      `proxy/shadowsocks/server.go:handleConnection`）-> 本仓 echo 服务；
//!   3. Rust<->Rust 基线（本仓 `tcp::Reader`/`tcp::Writer` 客户端 -> 同一中继服务，
//!      仅作方向 2 的对照，**不冒充互通**）。
use lengsuo_shadowsocks::{CipherSuite, RelayConfig, RelayConfigParts, RelayService, TargetAddr};
use lengsuo_shadowsocks::{TcpReader, TcpWriter};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::LocalSet,
    time::{timeout, Instant},
};

const DEFAULT_MIHOMO: &str = "/opt/clash-for-linux/bin/clash-linux-amd64";
const CIPHER: &str = "aes-128-gcm";
const SUITE: CipherSuite = CipherSuite::Aes128Gcm;
const PASSWORD: &str = "clash-interop-fake";
const WAIT: Duration = Duration::from_secs(8);
const PAYLOAD: &[u8] = b"clash-interop shadowsocks payload\0binary\xff";

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

/// 本仓中继服务配置：单一口令、单一 AEAD 套件、无重放窗口（对齐参考基线）。
fn relay_config() -> RelayConfig {
    RelayConfig::new(
        RelayConfigParts {
            suite: SUITE,
            idle_timeout: WAIT,
            replay: None,
        },
        PASSWORD.as_bytes(),
    )
}

/// 本仓中继服务绑定回环临时端口，返回（端口，已启动的服务句柄）。
///
/// `RelayService::start` 用 `spawn_local` 并发连接任务，故调用方必须在一个
/// `LocalSet` 里 await（服务本身不要求 `Send`）。
async fn start_relay() -> (u16, lengsuo_shadowsocks::RelayHandle) {
    let service = RelayService::bind("127.0.0.1:0".parse().unwrap(), relay_config())
        .await
        .unwrap();
    let port = service.local_addr().unwrap().port();
    let handle = service.start().await.unwrap();
    (port, handle)
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

/// 用本仓 ss 客户端（`tcp::Writer`/`tcp::Reader`）连 `ss_port`，向 `target_port`
/// 发一条请求并读回逐字节一致的载荷。
async fn rust_ss_client_roundtrip(ss_port: u16, target_port: u16) -> Result<(), String> {
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, ss_port))
        .await
        .map_err(|e| e.to_string())?;
    let (read_half, write_half) = stream.split();
    let mut writer =
        TcpWriter::new(write_half, SUITE, PASSWORD.as_bytes(), WAIT).map_err(|e| e.to_string())?;
    let mut reader =
        TcpReader::new(read_half, SUITE, PASSWORD.as_bytes(), WAIT).map_err(|e| e.to_string())?;
    // 首个 chunk：SOCKS 地址（ATYP+地址+端口）。
    let mut address = Vec::new();
    TargetAddr::V4([127, 0, 0, 1], target_port).encode_into(&mut address);
    writer.send(&address).await.map_err(|e| e.to_string())?;
    writer.send(PAYLOAD).await.map_err(|e| e.to_string())?;
    writer.shutdown().await.map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    while response.len() < PAYLOAD.len() {
        match reader.recv().await.map_err(|e| e.to_string())? {
            Some(chunk) => response.extend_from_slice(&chunk),
            None => break,
        }
    }
    assert_eq!(response, PAYLOAD, "载荷未逐字节一致");
    Ok(())
}

/// 重试跨过 Mihomo 入站监听的初始化窗口（与 mixed-port 同类时序行为，实测
/// 全量跑时首连可能被 reset；单连重试可解释地消除窗口，超次 fail-closed）。
async fn rust_ss_client_retry(ss_port: u16, target_port: u16) {
    let mut last = String::from("未尝试");
    for _ in 0..20 {
        match rust_ss_client_roundtrip(ss_port, target_port).await {
            Ok(()) => return,
            Err(error) => {
                last = error;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("ss 客户端拨号在 20 次重试内未成功（窗口期过长？）：{last}");
}

// ------------------------------------------------------------------ 用例

/// 方向 2：Mihomo `ss` 出站 -> 本仓中继服务 -> echo，载荷逐字节一致。
#[tokio::test]
async fn clash_outbound_to_rust_server_tcp() {
    timeout(WAIT, async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let echo_port = echo_listener.local_addr().unwrap().port();
                let (ss_port, handle) = start_relay().await;
                let mixed_port = free_port();
                let mihomo = launch(
                    base_config(
                        mixed_port,
                        json!({
                            "name": "rust", "type": "ss", "server": "127.0.0.1",
                            "port": ss_port, "cipher": CIPHER, "password": PASSWORD,
                            "udp": false,
                        }),
                    ),
                    mixed_port,
                    "ss-clash-out",
                )
                .await;
                let echo_task = tokio::spawn(echo(echo_listener));
                proxy_payload(mixed_port, echo_port).await;
                echo_task.await.unwrap();
                handle.shutdown().await.unwrap();
                drop(mihomo);
            })
            .await;
    })
    .await
    .unwrap();
}

/// 方向 3：Rust<->Rust 基线（本仓 ss 客户端 -> 同一中继服务 -> echo）。
#[tokio::test]
async fn rust_roundtrip_baseline_tcp() {
    timeout(WAIT, async {
        let local = LocalSet::new();
        local
            .run_until(async {
                let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let echo_port = echo_listener.local_addr().unwrap().port();
                let (ss_port, handle) = start_relay().await;
                let echo_task = tokio::spawn(echo(echo_listener));
                rust_ss_client_roundtrip(ss_port, echo_port).await.unwrap();
                echo_task.await.unwrap();
                handle.shutdown().await.unwrap();
            })
            .await;
    })
    .await
    .unwrap();
}

/// 方向 1：Rust 客户端 -> Mihomo `ss` 协议入站 -> `direct` 出站 -> 本仓 echo。
/// 实测（2026-10-25）：入站类型名是 `shadowsocks`（`ss`/`shadowaead` 均被拒：
/// `unsupport proxy type`），出站类型名是 `ss`。
#[tokio::test]
async fn rust_client_to_clash_listener_tcp() {
    timeout(WAIT, async {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let in_port = free_port();
        let mixed_port = free_port();
        let mut config = base_config(
            mixed_port,
            json!({"name": "rust", "type": "ss", "server": "127.0.0.1", "port": echo_port,
                   "cipher": CIPHER, "password": PASSWORD}),
        );
        config["rules"] = json!(["MATCH,DIRECT"]);
        config["listeners"] = json!([{
            "name": "ss-in", "type": "shadowsocks", "port": in_port, "listen": "127.0.0.1",
            "cipher": CIPHER, "password": PASSWORD,
        }]);
        let mihomo = launch(config, in_port, "ss-clash-in").await;
        let echo_task = tokio::spawn(echo(echo_listener));
        rust_ss_client_retry(in_port, echo_port).await;
        echo_task.await.unwrap();
        drop(mihomo);
    })
    .await
    .unwrap();
}
