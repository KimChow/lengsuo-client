//! 客户端全链路端到端测试：浏览器代理参数 → 本地 SOCKS5 → 策略分流 →
//! 真实 SS AEAD 隧道 → 真实 `RelayService` → 目标 echo → 原路返回。
//!
//! 真实组件（不是桩、不是自家 roundtrip）：
//! - `lengsuo_shadowsocks::RelayService` —— 仓内可部署的真实 SS TCP 服务端；
//! - `ss_client::runtime::Runtime` —— 真实入站 + 分流 + 出口；
//! - `lengsuo_browser_launch::ProxyConfig` —— 浏览器 `--proxy-server` 渲染。
//!
//! 注意 `Runtime::run` 的 future 持有 `!Send` 的 `Tunnel`（见 runtime 模块文档），
//! `RelayService::start` 用 `spawn_local`，故涉及运行时的用例都在 `LocalSet` 里跑。

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_browser_launch::{ProxyConfig, ProxyScheme};
use lengsuo_shadowsocks::{CipherSuite, RelayConfig, RelayConfigParts, RelayHandle, RelayService};
use ss_client::config::{load_config_str, ClientConfig};
use ss_client::runtime::Runtime;
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, LocalSet};

const TIMEOUT: Duration = Duration::from_secs(10);
const METHOD: &str = "aes-256-gcm";
const PASSWORD: &str = "e2e-relay-password";
const WRONG_PASSWORD: &str = "e2e-wrong-password";

/// 每个 await 都套 10s 超时；超时即 panic（测试不允许悬挂）。
async fn timed<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("operation timed out")
}

/// 命中 127.0.0.1/32 走代理；其余（含 fallback）走直连。
const PROXY_LOOPBACK: &str =
    "fallback = \"direct\"\n[[rules]]\nname = \"loopback-proxy\"\naction = \"proxy\"\n\
     match = { ip = [\"127.0.0.1/32\"] }\n";

/// 命中 127.0.0.1/32 走直连。
const DIRECT_LOOPBACK: &str = "[[rules]]\nname = \"loopback-direct\"\naction = \"direct\"\n\
     match = { ip = [\"127.0.0.1/32\"] }\n";

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// 客户端配置：规则 + 指向给定 SS 服务端的出口。
fn config(rules: &str, server: SocketAddr, password: &str) -> ClientConfig {
    load_config_str(&format!(
        "{rules}\n[outbound]\nss_url = \"ss://{METHOD}:{password}@{server}\"\n\
         connect_timeout_ms = 2_000\n"
    ))
    .expect("test config must load")
}

/// 单连接 echo 服务端；返回监听端口与已收到的字节计数。
async fn spawn_echo() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 1024];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    seen.fetch_add(n, Ordering::SeqCst);
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    (port, count)
}

/// 起真实 `RelayService`（aes-256-gcm）。须在 `LocalSet` 内调用（内部 `spawn_local`）。
async fn start_relay(password: &str) -> (SocketAddr, RelayHandle) {
    let config = RelayConfig::new(
        RelayConfigParts {
            suite: CipherSuite::Aes256Gcm,
            idle_timeout: Duration::from_secs(10),
            replay: None,
        },
        password.as_bytes(),
    );
    let service = timed(RelayService::bind(loopback(), config)).await.unwrap();
    let addr = service.local_addr().unwrap();
    let handle = timed(service.start()).await.unwrap();
    (addr, handle)
}

/// 起真实 `Runtime` 并后台跑 accept 循环。须在 `LocalSet` 内调用。
async fn start_runtime(config: ClientConfig) -> (SocketAddr, JoinHandle<()>) {
    let runtime = timed(Runtime::with_bind(config, loopback())).await.unwrap();
    let addr = runtime.local_addr().unwrap();
    let task = tokio::task::spawn_local(async move {
        let _ = runtime.run().await;
    });
    (addr, task)
}

/// SOCKS5 无认证 greeting：`05 01 00` ⇒ 断言回 `05 00`。
async fn socks_greeting(client: &mut TcpStream) {
    timed(client.write_all(&[0x05, 0x01, 0x00])).await.unwrap();
    let mut reply = [0u8; 2];
    timed(client.read_exact(&mut reply)).await.unwrap();
    assert_eq!(reply, [0x05, 0x00], "SOCKS5 no-auth greeting must succeed");
}

/// SOCKS5 CONNECT；`payload` 与请求头写在**同一次 write**（成为入站 `residual`）。
///
/// 必须与请求同批发送：`Dialer::connect` 要读到**首个认证回程 chunk** 才返回，
/// 而运行时只把 `residual` 作为隧道首批载荷转交。若在 CONNECT 应答后才写业务
/// 数据，客户端字节会滞留在入站 socket 里（splice 尚未开始），而隧道又在等
/// 目标先开口 —— 客户端先说话的场景（echo 正是如此）会互相等待。
/// 这是 `src/outbound/dialer.rs` 的既有语义，本卡不改 `src/`，见报告。
async fn socks_connect(
    proxy: SocketAddr,
    target: &TargetAddr,
    payload: &[u8],
) -> (TcpStream, [u8; 10]) {
    let mut client = timed(TcpStream::connect(proxy)).await.unwrap();
    socks_greeting(&mut client).await;
    let mut request = vec![0x05, 0x00, 0x01];
    target.encode_into(&mut request);
    request.extend_from_slice(payload);
    timed(client.write_all(&request)).await.unwrap();
    let mut reply = [0u8; 10];
    timed(client.read_exact(&mut reply)).await.unwrap();
    (client, reply)
}

/// 主证据：SOCKS5 → 分流(proxy) → SS 隧道 → 真实 RelayService → echo → 原路返回。
#[tokio::test(flavor = "current_thread")]
async fn proxy_chain_roundtrip() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let (echo_port, echo_bytes) = spawn_echo().await;
        let (relay_addr, relay_handle) = start_relay(PASSWORD).await;
        let (proxy_addr, runtime_task) =
            start_runtime(config(PROXY_LOOPBACK, relay_addr, PASSWORD)).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);

        let (mut client, reply) = socks_connect(proxy_addr, &target, b"hello-e2e").await;
        assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT must be accepted");

        let payload = b"hello-e2e";
        let mut got = [0u8; 9];
        timed(client.read_exact(&mut got)).await.unwrap();
        assert_eq!(&got, payload, "payload must round-trip byte-for-byte");

        // `RelayService` 不暴露 accept 计数，故以 echo 服务端**实际收到的字节**为判据：
        // 只有 proxy 路径真的拨通目标，这 9 字节才可能到达 echo。
        assert_eq!(
            echo_bytes.load(Ordering::SeqCst),
            payload.len(),
            "echo server must have seen the tunnelled payload"
        );

        runtime_task.abort();
        let _ = runtime_task.await;
        timed(relay_handle.shutdown()).await.unwrap();
    }))
    .await;
}

/// 浏览器交接：渲染出的 `--proxy-server` 指向运行时实际监听的 SOCKS5 端口。
#[tokio::test]
async fn browser_arg_matches_listener() {
    let config = config(PROXY_LOOPBACK, "127.0.0.1:1".parse().unwrap(), PASSWORD);
    let runtime = timed(Runtime::with_bind(config, loopback())).await.unwrap();
    let port = runtime.local_addr().unwrap().port();

    let proxy = ProxyConfig::empty()
        .with_endpoint(ProxyScheme::Socks5, "127.0.0.1", port)
        .expect("valid socks5 endpoint");
    let rendered = proxy.chromium_server_value().unwrap();

    assert!(rendered.contains("socks5://"), "rendered: {rendered}");
    assert!(
        rendered.contains("127.0.0.1"),
        "host must be loopback: {rendered}"
    );
    let endpoint = rendered.split('=').nth(1).expect("scheme=value mapping");
    let parsed_port: u16 = endpoint
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .expect("rendered port must be numeric");
    assert_eq!(parsed_port, port, "rendered: {rendered}");
}

/// 直连规则：出口指向必然连不上的 `127.0.0.1:1`，仍能打通 echo ⇒ 未走隧道。
#[tokio::test(flavor = "current_thread")]
async fn direct_rule_bypasses_tunnel() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let (echo_port, echo_bytes) = spawn_echo().await;
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (proxy_addr, runtime_task) =
            start_runtime(config(DIRECT_LOOPBACK, dead, PASSWORD)).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);

        let (mut client, reply) = socks_connect(proxy_addr, &target, b"direct").await;
        assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT must be accepted");
        let mut got = [0u8; 6];
        timed(client.read_exact(&mut got)).await.unwrap();
        assert_eq!(
            &got, b"direct",
            "direct path must reach echo without the tunnel"
        );
        assert_eq!(echo_bytes.load(Ordering::SeqCst), 6);

        runtime_task.abort();
        let _ = runtime_task.await;
    }))
    .await;
}

/// 口令不匹配：必须 fail-closed —— 收到失败应答或被关闭，且 echo 收不到任何字节。
#[tokio::test(flavor = "current_thread")]
async fn wrong_password_fails_closed() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let (echo_port, echo_bytes) = spawn_echo().await;
        let (relay_addr, relay_handle) = start_relay(PASSWORD).await;
        let (proxy_addr, runtime_task) =
            start_runtime(config(PROXY_LOOPBACK, relay_addr, WRONG_PASSWORD)).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);

        let (mut client, reply) = socks_connect(proxy_addr, &target, b"should-not-leak").await;
        // 入站已在拨号前回过 0x00；此后的失败只能体现为显式 REP 或连接关闭。
        if reply[1] == 0x00 {
            let mut buf = [0u8; 1];
            let n = timed(client.read(&mut buf)).await.unwrap();
            assert_eq!(n, 0, "wrong-password tunnel must close without data");
        } else {
            assert!(
                matches!(reply[1], 0x01 | 0x05),
                "unexpected SOCKS5 REP {}",
                reply[1]
            );
        }
        // 防「失败却回退直连」：echo 不能收到任何业务字节。
        assert_eq!(
            echo_bytes.load(Ordering::SeqCst),
            0,
            "echo server must never see bytes on a failed tunnel"
        );

        runtime_task.abort();
        let _ = runtime_task.await;
        timed(relay_handle.shutdown()).await.unwrap();
    }))
    .await;
}

/// 收尾干净：shutdown / 中止后两个监听端口都应拒绝新连接。
#[tokio::test(flavor = "current_thread")]
async fn shutdown_releases_port() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let (relay_addr, relay_handle) = start_relay(PASSWORD).await;
        let (proxy_addr, runtime_task) =
            start_runtime(config(PROXY_LOOPBACK, relay_addr, PASSWORD)).await;

        // `run()` 没有返回路径，abort 即 drop 持有监听器的 future。
        timed(relay_handle.shutdown()).await.unwrap();
        runtime_task.abort();
        let _ = runtime_task.await;

        assert!(
            timed(TcpStream::connect(relay_addr)).await.is_err(),
            "relay port must be released"
        );
        assert!(
            timed(TcpStream::connect(proxy_addr)).await.is_err(),
            "runtime port must be released"
        );
    }))
    .await;
}
