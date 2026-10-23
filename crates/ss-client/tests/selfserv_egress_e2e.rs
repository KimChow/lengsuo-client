//! 自研出口服务端**二进制**的回环端到端（Rust 客户端 ↔ Rust 服务端真子进程）。
//!
//! 与 `e2e_chain.rs`（进程内 `RelayService`）互补：本文件用 `std::process::Command`
//! 起真子进程（tokio 未启用 `process` feature 且共享 `Cargo.toml` 是禁区），从 stdout
//! 首行 `LISTEN <addr>` 取实际端口，证明**可部署二进制**真能互通、失败 fail-closed。
//! 链路：SOCKS5 入站 → 分流(proxy) → SS AEAD 隧道 → 子进程服务端 → echo → 原路返回。
//!
//! `Runtime::run` 持有 `!Send` 的 `Tunnel`、`RelayService::start` 用 `spawn_local`
//! ⇒ 涉及运行时的用例都在 `LocalSet` 里跑。

use std::future::Future;
use std::io::BufRead as _;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ss_client::config::{load_config_str, ClientConfig};
use ss_client::runtime::Runtime;
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, LocalSet};

/// bin 名带连字符，`CARGO_BIN_EXE_<name>` 原样写。
const BIN: &str = env!("CARGO_BIN_EXE_lengsuo-ss-relay-server");
const TIMEOUT: Duration = Duration::from_secs(10);
const METHOD: &str = "aes-256-gcm";
const PASSWORD: &str = "selfserv-e2e-password";
const WRONG_PASSWORD: &str = "selfserv-wrong-password";
const PAYLOAD: &[u8] = b"selfserv-payload";

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

/// 客户端配置：proxy 规则 + 指向给定 SS 服务端的出口。`connect_timeout_ms` 保证
/// 服务端宕机场景下拨号必失败返回（不悬挂）。
fn config(server: SocketAddr, password: &str) -> ClientConfig {
    load_config_str(&format!(
        "{PROXY_LOOPBACK}\n[outbound]\nss_url = \"ss://{METHOD}:{password}@{server}\"\n\
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

/// 起真实 `Runtime` 并后台跑 accept 循环。须在 `LocalSet` 内调用。
async fn start_runtime(config: ClientConfig) -> (SocketAddr, JoinHandle<()>) {
    let runtime = timed(Runtime::with_bind(config, "127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
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
/// 必须同批发送：`Dialer::connect` 要读到**首个认证回程 chunk** 才返回，而运行时只
/// 把 `residual` 作为隧道首批载荷转交（`src/outbound/dialer.rs` 的既有语义，见
/// `e2e_chain.rs` 同名函数注释）。
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

/// 真二进制子进程 + 已解析的监听地址；`Drop` 收尾 kill+wait，不留孤儿进程。
struct SelfServ {
    child: Child,
    addr: SocketAddr,
}

impl SelfServ {
    /// 起子进程（口令走环境变量，不进命令行）并等 stdout 首行 `LISTEN <addr>`
    /// （10s 内未出现 ⇒ panic，见 `timed`）。
    async fn start(password: &str) -> Self {
        let mut child = Command::new(BIN)
            .args(["--bind", "127.0.0.1:0", "--method", METHOD])
            .env("LENGSUO_SS_PASSWORD", password)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn lengsuo-ss-relay-server");
        let stdout = child.stdout.take().expect("stdout is piped");
        // 同步读首行必须挪出 async 执行器（current_thread 下会卡死整个测试）。
        let first = timed(async {
            tokio::task::spawn_blocking(move || {
                let mut line = String::new();
                std::io::BufReader::new(stdout)
                    .read_line(&mut line)
                    .expect("read child stdout must not fail");
                line
            })
            .await
            .expect("read LISTEN line task must not panic")
        })
        .await;
        let addr: SocketAddr = first
            .trim_end()
            .strip_prefix("LISTEN ")
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("unexpected first stdout line: {first:?}"));
        Self { child, addr }
    }

    /// 停止子进程（幂等）：kill + wait 回收，不留孤儿进程。
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for SelfServ {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 二进制真起来：10s 内打印 `LISTEN 127.0.0.1:<port>`，且该端口可 TCP 连通。
#[tokio::test(flavor = "current_thread")]
async fn selfserv_binary_listens_and_prints_addr() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let server = SelfServ::start(PASSWORD).await;
        assert!(server.addr.ip().is_loopback(), "addr: {}", server.addr);
        assert_ne!(server.addr.port(), 0, "ephemeral port must be resolved");
        let _probe = timed(TcpStream::connect(server.addr))
            .await
            .expect("listener must accept TCP connections");
    }))
    .await;
}

/// 主证据：经子进程二进制的隧道请求 echo，回程载荷**逐字节一致**，
/// 且 echo 端**收到 >0 字节**（非空转、非桩）。
#[tokio::test(flavor = "current_thread")]
async fn selfserv_roundtrip_payload_is_byte_identical() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let (echo_port, echo_bytes) = spawn_echo().await;
        let server = SelfServ::start(PASSWORD).await;
        let (proxy_addr, runtime_task) = start_runtime(config(server.addr, PASSWORD)).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);

        let (mut client, reply) = socks_connect(proxy_addr, &target, PAYLOAD).await;
        assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT must be accepted");

        let mut got = [0u8; PAYLOAD.len()];
        timed(client.read_exact(&mut got)).await.unwrap();
        assert_eq!(&got, PAYLOAD, "round-trip payload must be byte-identical");
        assert!(
            echo_bytes.load(Ordering::SeqCst) > 0,
            "echo server must have received bytes through the binary server"
        );

        runtime_task.abort();
        let _ = runtime_task.await;
    }))
    .await;
}

/// 错口令 ⇒ fail-closed：请求以显式失败收场（SOCKS5 REP 错误或连接被关，
/// 即 Runtime 侧的等价认证失败），且 echo 端**0 字节** —— 没有静默直连、
/// 没有静默回退 SS。
#[tokio::test(flavor = "current_thread")]
async fn selfserv_wrong_password_is_fail_closed_no_direct() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let (echo_port, echo_bytes) = spawn_echo().await;
        let server = SelfServ::start(PASSWORD).await;
        let (proxy_addr, runtime_task) = start_runtime(config(server.addr, WRONG_PASSWORD)).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);

        let (mut client, reply) = socks_connect(proxy_addr, &target, b"must-not-leak").await;
        // 入站已在拨号前回过 0x00；隧道认证失败只能体现为显式 REP 或连接关闭。
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
    }))
    .await;
}

/// 服务端进程死 ⇒ fail-closed：监听端口被释放、后续请求报错（不悬挂、不静默直连）。
#[tokio::test(flavor = "current_thread")]
async fn selfserv_down_is_fail_closed() {
    let local = LocalSet::new();
    timed(local.run_until(async {
        let (echo_port, echo_bytes) = spawn_echo().await;
        let mut server = SelfServ::start(PASSWORD).await;
        let (proxy_addr, runtime_task) = start_runtime(config(server.addr, PASSWORD)).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);

        // 模拟服务端宕机：kill + wait 后端口必须释放（无残留监听 fd）。
        server.stop();
        assert!(
            timed(TcpStream::connect(server.addr)).await.is_err(),
            "dead server must release its listening port"
        );

        // connect_timeout_ms=2s ⇒ 拨号失败必返回（不悬挂）；失败只能体现为显式
        // REP 或连接被关，绝不能正常读到数据（那说明静默直连了）。
        let (mut client, reply) = socks_connect(proxy_addr, &target, b"after-down").await;
        let failed = if reply[1] != 0x00 {
            true
        } else {
            let mut buf = [0u8; 1];
            timed(client.read(&mut buf)).await.unwrap() == 0
        };
        assert!(
            failed,
            "request must fail after the server is down, not succeed"
        );
        assert_eq!(
            echo_bytes.load(Ordering::SeqCst),
            0,
            "no silent direct fallback when the server is down"
        );

        runtime_task.abort();
        let _ = runtime_task.await;
    }))
    .await;
}
