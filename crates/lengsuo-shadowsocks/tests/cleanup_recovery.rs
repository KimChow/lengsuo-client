//! Shadowsocks TCP 中继「清理/资源回收」具名用例（仅回环、假口令、临时端口）。
//!
//! 对齐固定参考（Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，
//! `proxy/shadowsocks/server.go` `handleConnection`）：任一方向结束/出错即中断另一方向
//! 并回收连接；服务停止时监听器关闭、在途连接全部结束。
//!
//! 观测面照抄 `crates/lengsuo-wireguard/tests/half_close_matrix/fixture.rs` 的
//! `open_fd_count()`（`/proc/self/fd`）与 `thread_count()`（`/proc/self/task`），读数窗口
//!（独占锁 + 同构基线 + 有界回落轮询）复制自该做法，不改任何共享文件；无 `/proc`
//! 的平台如实打印「无法断言」而不伪造通过。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use lengsuo_shadowsocks::{
    CipherSuite, RelayConfig, RelayConfigParts, RelayHandle, RelayService, TargetAddr, TcpReader,
    TcpWriter,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PASSWORD: &str = "ss-cleanup-recovery-fake-passw0rd";
const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
const WAIT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const FD_SLACK: usize = 1;
const THREAD_SLACK: usize = 1;
const RECLAIM_WINDOW: Duration = Duration::from_secs(3);
const SETTLE_WINDOW: Duration = Duration::from_millis(1000);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

// ---------- 观测面（照抄 wireguard fixture.rs） ----------

fn open_fd_count() -> Option<usize> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    let mut count = 0usize;
    for entry in entries.flatten() {
        let _ = entry;
        count += 1;
    }
    Some(count)
}

fn thread_count() -> Option<usize> {
    let entries = std::fs::read_dir("/proc/self/task").ok()?;
    let mut count = 0usize;
    for entry in entries.flatten() {
        let _ = entry;
        count += 1;
    }
    Some(count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resources {
    fds: usize,
    threads: usize,
}

impl Resources {
    fn snapshot() -> Option<Self> {
        Some(Self {
            fds: open_fd_count()?,
            threads: thread_count()?,
        })
    }
}

static SERIAL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn serial_guard() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL_LOCK.blocking_lock()
}

async fn baseline() -> Option<Resources> {
    let deadline = tokio::time::Instant::now() + SETTLE_WINDOW;
    let mut threads = thread_count()?;
    let mut last = Resources {
        fds: open_fd_count()?,
        threads,
    };
    let mut stable = 0usize;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let now = Resources::snapshot()?;
        threads = threads.max(now.threads);
        stable = if now == last { stable + 1 } else { 0 };
        last = now;
        if stable >= 3 || tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    Some(Resources {
        fds: last.fds,
        threads,
    })
}

async fn wait_for_reclaim(base: Resources) -> Option<Resources> {
    let deadline = tokio::time::Instant::now() + RECLAIM_WINDOW;
    loop {
        let now = Resources::snapshot()?;
        let ok = now.fds <= base.fds + FD_SLACK && now.threads <= base.threads + THREAD_SLACK;
        if ok || tokio::time::Instant::now() >= deadline {
            return Some(now);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ---------- 夹具 ----------

fn local_set() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

fn config() -> RelayConfig {
    RelayConfig::new(
        RelayConfigParts {
            suite: SUITE,
            idle_timeout: IDLE_TIMEOUT,
            replay: None,
        },
        PASSWORD.as_bytes(),
    )
}

async fn start_relay() -> (SocketAddr, RelayHandle) {
    let service = RelayService::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), config())
        .await
        .expect("中继绑定");
    let addr = service.local_addr().expect("中继地址");
    let handle = service.start().await.expect("中继启动");
    (addr, handle)
}

/// 回环目标：`echo=true` 原样回写，`echo=false` 只读不写（用于「关闭前不投递数据」）。
async fn spawn_target(echo: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target 地址");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if echo && stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                if echo {
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    addr
}

async fn roundtrip(relay: SocketAddr, target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    let mut request = Vec::new();
    target.encode_checked(&mut request).expect("目标可编码");
    request.extend_from_slice(payload);
    let mut writer =
        TcpWriter::new(&mut stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 超时")
        .expect("send 成功");
    timeout(WAIT, writer.shutdown())
        .await
        .expect("shutdown 超时")
        .expect("shutdown 成功");
    drop(writer);
    let (read_half, _write_half) = stream.split();
    let mut reader = TcpReader::new(read_half, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造读端");
    let mut got = Vec::new();
    for _ in 0..16 {
        match timeout(WAIT, reader.recv()).await.expect("recv 超时") {
            Ok(Some(chunk)) => got.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(err) => panic!("回程读取失败：{err}"),
        }
    }
    got
}

async fn open_session(relay: SocketAddr, target: &TargetAddr, payload: &[u8]) -> TcpStream {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    let mut request = Vec::new();
    target.encode_checked(&mut request).expect("目标可编码");
    request.extend_from_slice(payload);
    let mut writer =
        TcpWriter::new(&mut stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 超时")
        .expect("send 成功");
    drop(writer);
    stream
}

async fn roundtrip_then_reset(relay: SocketAddr, target: &TargetAddr, payload: &[u8]) {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    let mut request = Vec::new();
    target.encode_checked(&mut request).expect("目标可编码");
    request.extend_from_slice(payload);
    {
        let mut writer =
            TcpWriter::new(&mut stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造写端");
        timeout(WAIT, writer.send(&request))
            .await
            .expect("send 超时")
            .expect("send 成功");
        drop(writer);
    }
    {
        let mut reader =
            TcpReader::new(&mut stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造读端");
        let mut got = Vec::new();
        while got.len() < payload.len() {
            match timeout(WAIT, reader.recv()).await.expect("recv 超时") {
                Ok(Some(chunk)) => got.extend_from_slice(&chunk),
                Ok(None) => panic!("RST 之前回程意外 EOF"),
                Err(err) => panic!("RST 之前回程读取失败：{err}"),
            }
        }
        assert!(
            got == payload,
            "RST 之前中继应已完整转发（收到 {} 字节）",
            got.len()
        );
    }
    stream.set_zero_linger().expect("SO_LINGER=0 应可设置");
    drop(stream);
}

async fn observe_after_clean_sessions() -> Option<(Resources, Resources)> {
    let echo = spawn_target(true).await;
    let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
    let base = baseline().await?;
    let (relay, handle) = start_relay().await;
    for index in 0..3u8 {
        let payload = format!("cleanup-recovery-{index}").into_bytes();
        let got = roundtrip(relay, &target, &payload).await;
        assert_eq!(got, payload, "第 {index} 条连接的回程应与载荷一致");
    }
    handle.shutdown().await.expect("中继应干净停止");
    let after = wait_for_reclaim(base).await?;
    Some((base, after))
}

// ---------- 具名用例 ----------

#[test]
fn fd_reclaimed_after_relay_shutdown() {
    let _guard = serial_guard();
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let Some((base, after)) = observe_after_clean_sessions().await else {
            eprintln!("本平台无 /proc/self/fd ⇒ fd 回收无法断言（不宣称通过）");
            return;
        };
        assert!(
            after.fds <= base.fds + FD_SLACK,
            "中继关闭后 fd 未回落到基线 {} + 抖动 {FD_SLACK}（收尾读数 {}，线程读数 {}）",
            base.fds,
            after.fds,
            after.threads
        );
    });
}

#[test]
fn thread_reclaimed_after_relay_shutdown() {
    let _guard = serial_guard();
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let Some((base, after)) = observe_after_clean_sessions().await else {
            eprintln!("本平台无 /proc/self/task ⇒ 线程回收无法断言（不宣称通过）");
            return;
        };
        assert!(
            after.threads <= base.threads + THREAD_SLACK,
            "中继关闭后线程数未回落到基线 {} + 抖动 {THREAD_SLACK}（收尾读数 {}，fd 读数 {}）",
            base.threads,
            after.threads,
            after.fds
        );
    });
}

#[test]
fn no_session_residue_after_relay_shutdown() {
    let _guard = serial_guard();
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let hold = spawn_target(false).await;
        let echo = spawn_target(true).await;
        let hold_target = TargetAddr::V4([127, 0, 0, 1], hold.port());
        let echo_target = TargetAddr::V4([127, 0, 0, 1], echo.port());
        let (relay, handle) = start_relay().await;

        let mut held = open_session(relay, &hold_target, b"held-session-payload").await;

        let got = roundtrip(relay, &echo_target, b"reconnect-payload").await;
        assert!(
            got == b"reconnect-payload",
            "同一端口重连应成功（收到 {} 字节）",
            got.len()
        );

        handle.shutdown().await.expect("中继应干净停止");
        let mut buf = [0u8; 64];
        match timeout(WAIT, held.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("旧会话在 relay 关闭后仍投递了 {n} 字节数据"),
            Err(_) => panic!("旧会话在 relay 关闭后未被回收（读等待超时）"),
        }
    });
}

#[test]
fn resources_reclaimed_after_peer_reset() {
    let _guard = serial_guard();
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let echo = spawn_target(true).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
        let Some(base) = baseline().await else {
            eprintln!("本平台无 /proc/self/fd 或 /proc/self/task ⇒ 资源回收无法断言（不宣称通过）");
            return;
        };

        let (relay, handle) = start_relay().await;
        for index in 0..3u8 {
            let payload = format!("reset-{index}").into_bytes();
            roundtrip_then_reset(relay, &target, &payload).await;
        }
        let got = roundtrip(relay, &target, b"after-reset").await;
        assert!(
            got == b"after-reset",
            "RST 后新会话应正常往返（收到 {} 字节）",
            got.len()
        );

        handle.shutdown().await.expect("中继应干净停止");
        let Some(after) = wait_for_reclaim(base).await else {
            eprintln!("读数中途失去观测点 ⇒ 资源回收无法断言（不宣称通过）");
            return;
        };
        assert!(
            after.fds <= base.fds + FD_SLACK,
            "RST 后 fd 未回落到基线 {} + 抖动 {FD_SLACK}（收尾读数 {}，线程读数 {}）",
            base.fds,
            after.fds,
            after.threads
        );
        assert!(
            after.threads <= base.threads + THREAD_SLACK,
            "RST 后线程数未回落到基线 {} + 抖动 {THREAD_SLACK}（收尾读数 {}，fd 读数 {}）",
            base.threads,
            after.threads,
            after.fds
        );
    });
}
