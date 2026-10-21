//! Hysteria 异常矩阵补缺：半关闭（half-close）与清理（cleanup）。
//!
//! 对应 `docs/audit-all1.md` §3 异常路径矩阵里 Hysteria 的两格：
//! - 「半关闭 ❌」→ `lifecycle/half_close.rs`（A 组）；
//! - 「清理 ❌」→ `lifecycle/cleanup.rs`（B 组）。
//!
//! 全部用例都是**本仓客户端 ↔ 本仓服务端**的闭环（范式照
//! `tests/rust_roundtrip.rs`）：服务端 `HysteriaServer::bind` + `accept_loop`
//! （ALPN=h3、openssl 现场自签证书进临时目录），客户端 `HysteriaClient`。
//! 这**不冒充**与官方 Xray 的互通（真实互通见 `tests/xray_hysteria*.rs`，
//! `#[ignore]`）；本卡验的是生命周期语义，不是互通。
//!
//! # 观测手段（用既有可观测点，不自造 API）
//!
//! | 观测点 | 含义 | 可观测的语义 |
//! |---|---|---|
//! | `Server::open_connections()` | `quinn::Endpoint::open_connections` | 服务端端点上的 QUIC 连接数（服务端**连接级**会话表计数） |
//! | `client.open_udp()` 的结果 | `quic/client.rs` `UdpManager.closed` | 客户端 UDP 会话表是否已被 `close_all()` **清空并关闭** |
//! | `UdpSession::recv_raw()` → `None` | 客户端 `UdpManager.sessions` 条目被丢弃 | 客户端会话表条目归零 |
//! | 目标端观察到的 UDP 源端口 | 服务端 `quic/server.rs` `UdpManager::sessions` 条目被移除后重建 | 服务端 **UDP 会话表**按条目回收（换端口=换出站 socket） |
//! | 目标 TCP 读到 EOF | 服务端 `proxy::relay` 收尾、出站 socket 释放 | 服务端 **TCP 承载**已回收 |
//! | 目标 TCP 的接入次数 | 服务端 `proxy::serve_tcp_stream_paced` | 服务端**是否**为该请求建立了出站连接（畸形帧不得放行） |
//!
//! 服务端 UDP 会话表（`quic::server::UdpManager::sessions`）是 `pub(crate)`，
//! 集成测试**读不到条目数**（客户端那份 `UdpManager.sessions` 是私有的）；
//! 故用上表**外部可观测等价物**替代，
//! 不改 `src/**`（本卡是纯测试卡）。
//!
//! 凭据/口令一律运行时生成，不落日志；回环地址 + 临时端口；
//! 每个网络操作都有 `tokio::time::timeout`；等待回收一律「轮询 + 总截止」，
//! **禁止**固定 sleep 后直接断言。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig};
use lengsuo_hysteria::quic::{ClientConfig, ConnectError, HysteriaClient};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

// 子目录模块（`tests/lifecycle/`）：crate root 是 `tests/lifecycle.rs`，
// 裸 `mod cleanup;` 会去找 `tests/cleanup.rs`，故用 `#[path]` 显式指到
// `tests/lifecycle/cleanup.rs`。
#[path = "lifecycle/cleanup.rs"]
mod cleanup;
#[path = "lifecycle/half_close.rs"]
mod half_close;

/// 单次网络操作的上限（所有 IO 都要套 `tokio::time::timeout`）。
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// 轮询等待「会话被回收」的总截止时间（不是单次 sleep）。
pub(crate) const RECLAIM_DEADLINE: Duration = Duration::from_secs(25);
/// 轮询间隔（只出现在轮询循环里，不用于「睡够就断言」）。
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// TLS 校验名（自签证书的 SAN 含 `DNS:localhost`）。
const SERVER_NAME: &str = "localhost";
/// 参考实现的 `closeErrCodeOK`（`transport/internet/hysteria/config.go`：
/// `0x100` = HTTP3 ErrCodeNoError）。
pub(crate) const CLOSE_ERR_CODE_OK: u32 = 0x100;

/// 运行时生成的假口令：每条用例一份，不写死、不进日志。
fn fake_auth(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("lengsuo-lifecycle-{tag}-{}-{nanos}", std::process::id())
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hy-lc-{}-{}", tag, std::process::id()));
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

/// 确定性伪随机载荷（逐字节比对用）。
pub(crate) fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// 已绑定的本仓服务端。
pub(crate) struct Server {
    pub(crate) addr: SocketAddr,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) auth: String,
    /// 临时目录（证书落盘处）；保留引用以便调试时定位。
    #[allow(dead_code)]
    pub(crate) dir: PathBuf,
    pub(crate) inner: Arc<HysteriaServer>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        // accept_loop 会在 endpoint 关闭后退出；不强杀。
    }
}

impl Server {
    /// 服务端端点上的 QUIC 连接数（服务端**连接级**会话表计数）。
    pub(crate) fn open_connections(&self) -> usize {
        self.inner.endpoint().open_connections()
    }

    /// 服务端主动关闭整个端点（对齐参考 `Listener.Close()`：关 listener +
    /// 关 pktConn ⇒ 所有连接随之关闭）。
    pub(crate) fn close(&self) {
        self.inner.close();
    }
}

/// 起一个本仓服务端（UDP 端口由系统分配）+ 返回（地址、证书 DER 与保活的
/// accept 任务句柄）。`udp_idle_timeout_secs` 控制服务端 UDP 会话的空闲
/// 回收阈值（回收动作由 `quic::server::UDP_IDLE_CLEANUP_INTERVAL_SECS`
/// 的 ticker 驱动）。
pub(crate) async fn start_server(tag: &str, udp_idle_timeout_secs: u64) -> Server {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let key_der = key_der(&key);
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let auth = fake_auth(tag);
    let config = ServerConfig {
        listen_addr: listen,
        cert_chain_der: vec![der.clone()],
        key_der,
        auth: auth.clone(),
        brutal_down: 0,
        brutal_up: 0,
        udp_enabled: true,
        udp_idle_timeout_secs,
        congestion: String::new(),
    };
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let addr = server.local_addr().expect("读取监听地址");
    let srv = Arc::clone(&server);
    let task = tokio::spawn(async move { srv.accept_loop().await });
    Server {
        addr,
        cert_der: der,
        auth,
        dir,
        inner: server,
        task,
    }
}

pub(crate) fn client_config(server: &Server, auth: &str) -> ClientConfig {
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

pub(crate) async fn connect_with(
    server: &Server,
    auth: &str,
) -> Result<HysteriaClient, ConnectError> {
    HysteriaClient::connect(client_config(server, auth)).await
}

/// 轮询等待条件成立：每次尝试都有单次上限，总时长不超过 `deadline`。
///
/// 禁止「固定 sleep 后直接断言」：这里每次尝试都套 `timeout`，
/// 条件不成立就等到总截止时间。
pub(crate) async fn wait_until<F, Fut>(deadline: Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        match tokio::time::timeout(left.min(IO_TIMEOUT), cond()).await {
            Ok(true) => return true,
            Ok(false) => {}
            Err(_) => return false,
        }
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        tokio::time::sleep(left.min(POLL_INTERVAL)).await;
    }
}

// ===========================================================================
// 本地目标（TCP / UDP）
// ===========================================================================

/// 本地 TCP 目标的事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetEvent {
    /// 读到了一批字节。
    Read(usize),
    /// 读端收到 EOF（对端半关闭了写端）。
    Eof,
    /// 目标已关闭自己的写端（半关闭）。
    WriteClosed,
}

/// 本地 TCP 目标的脚本。
#[derive(Debug, Clone)]
pub(crate) enum TargetScript {
    /// 读到 EOF 后才回写 `reply`，随后关闭写端。
    /// ⇒ 用来验「客户端半关闭写端后，读方向仍然可继续收」。
    ReplyAfterEof(Vec<u8>),
    /// 读到第一批数据后：先回写 `reply`，再**半关闭写端**
    /// （`shutdown(Write)`），但继续读。
    /// ⇒ 用来验「对端半关闭的对称性」：客户端应先读到数据、再读到
    /// **干净 EOF**（`Ok(0)`），而不是读错误。
    ReplyThenHalfClose(Vec<u8>),
    /// 读到第一批数据后立刻回写 `reply`，随后读到 EOF 再关闭。
    ReplyThenDrain(Vec<u8>),
    /// 读到第一批数据后立刻**整条关闭**（读端 + 写端）。
    /// ⇒ 用来让服务端的出站连接及时收尾（否则承载任务会一直挂着）。
    CloseAfterFirstRead,
    /// 只读不写、**永不主动关闭**（读到 EOF 才结束）。
    /// ⇒ 用来观察「对端异常断开时，服务端的出站连接是否被释放」。
    KeepOpen,
}

/// 本地 TCP 目标（服务端直连出站的对象）。
pub(crate) struct TcpTarget {
    pub(crate) addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    accepts: Arc<AtomicUsize>,
    events: mpsc::UnboundedReceiver<TargetEvent>,
}

impl TcpTarget {
    /// 目标已从客户端读到的全部字节。
    pub(crate) fn received(&self) -> Vec<u8> {
        self.received.lock().expect("目标缓冲锁中毒").clone()
    }

    /// 目标被**接入**的连接数（服务端出站 TCP 连接的条数）。
    ///
    /// 用来区分「服务端把残帧当干净 EOF 放行」（会建立出站连接）与
    /// 「服务端把残帧当协议错误拒绝」（不建立任何出站连接）。
    pub(crate) fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// 等到出现满足 `pred` 的事件（带上限）。
    pub(crate) async fn wait_event(&mut self, pred: impl Fn(TargetEvent) -> bool) -> bool {
        tokio::time::timeout(IO_TIMEOUT, async {
            while let Some(ev) = self.events.recv().await {
                if pred(ev) {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false)
    }
}

/// 起一个本地 TCP 目标。
pub(crate) async fn spawn_tcp_target(script: TargetScript) -> TcpTarget {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定本地 TCP 目标");
    let addr = listener.local_addr().expect("目标地址");
    let received = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::unbounded_channel();
    let sink = Arc::clone(&received);
    let counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        counter.fetch_add(1, Ordering::SeqCst);
        let _ = sock.set_nodelay(true);
        let mut buf = [0u8; 16 * 1024];
        let mut replied = false;
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => {
                    let _ = tx.send(TargetEvent::Eof);
                    break;
                }
                Ok(n) => {
                    sink.lock()
                        .expect("目标缓冲锁中毒")
                        .extend_from_slice(&buf[..n]);
                    let _ = tx.send(TargetEvent::Read(n));
                    match &script {
                        TargetScript::ReplyAfterEof(_) => {}
                        TargetScript::ReplyThenHalfClose(reply) => {
                            if !replied {
                                replied = true;
                                let _ = sock.write_all(reply).await;
                                let _ = sock.flush().await;
                                // 半关闭写端：读方向保持打开。
                                let _ = sock.shutdown().await;
                                let _ = tx.send(TargetEvent::WriteClosed);
                            }
                        }
                        TargetScript::ReplyThenDrain(reply) => {
                            if !replied {
                                replied = true;
                                let _ = sock.write_all(reply).await;
                            }
                        }
                        TargetScript::CloseAfterFirstRead => {
                            break;
                        }
                        TargetScript::KeepOpen => {}
                    }
                }
                Err(_) => break,
            }
        }
        if let TargetScript::ReplyAfterEof(reply) = &script {
            let _ = sock.write_all(reply).await;
            let _ = sock.flush().await;
        }
        let _ = sock.shutdown().await;
    });
    TcpTarget {
        addr,
        received,
        accepts,
        events: rx,
    }
}

/// 一条被本地 UDP 目标收到的数据报：**源地址**（服务端出站 socket 的源
/// 端口 ⇒ 服务端 UDP 会话条目的身份）+ 载荷。
pub(crate) type UdpPacket = (SocketAddr, Vec<u8>);

/// 本地 UDP 目标：记录每个数据报的**源地址**（服务端出站 socket 的源端口
/// ⇒ 服务端 UDP 会话条目的身份）与载荷，并原样回送。
pub(crate) struct UdpTarget {
    pub(crate) addr: SocketAddr,
    packets: Arc<Mutex<Vec<UdpPacket>>>,
}

impl UdpTarget {
    /// 已收到的所有数据报（源地址 + 载荷）。
    pub(crate) fn packets(&self) -> Vec<UdpPacket> {
        self.packets.lock().expect("UDP 目标锁中毒").clone()
    }
}

/// 起一个本地 UDP 回送目标。
pub(crate) async fn spawn_udp_target() -> UdpTarget {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("绑定本地 UDP 目标");
    let addr = sock.local_addr().expect("UDP 目标地址");
    let packets = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&packets);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            sink.lock()
                .expect("UDP 目标锁中毒")
                .push((from, buf[..n].to_vec()));
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    UdpTarget { addr, packets }
}

// ===========================================================================
// 读方向的结果分类
// ===========================================================================

/// 读方向的结果（区分「干净 EOF」与「协议错误」——任务书点名的关键坑）。
#[derive(Debug)]
pub(crate) enum ReadOutcome {
    /// 读到了 EOF 且**缓冲已空** = 干净 EOF（对齐参考 `common/buf/copy.go`
    /// 的 `Copy` 遇 `io.EOF` 正常返回 nil）。
    CleanEof {
        /// EOF 之前读到的字节。
        data: Vec<u8>,
    },
    /// 读到了 EOF 但**缓冲里还有残留字节** = 协议错误（残帧被当成了
    /// 干净 EOF 放行）。
    EofWithResidue {
        /// EOF 之前读到的字节。
        data: Vec<u8>,
    },
    /// 读方向报错（`Err(UnexpectedEof)` / `Err(Reset)` / `Err(ConnectionLost)`）。
    ReadError {
        /// 报错前读到的字节。
        #[allow(dead_code)]
        data: Vec<u8>,
        /// 错误文本（不含任何机密）。
        err: String,
    },
}

/// 读到底并分类结果。
///
/// 语义（**必须**区分两种 EOF）：
/// - EOF 且缓冲空 ⇒ [`ReadOutcome::CleanEof`]；
/// - EOF 且缓冲里还有字节 ⇒ [`ReadOutcome::EofWithResidue`]（协议错误）。
pub(crate) async fn read_to_eof(mut recv: quinn::RecvStream) -> ReadOutcome {
    let mut data: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match recv.read(&mut buf).await {
            Ok(None) => {
                return if data.is_empty() {
                    ReadOutcome::CleanEof { data }
                } else {
                    ReadOutcome::EofWithResidue { data }
                };
            }
            Ok(Some(n)) => data.extend_from_slice(&buf[..n]),
            Err(e) => {
                return ReadOutcome::ReadError {
                    data,
                    err: e.to_string(),
                };
            }
        }
    }
}

/// 读到底并分类结果（**应用层**，走 `proxy::TcpProxyStream`）。
///
/// 与 [`read_to_eof`] 同口径：EOF 且缓冲空 = 干净 EOF；EOF 且缓冲里有
/// 残留 = 协议错误；读报错 = 读错误。
pub(crate) async fn read_proxy_to_eof(stream: &mut proxy::TcpProxyStream) -> ReadOutcome {
    let mut data: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                return if data.is_empty() {
                    ReadOutcome::CleanEof { data }
                } else {
                    ReadOutcome::EofWithResidue { data }
                };
            }
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e) => {
                return ReadOutcome::ReadError {
                    data,
                    err: e.to_string(),
                };
            }
        }
    }
}

// ===========================================================================
// 会话普查
// ===========================================================================

/// 客户端 UDP 会话表的状态（观测 `quic/client.rs` 的 `UdpManager`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientUdpTable {
    /// 表仍开着（可以开新会话）。
    Open,
    /// 表已被 `close_all()` **清空并关闭**（连接已死）。
    Closed,
    /// 服务端未启用 UDP datagram。
    Unsupported,
}

/// 采集客户端 UDP 会话表状态。
///
/// `open_udp()` 是**非破坏性**探针：表被 `close_all()` 清空后必然返回
/// `Err(Quic(LocallyClosed))`，而 `close_all()` 同时置 `closed = true` ⇒
/// 「已关闭」蕴含「表已清空」。
pub(crate) async fn client_udp_table(client: &HysteriaClient) -> ClientUdpTable {
    match tokio::time::timeout(IO_TIMEOUT, client.open_udp()).await {
        Err(_) => ClientUdpTable::Unsupported,
        Ok(Ok(_)) => ClientUdpTable::Open,
        Ok(Err(ConnectError::UdpUnsupported)) => ClientUdpTable::Unsupported,
        Ok(Err(ConnectError::Quic(_))) => ClientUdpTable::Closed,
        Ok(Err(_)) => ClientUdpTable::Closed,
    }
}
