//! AnyTLS 异常矩阵补缺：重放（replay）与半关闭（half-close）。
//!
//! 覆盖 `docs/audit-all1.md` §3 异常路径矩阵里 AnyTLS 的两格空缺：
//! - 「重放」格：逐条判定**本仓**与**参考 anytls-go** 各自是否防护；
//! - 「半关闭」格：单向半关闭、对称性（干净 EOF 与残留半帧必须区分）、
//!   以及半关闭后同连接继续用。
//!
//! 夹具照抄 `tests/server_roundtrip.rs`（`start`/`send`/`recv`/`expect`/`finish`/
//! `settings`/`push_with_target`），不改动原文件；回环地址、临时端口与假凭据
//! 全部运行时生成，日志与断言不出现口令。
//!
//! 参考实现（anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50）：
//! - `proxy/session/session.go::recvLoop`：帧分发与各命令的边界处理；
//! - `proxy/session/frame.go`：帧头（cmd/sid/len）定义。
//!
//! 逐条结论、参考行号与「本仓防护 vs 验证了参考也不防护」的判定见
//! `docs/anytls-status.md` 的「异常矩阵补缺（重放 / 半关闭）」。
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    padding::PaddingScheme,
    server::{self, ServerConfig},
    Error,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[path = "lifecycle/client.rs"]
mod client;
#[path = "lifecycle/half_close.rs"]
mod half_close;
#[path = "lifecycle/interop.rs"]
mod interop;
#[path = "lifecycle/replay.rs"]
mod replay;
// 官方 server 互通的复用件（只读引用，不改动这些文件）：
// `interop/support.rs`（参考二进制定位与进程管理）、`interop_client/tls.rs`
// （pin + 证书链 + 名称校验的 TLS 客户端）、`interop_client/harness.rs`
// （spawn 官方 server 并现取其自签叶子）。
#[path = "interop_client/harness.rs"]
mod interop_harness;
#[path = "interop/support.rs"]
mod support;
#[path = "interop_client/tls.rs"]
mod tls;

/// 单次网络操作的等待上限。
pub const WAIT: Duration = Duration::from_secs(2);
/// 整条会话的等待上限。
pub const TOTAL: Duration = Duration::from_secs(10);
/// 测试口令：仅本模块内部使用，不出现在任何日志或断言文本里。
pub const PASSWORD: &[u8] = b"lifecycle-fixture-password";

/// 在 `duplex` 管道的服务端半上跑会话，客户端半交回调用方。
pub struct Harness {
    client: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<Result<server::SessionStats, Error>>,
}

impl Harness {
    /// 建连接并完成认证（客户端侧）。
    pub async fn start(password: &[u8]) -> Self {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = ServerConfig::new(password, WAIT);
        let task = tokio::spawn(server::serve(server_side, config));
        let mut harness = Self { client, task };
        Credential::new(password)
            .send(&mut harness.client, b"", WAIT)
            .await
            .expect("认证发送");
        harness
    }

    /// 写一帧。
    pub async fn send(&mut self, frame: Frame) {
        frame.write(&mut self.client, WAIT).await.expect("写帧");
    }

    /// 直接写出已编码的帧字节（用于「逐字节重放」与「跨会话重放」）。
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        timeout(WAIT, async {
            self.client.write_all(bytes).await.expect("写原始字节");
            self.client.flush().await.expect("刷新");
        })
        .await
        .expect("写原始字节超时");
    }

    /// 读一帧（跳过 Waste 填充帧）；出错时返回错误而不 panic。
    pub async fn try_recv(&mut self) -> Result<Frame, Error> {
        loop {
            let frame = Frame::read(&mut self.client, u16::MAX, WAIT).await?;
            if frame.command != Command::Waste {
                return Ok(frame);
            }
        }
    }

    /// 读一帧（跳过 Waste 填充帧）。
    pub async fn recv(&mut self) -> Frame {
        self.try_recv().await.expect("读帧")
    }

    /// 读一帧并断言命令；返回帧。
    pub async fn expect(&mut self, command: Command) -> Frame {
        let frame = self.recv().await;
        assert_eq!(
            frame.command,
            command,
            "帧命令不符：期望 {command:?}，实际 {:?}（sid={}, len={}）",
            frame.command,
            frame.stream_id,
            frame.data.len()
        );
        frame
    }

    /// 杀掉客户端半，让服务端读到 EOF，返回会话统计。
    pub async fn finish(self) -> Result<server::SessionStats, Error> {
        drop(self.client);
        timeout(TOTAL, self.task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic")
    }
}

/// 客户端 Settings 帧：本模块的 `ServerState` 要求 v + client + padding-md5。
pub fn settings(padding_md5: &str) -> Frame {
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: format!("v=2\nclient=lengsuo-test\npadding-md5={padding_md5}").into_bytes(),
    }
}

/// 默认 padding 方案的 md5（与本仓服务端同方案 ⇒ 服务端不下发 UpdatePadding）。
pub fn default_md5() -> String {
    PaddingScheme::default_scheme().md5().to_owned()
}

/// 目标地址 + 载荷拼成首帧 PUSH（参考：地址是 SOCKS5 格式）。
pub fn push_with_target(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        panic!("测试固定 IPv4 回环");
    };
    let mut data = vec![0x01];
    data.extend_from_slice(&v4.octets());
    data.extend_from_slice(&addr.port().to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// 可观测的回环目标：记录收到的全部字节、连接次数与「读侧是否见到 EOF」，
/// 并可在读侧 EOF 之后回送尾数据（用于证明写侧仍可用 = 半关闭语义）。
pub struct Target {
    /// 目标地址（供首帧 PUSH 携带）。
    pub addr: SocketAddr,
    /// 接受的连接数：用于断言「流只被打开一次」。
    pub accepted: AtomicUsize,
    /// 收到的全部字节。
    received: Mutex<Vec<u8>>,
    /// 读侧是否已读到 EOF（对端半关闭写端的证据）。
    pub eof_seen: AtomicBool,
    /// 读侧 EOF 之后回送的尾数据。
    tail: Vec<u8>,
    /// 回显一次后立即关闭（对端先关的场景）。
    close_after_echo: bool,
}

impl Target {
    /// 目标收到的全部字节。
    pub fn received(&self) -> Vec<u8> {
        self.received.lock().expect("目标缓冲锁").clone()
    }

    /// 目标收到的字节里，`needle` 出现的次数（重放是否被再次转发的判据）。
    pub fn occurrences(&self, needle: &[u8]) -> usize {
        occurrences(&self.received(), needle)
    }
}

/// 统计 `haystack` 里 `needle` 出现次数（不重叠计数）。
pub fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut count = 0;
    let mut start = 0;
    while let Some(offset) = haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        count += 1;
        start += offset + needle.len();
    }
    count
}

/// 启动可观测的回环目标。
///
/// - `tail`：读侧 EOF 之后回送的尾数据（写侧仍可用 = 半关闭语义）；
/// - `close_after_echo`：回显一次后**立即关闭**（对端先关的场景），
///   否则一直读到 EOF 再回送 `tail`。
pub async fn spawn_target(tail: &[u8], close_after_echo: bool) -> Arc<Target> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("target 监听");
    let addr = listener.local_addr().expect("target 地址");
    let target = Arc::new(Target {
        addr,
        accepted: AtomicUsize::new(0),
        received: Mutex::new(Vec::new()),
        eof_seen: AtomicBool::new(false),
        tail: tail.to_vec(),
        close_after_echo,
    });
    let handle = Arc::clone(&target);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            handle.accepted.fetch_add(1, Ordering::SeqCst);
            let handle = Arc::clone(&handle);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let mut echoed = false;
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            handle
                                .received
                                .lock()
                                .expect("目标缓冲锁")
                                .extend_from_slice(&buffer[..count]);
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                            echoed = true;
                            if handle.close_after_echo {
                                // 对端先关：回显后立即关闭写侧。
                                break;
                            }
                        }
                    }
                }
                // 读侧 EOF：写侧仍可用（半关闭语义），回送尾数据。
                handle.eof_seen.store(true, Ordering::SeqCst);
                if !handle.close_after_echo && !handle.tail.is_empty() {
                    let _ = socket.write_all(&handle.tail).await;
                    let _ = socket.flush().await;
                }
                let _ = echoed;
            });
        }
    });
    target
}

/// 会话结局：干净收尾 or fail-closed（供「截断 vs 干净 EOF」判定）。
#[derive(Debug, Clone)]
pub enum SessionOutcome {
    /// 干净收尾（对端正常关闭，或 EOF 时缓冲为空）。
    Clean { streams_opened: usize },
    /// fail-closed：协议违规或传输错误。
    Failed {
        /// 错误描述（不含口令与载荷）。
        reason: String,
        /// 传输错误的 kind（协议错误为 `None`）。
        io_kind: Option<std::io::ErrorKind>,
    },
}

/// 已启动的本仓服务端：监听地址 + 各连接的会话结局。
pub struct RustServer {
    /// 监听地址。
    pub addr: SocketAddr,
    /// 每个已结束连接的会话结局。
    outcomes: Arc<Mutex<Vec<SessionOutcome>>>,
}

impl RustServer {
    /// 已结束的连接数。
    pub fn finished(&self) -> usize {
        self.outcomes.lock().expect("结局锁").len()
    }

    /// 第 `index` 个连接的结局（`None` = 该连接尚未结束）。
    pub fn outcome(&self, index: usize) -> Option<SessionOutcome> {
        self.outcomes.lock().expect("结局锁").get(index).cloned()
    }
}

/// 启动本仓 AnyTLS 服务端（真实 TCP），返回监听地址与会话结局收集器。
pub async fn spawn_rust_server(password: &[u8]) -> RustServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听");
    let addr = listener.local_addr().expect("地址");
    let outcomes: Arc<Mutex<Vec<SessionOutcome>>> = Arc::new(Mutex::new(Vec::new()));
    let collected = Arc::clone(&outcomes);
    let password = password.to_vec();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let password = password.clone();
            let collected = Arc::clone(&collected);
            tokio::spawn(async move {
                let outcome = match server::serve(socket, ServerConfig::new(&password, WAIT)).await
                {
                    Ok(stats) => SessionOutcome::Clean {
                        streams_opened: stats.streams_opened,
                    },
                    Err(err) => SessionOutcome::Failed {
                        reason: err.to_string(),
                        io_kind: match &err {
                            Error::Io(io) => Some(io.kind()),
                            _ => None,
                        },
                    },
                };
                collected.lock().expect("结局锁").push(outcome);
            });
        }
    });
    RustServer { addr, outcomes }
}

/// 帧读取器的 EOF 判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eof {
    /// 缓冲为空时读到 EOF = 干净 EOF（0 字节）。
    Clean,
    /// EOF 时仍有残留半帧 = 协议错误（截断）。
    Truncated(usize),
}

/// 带缓冲的帧读取器：**EOF 判定区分「缓冲空」与「残留半帧」**。
///
/// 这是 `docs/audit-all1.md` §3「半关闭」格的坑：把两者混为一谈会把截断
/// 误判成干净 EOF。残留字节数即被截断的帧长度。
pub struct FrameReader {
    buffer: Vec<u8>,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// 缓冲里若已有完整帧则取出；`None` 表示需要更多字节。
    pub fn take(&mut self) -> Result<Option<Frame>, Error> {
        match Frame::decode(&self.buffer) {
            Ok((frame, used)) => {
                self.buffer.drain(..used);
                Ok(Some(frame))
            }
            Err(Error::Incomplete) => Ok(None),
            Err(other) => Err(other),
        }
    }

    /// 读一批字节进缓冲；`Some(eof)` 表示传输层 EOF（此时判定干净/截断）。
    pub async fn fill(&mut self, stream: &mut TcpStream) -> Result<Option<Eof>, String> {
        let mut chunk = [0u8; 4096];
        let read = timeout(WAIT, stream.read(&mut chunk))
            .await
            .map_err(|_| "读超时".to_owned())?
            .map_err(|err| format!("读失败：{err}"))?;
        if read == 0 {
            return Ok(Some(if self.buffer.is_empty() {
                Eof::Clean
            } else {
                Eof::Truncated(self.buffer.len())
            }));
        }
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(None)
    }
}
