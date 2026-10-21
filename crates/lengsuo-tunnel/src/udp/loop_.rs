//! 收发循环：**一个能收的循环**，带**明确的结束条件**。
//!
//! # 形态
//!
//! `async fn` + **channel**：`spawn_recv_loop` 起一个后台任务，把收到的帧
//! 通过 `mpsc` 交给上层。任务句柄 [`LoopHandle`] 暴露 `stop()`，
//! 上层可以**确定地**等它退出。
//!
//! # 结束条件（**没有一条是「永远挂着」**）
//!
//! | 结束条件 | [`LoopOutcome`] | 触发方式 |
//! |---|---|---|
//! | 上层取消 | `Cancelled` | [`Cancel::cancel()`] |
//! | 上层关掉事件通道 | `ChannelClosed` | 丢掉 `mpsc::Receiver` |
//! | socket 级错误 | `SocketError` | 对端不可达等（**上报**） |
//!
//! # 两级错误语义（本卡的核心）
//!
//! - **单包坏** ⇒ 发 [`UdpEvent::BadDatagram`]，**循环继续**。
//!   坏包不该杀掉整条链路——UDP 链路上乱序/垃圾/截断是常态。
//! - **连接坏** ⇒ 发 [`UdpEvent::SocketError`] 并**结束循环**。
//!   socket 都坏了，继续收也没有意义，必须让上层知道。
//!
//! ⛔ 循环里**没有** `loop { ... }` 之外的隐式挂死点：
//! 每一步都 `select!` 在「取消 / 通道关闭 / socket 可读」三者之间。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lengsuo_link_core::frame::{Frame, MAX_FRAME_LEN};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::error::{ErrorSeverity, UdpError};
use super::socket::UdpEndpoint;

/// 事件通道的**默认容量**。
///
/// 容量有限 ⇒ 上层消费慢时**背压**（`send` 会等），不会无界占内存。
pub const DEFAULT_RECV_QUEUE_CAPACITY: usize = 64;

/// 收循环收到的一个事件。
#[derive(Debug)]
pub enum UdpEvent {
    /// 收到一个**合法帧**。
    Frame(Frame),
    /// 收到一个**解不开的数据报**（**单包级**）：只丢这一包，循环**继续**。
    BadDatagram {
        /// 数据报来源地址。
        source: SocketAddr,
        /// 失败原因（帧层错误）。
        reason: lengsuo_link_core::frame::FrameError,
    },
    /// **socket 级错误**（**连接级**）：上报，循环随即结束。
    SocketError(UdpError),
}

impl UdpEvent {
    /// 事件的严重级别。**合法帧不是错误** ⇒ 返回 `None`。
    ///
    /// 让上层**不必匹配变体**就能判两级：
    /// 坏数据报是 [`ErrorSeverity::Packet`]（只丢这一包，循环继续），
    /// socket 错误是 [`ErrorSeverity::Connection`]（上报并断链）。
    #[must_use]
    pub fn severity(&self) -> Option<ErrorSeverity> {
        match self {
            // 合法帧：不构成错误。
            Self::Frame(_) => None,
            // 单包级：只丢这一包，循环继续。
            Self::BadDatagram { .. } => Some(ErrorSeverity::Packet),
            // 连接级：上报并结束循环。
            Self::SocketError(err) => Some(err.severity()),
        }
    }

    /// 是不是**致命**事件（收到它之后循环就结束了）。
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::SocketError(_))
    }
}

/// 收循环的**结束方式**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopOutcome {
    /// 上层调用了 [`Cancel::cancel()`]。
    Cancelled,
    /// 上层丢掉了事件通道的接收端。
    ChannelClosed,
    /// socket 级错误：循环在**上报**该错误后结束。
    SocketError(UdpError),
}

/// 取消令牌：让收循环**确定地**退出。
///
/// 语义是**一次性**的（broadcast 式）：一旦取消，所有订阅者都会看到。
#[derive(Debug, Clone)]
pub struct Cancel {
    inner: Arc<CancelInner>,
}

/// 取消令牌的内部状态。
#[derive(Debug)]
struct CancelInner {
    /// 通知用：`Notify` 只在「有新一次取消」时唤醒，状态本身记在 `cancelled` 里。
    notify: tokio::sync::Notify,
    /// 是否已取消。
    cancelled: std::sync::atomic::AtomicBool,
}

impl Cancel {
    /// 造一个**未取消**的令牌。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancelInner {
                notify: tokio::sync::Notify::new(),
                cancelled: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// 取消：唤醒所有等待者。
    pub fn cancel(&self) {
        self.inner
            .cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// 是否已取消。
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner
            .cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 等到被取消为止。
    ///
    /// **取消安全**：在 `select!` 里当分支用时，不会漏掉「已取消」这个状态
    /// （先查标志再等通知）。
    pub async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

/// 收循环句柄：上层用它**确定地**等循环退出。
#[derive(Debug)]
pub struct LoopHandle {
    /// 后台任务。
    task: JoinHandle<LoopOutcome>,
    /// 取消令牌（`stop()` 会用它）。
    cancel: Cancel,
}

impl LoopHandle {
    /// **等**循环自己结束（不主动取消）。
    ///
    /// 与 [`LoopHandle::stop`] 的区别：`stop()` 会**先取消**，所以拿到的
    /// 一定是 `Cancelled`；`join()` 则如实反映循环**自己**为什么结束
    /// （上层关了通道 ⇒ `ChannelClosed`；socket 坏了 ⇒ `SocketError`）。
    ///
    /// ⚠️ **有硬超时要求**：调用方必须自己加超时（本卡的所有测试都加了）。
    /// 本方法**不会**自己超时——超时策略属于上层。
    pub async fn join(self) -> LoopOutcome {
        match self.task.await {
            Ok(outcome) => outcome,
            // 任务 panic：等价于「异常结束」。
            Err(err) => LoopOutcome::SocketError(UdpError::Socket {
                source: super::error::SocketError::new(std::io::Error::other(format!(
                    "收循环任务异常退出：{err}"
                ))),
            }),
        }
    }

    /// 主动结束循环并等它退出。
    ///
    /// ⚠️ **有硬超时要求**：调用方必须自己加超时（本卡的所有测试都加了），
    /// 否则一旦底层出错就会挂死。本方法**不会**自己超时——
    /// 超时策略属于上层（不同调用方的容忍度不同）。
    pub async fn stop(self) -> LoopOutcome {
        self.cancel.cancel();
        self.join().await
    }

    /// 任务是否已经结束（不阻塞）。
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// 启动收循环。
///
/// 返回 `(事件接收端, 循环句柄)`。
///
/// # 参数
/// - `endpoint`：要收的端点（内部会 clone 一份 socket 句柄）；
/// - `capacity`：事件通道容量（背压）；
/// - `cancel`：取消令牌。
///
/// # 结束条件
/// 见模块文档的表格：**取消 / 通道关闭 / socket 级错误**三者之一，
/// **没有**「永远挂着」的情况。
pub fn spawn_recv_loop(
    endpoint: UdpEndpoint,
    capacity: usize,
    cancel: Cancel,
) -> (mpsc::Receiver<UdpEvent>, LoopHandle) {
    let (tx, rx) = mpsc::channel(capacity);
    let task = tokio::spawn(run_recv_loop(endpoint, tx, cancel.clone()));
    (rx, LoopHandle { task, cancel })
}

/// 收循环本体。
async fn run_recv_loop(
    endpoint: UdpEndpoint,
    tx: mpsc::Sender<UdpEvent>,
    cancel: Cancel,
) -> LoopOutcome {
    // 缓冲按「一个满帧 + 1 字节」开：多 1 字节是为了**发现**超长数据报
    // （而不是被内核悄悄截断后当成正常帧）。
    let mut buf = vec![0u8; MAX_FRAME_LEN + 1];

    loop {
        tokio::select! {
            // ① 上层取消。**最高优先级**：上层说停就停。
            biased;

            () = cancel.cancelled() => {
                return LoopOutcome::Cancelled;
            }
            // ② 上层关掉了事件通道：结束，不再收。
            () = tx.closed() => {
                return LoopOutcome::ChannelClosed;
            }
            // ③ socket 可读。
            result = endpoint.recv_frame(&mut buf) => {
                match result {
                    Ok(frame) => {
                        // 帧：交给上层。若上层已走（通道满且已关），结束。
                        if tx.send(UdpEvent::Frame(frame)).await.is_err() {
                            return LoopOutcome::ChannelClosed;
                        }
                    }
                    // 单包坏：上报这一包，**循环继续**。
                    Err(err) if err.severity() == ErrorSeverity::Packet => {
                        let UdpError::BadDatagram { origin, reason } = err else {
                            // 不可达：Packet 级只有 BadDatagram 一种。
                            return LoopOutcome::SocketError(err);
                        };
                        if tx.send(UdpEvent::BadDatagram { source: origin, reason }).await.is_err() {
                            return LoopOutcome::ChannelClosed;
                        }
                    }
                    // 连接坏：上报并**结束**循环。
                    Err(err) => {
                        // 通道已关就没必要再上报。
                        let _ = tx.send(UdpEvent::SocketError(err.clone())).await;
                        return LoopOutcome::SocketError(err);
                    }
                }
            }
        }
    }
}

/// keepalive 的配置。**间隔由上层给**——本卡不写死任何节奏常量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveConfig {
    /// 发 keepalive 的间隔。`None` = **关闭** keepalive。
    pub interval: Option<Duration>,
}

/// keepalive 任务的结束方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepaliveOutcome {
    /// 上层取消。
    Cancelled,
    /// 端点出了问题（发送失败）。
    Failed(UdpError),
}

/// keepalive 任务句柄。
#[derive(Debug)]
pub struct KeepaliveHandle {
    task: JoinHandle<KeepaliveOutcome>,
    cancel: Cancel,
}

impl KeepaliveHandle {
    /// 主动结束 keepalive 任务并等它退出。
    ///
    /// ⚠️ 调用方必须自己加超时（与 [`LoopHandle::stop`] 同理）。
    pub async fn stop(self) -> KeepaliveOutcome {
        self.cancel.cancel();
        match self.task.await {
            Ok(outcome) => outcome,
            Err(err) => KeepaliveOutcome::Failed(UdpError::Socket {
                source: super::error::SocketError::new(std::io::Error::other(format!(
                    "keepalive 任务异常退出：{err}"
                ))),
            }),
        }
    }
}

/// 启动 keepalive 任务：周期性地发**零长载荷**的 keepalive 帧。
///
/// ⚠️ **间隔由上层给**（[`KeepaliveConfig::interval`]）——本卡**不写死**任何
/// 节奏常量（那是隧道装配卡的配置项）。`interval` 为 `None` 时**不启动**，
/// 返回 `None`。
///
/// keepalive 的作用是**穿过 NAT 的空闲回收**：定期让报文流过，
/// 免得映射表被中间设备悄悄丢掉。
///
/// # Errors
/// 本函数不返回 `Result`：间隔不合法（零）时视为配置错误，直接拒绝启动。
pub fn spawn_keepalive(
    endpoint: UdpEndpoint,
    config: KeepaliveConfig,
    cancel: Cancel,
) -> Option<KeepaliveHandle> {
    let interval = config.interval?;
    if interval.is_zero() {
        // 零间隔 = busy loop，绝不允许。
        return None;
    }
    let task = tokio::spawn(run_keepalive(endpoint, interval, cancel.clone()));
    Some(KeepaliveHandle { task, cancel })
}

/// keepalive 任务本体。
async fn run_keepalive(
    endpoint: UdpEndpoint,
    interval: Duration,
    cancel: Cancel,
) -> KeepaliveOutcome {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 第一次 tick 立刻触发；这里**跳过**它，让首个 keepalive 在一个间隔之后发。
    ticker.tick().await;

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                return KeepaliveOutcome::Cancelled;
            }
            _ = ticker.tick() => {
                // keepalive = **零长载荷**的帧。
                let frame = Frame::new(
                    lengsuo_link_core::frame::FrameType::Keepalive,
                    0,
                    Vec::new(),
                );
                if let Err(err) = endpoint.send_frame(&frame).await {
                    return KeepaliveOutcome::Failed(err);
                }
            }
        }
    }
}
