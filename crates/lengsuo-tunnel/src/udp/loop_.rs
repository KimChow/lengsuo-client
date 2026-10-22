//! 收发循环：**一个能收的循环**，带**明确的结束条件**。
//!
//! # 形态
//!
//! `async fn` + **channel**：`spawn_recv_loop` 起一个后台任务，把收到的
//! 数据报（裸握手 / L3 帧）通过 `mpsc` 交给上层。任务句柄 [`LoopHandle`]
//! 暴露 `stop()`，上层可以**确定地**等它退出。
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

use lengsuo_link_core::frame::{Frame, MAX_FRAME_LEN};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::datagram::{classify, Datagram, HandshakeKind};
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
    /// 收到一个**裸握手报文**（initiation / response / cookie）：
    /// **未**套 L3 帧头，由首字节判定种类（见 [`super::datagram`]）。
    Handshake {
        /// 报文种类。
        kind: HandshakeKind,
        /// 裸握手字节（线上原样，148 / 92 / 64 字节）。
        bytes: Vec<u8>,
        /// 数据报来源地址。
        source: SocketAddr,
    },
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
    /// 事件的严重级别。**合法帧 / 握手报文不是错误** ⇒ 返回 `None`。
    ///
    /// 让上层**不必匹配变体**就能判两级：
    /// 坏数据报是 [`ErrorSeverity::Packet`]（只丢这一包，循环继续），
    /// socket 错误是 [`ErrorSeverity::Connection`]（上报并断链）。
    #[must_use]
    pub fn severity(&self) -> Option<ErrorSeverity> {
        match self {
            // 合法帧 / 裸握手：不构成错误。
            Self::Frame(_) | Self::Handshake { .. } => None,
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
            // ③ socket 可读：收**裸数据报**，再按首字节分流。
            result = endpoint.recv_raw(&mut buf) => {
                match result {
                    Ok((len, source)) => {
                        match classify(&buf[..len]) {
                            // 帧：交给上层。若上层已走（通道满且已关），结束。
                            Ok(Datagram::Frame(frame)) => {
                                if tx.send(UdpEvent::Frame(frame)).await.is_err() {
                                    return LoopOutcome::ChannelClosed;
                                }
                            }
                            // 裸握手：原样交给上层（拷贝出缓冲，缓冲会被复用）。
                            Ok(Datagram::Handshake { kind }) => {
                                let event = UdpEvent::Handshake {
                                    kind,
                                    bytes: buf[..len].to_vec(),
                                    source,
                                };
                                if tx.send(event).await.is_err() {
                                    return LoopOutcome::ChannelClosed;
                                }
                            }
                            // 单包坏（未知首字节 / 帧解不开）：上报这一包，**循环继续**。
                            Err(err) => {
                                let reason = err.reason();
                                if tx.send(UdpEvent::BadDatagram { source, reason }).await.is_err() {
                                    return LoopOutcome::ChannelClosed;
                                }
                            }
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
