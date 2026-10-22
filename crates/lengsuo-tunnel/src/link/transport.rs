//! L1 搬运的 UDP 落地：把**异步**的 [`UdpEndpoint`] 适配成**同步**的
//! [`Transport`]。
//!
//! # 为什么需要桥
//!
//! `Transport`（`lengsuo-link-core`）是**同步** trait：`send` / `recv` 立刻
//! 返回。`UdpEndpoint` 是 **tokio 异步**：收发都要 `.await`。两者不能直接对接。
//!
//! # 桥的形态（后台任务 + 队列）
//!
//! ```text
//!   send(bytes) ──try_send──▶ [outbound 队列] ──recv().await──▶ 发送任务 ──▶ send_raw().await
//!   recv() ◀──try_recv── [inbound 队列] ◀──send().await── 接收任务 ◀── recv_raw().await
//! ```
//!
//! - 两个后台任务各自 `.await` 真正的 socket IO；
//! - 同步的 `send` / `recv` 只做**非阻塞**的 `try_send` / `try_recv`；
//! - 队列空 ⇒ [`TransportError::WouldBlock`]（契约 #4：这**不是**失败）。
//!
//! ⛔ **不用 `block_on`**：在 tokio 运行时线程上 `block_on` 会 panic
//! （不能在运行时里再启动运行时）；即便不 panic，也会把 reactor 线程钉死。
//! ⛔ **不用 `std::net::UdpSocket`**：同步 socket 的 `recv` 会阻塞 reactor，
//! 让同一运行时上的其它任务全部停摆。
//! ⛔ **不新开 socket**：复用现有的 [`UdpEndpoint`]（已 connected、已处理
//! MTU 预算）。
//!
//! # 错误语义（fail-closed）
//!
//! - 后台任务遇到 **socket 级错误** ⇒ 记进**粘性故障槽**并退出；此后
//!   `send` / `recv` 一律返回该错误（⛔ 不吞掉、⛔ 不改写成成功）。
//! - 超长 ⇒ [`TransportError::TooLong`]（**不截断**；接收侧整包丢弃）。
//! - 暂时没数据 ⇒ [`TransportError::WouldBlock`]。
//!
//! ⚠️ **一处已声明的偏离**：socket 级的**发送**错误发生在后台任务里，
//! 同步 `send` 此时已把字节交进队列并返回成功。错误会在**下一次**
//! `send` / `recv` 通过故障槽浮出，而不是在失败的那一次调用上。

use std::sync::{Arc, Mutex};

use lengsuo_link_core::frame::MAX_FRAME_LEN;
use lengsuo_link_core::transport::{Transport, TransportError};
use tokio::sync::mpsc;

use crate::udp::{Cancel, UdpEndpoint, UdpError};

/// 发送队列容量。
///
/// 有界 ⇒ 上层灌得太快时 `try_send` 返回 `Full`（背压），而不是无界占内存。
const OUTBOUND_CAPACITY: usize = 64;
/// 接收队列容量。
const INBOUND_CAPACITY: usize = 64;

/// 把异步 [`UdpEndpoint`] 适配成同步 [`Transport`] 的桥。
///
/// 构造即启动两个后台任务；[`Drop`] 会取消它们。
///
/// ⚠️ 必须在 tokio 运行时内构造（内部 `tokio::spawn`）。
pub struct UdpTransport {
    /// 交给发送任务的待发字节。
    outbound: mpsc::Sender<Vec<u8>>,
    /// 接收任务交上来的字节。
    inbound: mpsc::Receiver<Vec<u8>>,
    /// 粘性故障槽：后台任务的 socket 级错误在这里浮出（只记第一个）。
    fault: Arc<Mutex<Option<TransportError>>>,
    /// 取消令牌：`Drop` 时让两个任务确定退出。
    cancel: Cancel,
    /// 本端准入的单帧上限。
    max_frame_len: usize,
}

impl UdpTransport {
    /// 用一个已连接的端点造桥。端点内部会 clone 一份 socket 句柄给两个任务。
    #[must_use]
    pub fn new(endpoint: UdpEndpoint) -> Self {
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_CAPACITY);
        let fault = Arc::new(Mutex::new(None));
        let cancel = Cancel::new();

        spawn_sender(
            endpoint.clone(),
            outbound_rx,
            Arc::clone(&fault),
            cancel.clone(),
        );
        spawn_receiver(endpoint, inbound_tx, Arc::clone(&fault), cancel.clone());

        Self {
            outbound,
            inbound,
            fault,
            cancel,
            max_frame_len: MAX_FRAME_LEN,
        }
    }

    /// 故障槽里的**粘性**错误（`None` = 链路正常）。
    #[must_use]
    pub fn fault(&self) -> Option<TransportError> {
        lock(&self.fault).clone()
    }

    /// 收/发前的故障检查：链路坏了一律 fail-closed。
    fn check_fault(&self) -> Result<(), TransportError> {
        match lock(&self.fault).as_ref() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

impl Transport for UdpTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        // 长度检查**先于**入队：超长一个字节都不发，⛔ 不截断。
        if bytes.len() > self.max_frame_len {
            return Err(TransportError::TooLong {
                actual: bytes.len(),
                limit: self.max_frame_len,
            });
        }
        self.check_fault()?;
        match self.outbound.try_send(bytes.to_vec()) {
            Ok(()) => Ok(()),
            // 队列满 = 暂时发不出去（背压），⛔ 不是失败。
            Err(mpsc::error::TrySendError::Full(_)) => Err(TransportError::WouldBlock),
            // 发送任务已结束：链路不可用。
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportError::Closed {
                reason: "发送任务已结束",
            }),
        }
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        self.check_fault()?;
        match self.inbound.try_recv() {
            Ok(bytes) => {
                if bytes.len() > self.max_frame_len {
                    // 超长数据报：明确报错。包在接收任务里已整包取走 ⇒ 自然丢弃。
                    return Err(TransportError::TooLong {
                        actual: bytes.len(),
                        limit: self.max_frame_len,
                    });
                }
                Ok(bytes)
            }
            // 队列空 = 暂时没数据（契约 #4），⛔ 不是失败。
            Err(mpsc::error::TryRecvError::Empty) => Err(TransportError::WouldBlock),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TransportError::Closed {
                reason: "接收任务已结束",
            }),
        }
    }

    fn max_frame_len(&self) -> usize {
        self.max_frame_len
    }
}

impl Drop for UdpTransport {
    /// 取消两个后台任务（⛔ 不留永远挂着的循环）。
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// 发送任务：把队列里的字节交给 socket。
fn spawn_sender(
    endpoint: UdpEndpoint,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    fault: Arc<Mutex<Option<TransportError>>>,
    cancel: Cancel,
) {
    tokio::spawn(async move {
        loop {
            let bytes = tokio::select! {
                biased;
                // ① 上层取消：最高优先级。
                () = cancel.cancelled() => break,
                // ② 队列取到一帧；上层丢掉了发送端 ⇒ 结束。
                received = outbound.recv() => match received {
                    Some(bytes) => bytes,
                    None => break,
                },
            };
            if let Err(error) = endpoint.send_raw(&bytes).await {
                // socket 级错误：记进故障槽（粘性），⛔ 不吞掉。
                record(&fault, map_udp_error(&error));
                break;
            }
        }
    });
}

/// 接收任务：把 socket 收到的数据报交给队列。
fn spawn_receiver(
    endpoint: UdpEndpoint,
    inbound: mpsc::Sender<Vec<u8>>,
    fault: Arc<Mutex<Option<TransportError>>>,
    cancel: Cancel,
) {
    tokio::spawn(async move {
        // 多 1 字节是为了**发现**超长数据报（而不是被内核悄悄截断后当成正常帧）。
        let mut buf = vec![0u8; MAX_FRAME_LEN + 1];
        loop {
            let result = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                result = endpoint.recv_raw(&mut buf) => result,
            };
            match result {
                // 拷贝出缓冲（缓冲会被复用）；长度检查留给同步侧的 `recv`。
                Ok((len, _source)) => {
                    if inbound.send(buf[..len].to_vec()).await.is_err() {
                        // 上层丢掉了接收端 ⇒ 没人要了，结束。
                        break;
                    }
                }
                Err(error) => {
                    record(&fault, map_udp_error(&error));
                    break;
                }
            }
        }
    });
}

/// 只记**第一个**故障（粘性：后续调用一律返回它）。
fn record(fault: &Mutex<Option<TransportError>>, error: TransportError) {
    let mut slot = lock(fault);
    if slot.is_none() {
        *slot = Some(error);
    }
}

/// 取锁；互斥量**从不跨 await 持有**，中毒只会来自同伴任务的 panic。
fn lock(
    fault: &Mutex<Option<TransportError>>,
) -> std::sync::MutexGuard<'_, Option<TransportError>> {
    match fault.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// UDP 层错误 → L1 传输错误（⛔ 不吞掉、⛔ 不改写成成功）。
fn map_udp_error(error: &UdpError) -> TransportError {
    match error {
        // 没设对端 = 链路根本没接上。
        UdpError::NoPeer => TransportError::Closed {
            reason: "未设置对端地址",
        },
        // 对端不可达 / socket 断开 = 链路已关闭；其它 socket 错误按 IO 上报。
        UdpError::Socket { source } => match source.kind() {
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::BrokenPipe => TransportError::Closed {
                reason: "对端不可达",
            },
            _ => TransportError::Io {
                reason: "socket 收发失败",
            },
        },
        // 以下三者在本实现里理论不可达（缓冲固定 1421B、只走 raw 收发）：
        // 真出现就是实现缺陷，明确报出来，⛔ 不静默当成功。
        UdpError::Encode(_) => TransportError::Internal("帧编码失败"),
        UdpError::BufferTooSmall { .. } => TransportError::Internal("接收缓冲大小不合法"),
        UdpError::BadDatagram { .. } => TransportError::Internal("收到非帧数据报"),
    }
}
