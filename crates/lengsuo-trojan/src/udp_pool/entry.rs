//! UDP 会话池的**条目内部实现**（`crate::udp_pool` 的私有子模块）。
//!
//! 一个条目 = 一个目标地址 = 一个出站 `UdpSocket` + 一个回程读任务。
//! 参考语义见 `crate::udp_pool` 的模块注释（Xray v26.3.27 `d2758a0`）。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ss_core::target::TargetAddr;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};

use crate::udp_pool::{Error, Inbound};

/// 池内条目：一个目标对应一个出站 socket。
pub(crate) struct Entry {
    /// 实际发往的地址（域名目标已解析）。
    pub(crate) resolved: SocketAddr,
    /// 回程地址（由 `resolved` 还原为 SOCKS 地址）。
    pub(crate) reply: TargetAddr,
    /// 出站 socket（通配源，地址族跟随目标）。
    socket: UdpSocket,
    /// 同目标的发送串行锁（条目内局部，池表锁不参与）。
    send_lock: AsyncMutex<()>,
    /// 最后一次收发时刻（相对池创建点的毫秒数）：用于空闲回收判定。
    last_active: AtomicU64,
    /// 活跃序号（单调递增）：用于 LRU 淘汰的**确定性**排序。
    ///
    /// 不用毫秒时间戳排序：同一毫秒内建立的两个条目时间戳相同，LRU 会退化成
    /// 任意顺序，淘汰对象不可预测。单调序号保证“后建立/后使用”的条目序号更大。
    activity_seq: AtomicU64,
    /// 条目是否已关闭（被淘汰、回收或池关闭）。
    closed: AtomicBool,
    /// 关闭通知：唤醒阻塞在 `recv_from` 的读任务。
    close_notify: Notify,
    /// 时间基准（与池一致）。
    epoch: Instant,
    /// 池级存活计数（条目析构 ⇒ socket 真正释放 ⇒ 计数减一）。
    live: Arc<AtomicUsize>,
    /// 池级活跃序号分配器。
    seq: Arc<AtomicU64>,
}

impl Entry {
    /// 新建条目：`socket` 的所有权移入条目。
    pub(crate) fn new(
        resolved: SocketAddr,
        socket: UdpSocket,
        epoch: Instant,
        live: Arc<AtomicUsize>,
        seq: Arc<AtomicU64>,
    ) -> Self {
        let activity_seq = seq.fetch_add(1, Ordering::SeqCst) + 1;
        Self {
            resolved,
            reply: target_from_socket(resolved),
            socket,
            send_lock: AsyncMutex::new(()),
            last_active: AtomicU64::new(epoch.elapsed().as_millis() as u64),
            activity_seq: AtomicU64::new(activity_seq),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
            epoch,
            live,
            seq,
        }
    }

    /// 同条目的发送串行，保证发包顺序与参考一致。
    pub(crate) async fn send(&self, payload: &[u8]) -> Result<(), Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let _guard = self.send_lock.lock().await;
        self.socket
            .send_to(payload, self.resolved)
            .await
            .map_err(Error::Send)?;
        self.touch();
        Ok(())
    }

    /// 关闭条目：唤醒读任务；socket 随条目析构释放。
    ///
    /// 幂等：重复调用只生效一次（关闭计数也只减一次）。
    pub(crate) fn close(&self) -> bool {
        if self.closed.swap(true, Ordering::SeqCst) {
            return false;
        }
        // `notify_one` 在没有等待者时存下一个许可，避免与读任务注册之间的竞态。
        self.close_notify.notify_one();
        true
    }

    /// 条目是否已关闭。
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// 最后一次收发时刻（毫秒）。
    pub(crate) fn last_active(&self) -> u64 {
        self.last_active.load(Ordering::SeqCst)
    }

    /// 刷新活跃时刻（只允许前进，避免并发写回导致时间戳倒退）。
    ///
    /// 同时刷新活跃序号：LRU 淘汰按序号排序，「最近用过」的条目序号最大。
    pub(crate) fn touch(&self) {
        let now = self.epoch.elapsed().as_millis() as u64;
        self.last_active.fetch_max(now, Ordering::SeqCst);
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.activity_seq.fetch_max(seq, Ordering::SeqCst);
    }

    /// 当前活跃序号（LRU 排序键）。
    pub(crate) fn activity_seq(&self) -> u64 {
        self.activity_seq.load(Ordering::SeqCst)
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        // 条目析构 ⇒ 出站 socket 真正释放。
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 条目的回程读任务：把回程数据报送入池的有界队列。
///
/// 只接受来自本条目目标地址的回程，避免串包；队列满时丢弃该数据报并计数
/// （对齐参考 `dispatcherConn.callback` 的 `default:` 分支）。
pub(crate) fn spawn_reader(
    entry: Arc<Entry>,
    tx: mpsc::Sender<Inbound>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; crate::udp::MAX_PAYLOAD_LEN];
        loop {
            if entry.is_closed() {
                break;
            }
            let notified = entry.close_notify.notified();
            tokio::pin!(notified);
            let received = tokio::select! {
                _ = &mut notified => break,
                result = entry.socket.recv_from(&mut buf) => result,
            };
            let Ok((size, from)) = received else {
                break;
            };
            if from != entry.resolved {
                continue;
            }
            entry.touch();
            let inbound = Inbound {
                address: entry.reply.clone(),
                payload: buf[..size].to_vec(),
            };
            match tx.try_send(inbound) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    dropped.fetch_add(1, Ordering::SeqCst);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
    });
}

/// 把回程源地址还原为 SOCKS 地址。
pub(crate) fn target_from_socket(from: SocketAddr) -> TargetAddr {
    match from {
        SocketAddr::V4(addr) => TargetAddr::V4(addr.ip().octets(), addr.port()),
        SocketAddr::V6(addr) => TargetAddr::V6(addr.ip().octets(), addr.port()),
    }
}
