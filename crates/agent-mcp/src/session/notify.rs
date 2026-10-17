//! 通知订阅端：把会话内部的广播通道转成有界队列交给上层。
//!
//! 会话内部用 `tokio::sync::broadcast`（每个订阅端独立、滞后则丢最旧），上层
//! 要的是「有界队列、满了丢最旧、慢消费者绝不反压读循环」。两者之间需要一个
//! 转发任务，规则如下：
//! - 广播端滞后（读循环写得太快）→ 累加 `dropped` 计数，继续收下一条；
//! - 有界队列已满 → 丢队列头部（最旧）一条并累加计数，然后写入新的一条；
//! - 广播通道关闭（会话结束）或接收端被释放 → 转发任务退出并关闭队列，
//!   此时 `recv()` 返回 `None`，不留下永久等待。
//!
//! 队列不自带阻塞写入：`push` 只动 `Mutex<VecDeque>` + `Notify`，因此读循环
//! 与转发任务都不会因为消费者慢而停下来。

use std::collections::VecDeque;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::sync::{broadcast, Notify};

use super::state::Inner;
use crate::protocol::JsonRpcNotification;

/// 队列共享状态。
struct QueueState {
    capacity: usize,
    slots: Mutex<VecDeque<(String, Value)>>,
    closed: AtomicBool,
    /// 因滞后或队列满而被丢弃的通知条数（诊断用）。
    dropped: Arc<AtomicU64>,
    /// 唤醒等待中的接收端。
    wake: Notify,
    /// 唤醒转发任务：接收端已释放，任务应立即退出，不能等到广播通道关闭。
    stop: Notify,
}

impl QueueState {
    fn push(&self, item: (String, Value)) -> bool {
        {
            let mut slots = self.slots.lock().expect("通知队列锁不中毒");
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            while slots.len() >= self.capacity {
                // 丢最旧，保证最新一条能进去（消费慢不阻塞生产侧）。
                if slots.pop_front().is_some() {
                    self.dropped.fetch_add(1, Ordering::AcqRel);
                } else {
                    break;
                }
            }
            slots.push_back(item);
        }
        self.wake.notify_one();
        true
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_waiters();
        self.stop.notify_waiters();
    }

    /// 登记「等待停止」唤醒（转发任务用）。调用方必须用 `pin!` + `enable`
    /// 后再 `select!`，以免任务停等时漏掉关闭信号。
    fn stop_notified(&self) -> Notify<'_> {
        self.stop.notified()
    }

    fn take_next(&self) -> Option<Option<(String, Value)>> {
        let mut slots = self.slots.lock().expect("通知队列锁不中毒");
        match slots.pop_front() {
            Some(item) => Some(Some(item)),
            None if self.closed.load(Ordering::Acquire) => Some(None),
            None => None,
        }
    }
}

/// 服务端主动通知的订阅端（对外见 [`crate::NotificationReceiver`]）。
pub(crate) struct NotificationReceiver {
    state: Arc<QueueState>,
}

impl std::fmt::Debug for NotificationReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationReceiver")
            .field("capacity", &self.state.capacity)
            .field(
                "queued",
                &self
                    .state
                    .slots
                    .lock()
                    .map(|g| g.len())
                    .unwrap_or_else(|_| self.state.capacity),
            )
            .finish_non_exhaustive()
    }
}

impl NotificationReceiver {
    /// 取下一条通知；队列已关闭（会话结束或本接收端被释放）时返回 `None`。
    pub async fn recv(&mut self) -> Option<(String, Value)> {
        loop {
            // 先登记唤醒再检查，避免「检查完立刻有人 push」的丢唤醒窗口。
            let mut notified = pin!(self.state.wake.notified());
            notified.as_mut().enable();
            if let Some(outcome) = self.state.take_next() {
                return outcome;
            }
            notified.await;
        }
    }

    /// 非阻塞取一条通知（测试与轮询用）。队列为空返回 `None`。
    #[must_use]
    pub fn try_recv(&mut self) -> Option<(String, Value)> {
        self.state.take_next().flatten()
    }

    /// 队列中当前已排队的通知条数（诊断用）。
    #[must_use]
    pub fn queued(&self) -> usize {
        self.state
            .slots
            .lock()
            .map(|g| g.len())
            .unwrap_or(self.state.capacity)
    }

    /// 因滞后或队列满被丢弃的通知条数。
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.state.dropped.load(Ordering::Acquire)
    }
}

impl Drop for NotificationReceiver {
    fn drop(&mut self) {
        // 上层不再收通知：关闭队列，转发任务下一次 push 失败后退出。
        self.state.close();
    }
}

/// 从会话广播端取一个订阅者并启动转发任务。
///
/// 每个会话只能成功取一次（广播端只预留一个订阅者）；再次调用返回 `None`，
/// 由上层给出「通知订阅端已被取走」的错误。
pub(super) fn subscribe(inner: &Arc<Inner>, capacity: usize) -> Option<NotificationReceiver> {
    let seed = inner
        .notify_seed
        .lock()
        .expect("notify_seed 锁不中毒")
        .take()?;
    let state = Arc::new(QueueState {
        capacity: capacity.max(1),
        slots: Mutex::new(VecDeque::new()),
        closed: AtomicBool::new(false),
        dropped: Arc::clone(&inner.notify_dropped),
        wake: Notify::new(),
    });
    // 转发任务持有会话状态与队列状态的克隆：队列只由接收端释放或广播通道
    // 关闭来终结，任务不会因为上层不再收通知而悬挂。
    let task_inner = Arc::clone(inner);
    let task_state = Arc::clone(&state);
    let mut seed = seed;
    tokio::spawn(async move {
        loop {
            match seed.recv().await {
                Ok(note) => {
                    if !task_state.push(into_pair(note)) {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_skipped)) => {
                    task_inner.notify_dropped.fetch_add(1, Ordering::AcqRel);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        task_state.close();
    });
    Some(NotificationReceiver { state })
}

fn into_pair(note: JsonRpcNotification) -> (String, Value) {
    (note.method, note.params.unwrap_or(Value::Null))
}
