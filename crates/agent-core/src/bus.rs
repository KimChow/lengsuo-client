//! 事件订阅总线（开工说明 §2：`GET /events` 推送；核心不依赖 tokio）。
//!
//! 多生产者（回合执行）/多消费者（WS 连接）的最小广播：
//! - `subscribe` 返回带容量的订阅游标，慢消费者丢最旧事件（不断流、不阻塞发送方）；
//! - 发送方 `publish` 永不阻塞（`try_send`）；
//! - 网关层把 `Receiver` 桥接成 WebSocket 帧。
//!
//! 用 `std::sync::mpsc::SyncSender` 而非通道库，保持 agent-core 无运行时依赖。

use std::collections::BTreeMap;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use crate::schema::Event;

/// 每个订阅者的缓冲事件数（超出丢最旧，保证发布方永不阻塞）。
pub const SUBSCRIBER_CAPACITY: usize = 512;

/// 订阅句柄（网关侧持有）。
pub struct Subscription {
    id: u64,
    rx: std::sync::mpsc::Receiver<Event>,
    bus: Arc<Mutex<BusState>>,
}

impl Subscription {
    /// 取下一事件（阻塞）。发送端全部关闭且缓冲空时返回 `None`。
    pub fn next(&self) -> Option<Event> {
        self.rx.recv().ok()
    }

    /// 非阻塞取事件。
    pub fn try_next(&self) -> Option<Event> {
        self.rx.try_recv().ok()
    }

    /// 订阅者 id（观测用）。
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Ok(mut state) = self.bus.lock() {
            state.subscribers.remove(&self.id);
        }
    }
}

/// 会话级隔离的事件流集合（隔离键 → 总线）。
#[derive(Default)]
struct HubState {
    buses: BTreeMap<String, EventBus>,
}

/// 一条事件总线（按隔离键分组；同一会话的事件都发到该总线）。
#[derive(Clone, Default)]
pub struct EventBus {
    state: Arc<Mutex<BusState>>,
}

#[derive(Default)]
struct BusState {
    next_id: u64,
    subscribers: BTreeMap<u64, SyncSender<Event>>,
    published: u64,
    dropped: u64,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// 新订阅者。
    pub fn subscribe(&self) -> Subscription {
        let (tx, rx) = sync_channel::<Event>(SUBSCRIBER_CAPACITY);
        let mut state = self.state.lock().expect("事件总线锁不得毒化");
        let id = state.next_id;
        state.next_id += 1;
        state.subscribers.insert(id, tx);
        Subscription {
            id,
            rx,
            bus: Arc::clone(&self.state),
        }
    }

    /// 广播一条事件；满载订阅者丢弃本条事件并计数，断开订阅者直接摘除（非阻塞，保证回合线程继续跑）。
    pub fn publish(&self, event: Event) {
        let mut state = self.state.lock().expect("事件总线锁不得毒化");
        state.published += 1;
        let mut slow: Vec<u64> = Vec::new();
        let mut dropped_full: u64 = 0;
        for (id, tx) in state.subscribers.iter() {
            let item = event.clone();
            match tx.try_send(item) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    // 满：丢弃本条（SyncSender 无法从发送端回收最旧）。
                    dropped_full += 1;
                    slow.push(*id);
                }
                // 断开的订阅者直接摘除（其 Subscription 已被 drop）。
                Err(TrySendError::Disconnected(_)) => slow.push(*id),
            }
        }
        state.dropped += dropped_full;
        for id in slow {
            state.subscribers.remove(&id);
        }
    }

    /// 当前订阅者数量。
    pub fn subscriber_count(&self) -> usize {
        self.state
            .lock()
            .map(|s| s.subscribers.len())
            .unwrap_or_default()
    }

    /// 发布/丢弃计数（卡顿回归的观测口子，N9 教训）。
    pub fn stats(&self) -> (u64, u64) {
        self.state
            .lock()
            .map(|s| (s.published, s.dropped))
            .unwrap_or((0, 0))
    }
}

/// 按隔离键分组的总线仓库：不同用户/租户的事件互不可见。
#[derive(Default)]
pub struct EventHub {
    state: Mutex<HubState>,
}

impl EventHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// 取（或创建）指定隔离键的事件总线。
    pub fn bus(&self, isolation_key: &str) -> EventBus {
        let mut state = self.state.lock().expect("事件仓库锁不得毒化");
        state
            .buses
            .entry(isolation_key.to_string())
            .or_default()
            .clone()
    }

    /// 已知隔离键（升序）。
    pub fn keys(&self) -> Vec<String> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        state.buses.keys().cloned().collect()
    }
}
