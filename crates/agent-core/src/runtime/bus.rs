//! 事件重放、订阅与总线访问。

use uuid::Uuid;

use crate::bus::EventBus;
use crate::error::CoreError;
use crate::schema::Event;

use super::Runtime;

impl Runtime {
    /// 事件回放（`seq > after_seq`）。
    pub fn replay(
        &self,
        session_id: Uuid,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Event>, CoreError> {
        self.log.replay(session_id, after_seq, limit)
    }

    /// 订阅指定隔离键的事件流（网关 WS 用）。
    pub fn subscribe(&self, isolation_key: &str) -> crate::bus::Subscription {
        self.hub.bus(isolation_key).subscribe()
    }

    /// 总线句柄（观测/测试）。
    pub fn bus(&self, isolation_key: &str) -> EventBus {
        self.hub.bus(isolation_key)
    }

    /// 已登记会话 id（内存热态）。
    pub fn session_ids(&self) -> Vec<Uuid> {
        let guard = self.sessions.lock().expect("会话表锁不得毒化");
        guard.keys().copied().collect()
    }

    // ---------- 内部 ----------
}
