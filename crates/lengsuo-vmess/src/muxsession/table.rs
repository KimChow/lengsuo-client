//! Mux 会话表：id 分配与会话登记（参考 `common/mux/session.go` 的
//! `SessionManager`）。
//!
//! 语义来源：参考 `common/mux/session.go`，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::collections::BTreeMap;

use ss_core::target::TargetAddr;

use crate::muxframe::TargetNetwork;

/// 会话表上限语义（参考 `SessionManager`）：`MaxConcurrency` 限并发会话数，
/// `MaxConnection` 限本连接累计会话数，0 表示不限。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStrategy {
    pub max_concurrency: u32,
    pub max_connection: u32,
}

/// 一个 mux 会话的本地状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub id: u16,
    pub network: TargetNetwork,
    pub target: Option<TargetAddr>,
    /// 输出侧（对端 → 本端）是否已结束。
    pub remote_closed: bool,
    /// 输入侧（本端 → 对端）是否已结束。
    pub local_closed: bool,
    /// 是否已发出过 New 帧（之后一律 Keep）。
    pub new_sent: bool,
}

/// `SessionManager`：id 分配与会话登记。
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: BTreeMap<u16, SessionState>,
    count: u16,
    closed: bool,
    strategy: SessionStrategy,
}

impl SessionTable {
    /// `NewSessionManager` + 策略（参考 `Allocate` 读 `ClientStrategy`）。
    #[must_use]
    pub fn new(strategy: SessionStrategy) -> Self {
        SessionTable {
            sessions: BTreeMap::new(),
            count: 0,
            closed: false,
            strategy,
        }
    }

    /// 当前并发会话数（`Size()`）。
    #[must_use]
    pub fn size(&self) -> usize {
        self.sessions.len()
    }

    /// 累计分配过的会话数（`Count()`）。
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// 是否已关闭。
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// `Allocate`：分配新 id（`m.count++` 后取 `ID = count`，**从 1 开始**）。
    /// 超限或已关闭返回 `None`。
    pub fn allocate(&mut self, network: TargetNetwork, target: TargetAddr) -> Option<SessionState> {
        if self.closed {
            return None;
        }
        if self.strategy.max_concurrency > 0
            && self.sessions.len() >= self.strategy.max_concurrency as usize
        {
            return None;
        }
        if self.strategy.max_connection > 0 && self.count >= self.strategy.max_connection as u16 {
            return None;
        }
        self.count = self.count.wrapping_add(1);
        let state = SessionState {
            id: self.count,
            network,
            target: Some(target),
            remote_closed: false,
            local_closed: false,
            new_sent: false,
        };
        self.sessions.insert(state.id, state.clone());
        Some(state)
    }

    /// `Add`：按对端指定的 id 登记（服务端方向 `Session{ID: meta.SessionID}`）。
    pub fn add(&mut self, state: SessionState) -> bool {
        if self.closed {
            return false;
        }
        self.count = self.count.wrapping_add(1);
        self.sessions.insert(state.id, state);
        true
    }

    /// `Remove`。
    pub fn remove(&mut self, id: u16) {
        self.sessions.remove(&id);
    }

    /// `Get`。
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&SessionState> {
        self.sessions.get(&id)
    }

    /// `Get` 的可变版。
    pub fn get_mut(&mut self, id: u16) -> Option<&mut SessionState> {
        self.sessions.get_mut(&id)
    }

    /// 已登记的会话 id（升序）。
    pub fn ids(&self) -> Vec<u16> {
        self.sessions.keys().copied().collect()
    }

    /// `Close`：全部会话标记关闭并清表。
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.sessions.clear();
    }

    /// `CloseIfNoSessionAndIdle`：无会话且计数未变时置关闭。
    pub fn close_if_idle(&mut self, check_size: usize, check_count: u16) -> bool {
        if self.closed {
            return true;
        }
        if !self.sessions.is_empty() || check_size != 0 || check_count != self.count {
            return false;
        }
        self.closed = true;
        true
    }
}
