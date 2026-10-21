//! 会话表（`SessionManager`）与分配策略。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。语义逐条对齐参考
//! `common/mux/session.go`（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。

use std::collections::HashMap;

use crate::mux::frame::TargetNetwork;
use ss_core::target::TargetAddr;

/// 会话 ID 分配与查询（`SessionManager`）。
///
/// 与参考一致：`count` 单调递增用于下发 ID，**不复用**已关闭会话的 ID；
/// `size` 为当前活跃会话数。
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<u16, SessionState>,
    count: u16,
    closed: bool,
}

/// 会话表里的静态信息（参考 `Session` 中与网络无关的部分）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    /// 目标地址与网络。
    pub target: (TargetAddr, TargetNetwork),
}

/// 客户端/服务端策略（参考 `ClientStrategy`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Strategy {
    /// 单条 Mux 连接上的最大**活跃**会话数；0 表示不限制。
    pub max_concurrency: u32,
    /// 单条 Mux 连接上的最大**累计**会话数；0 表示不限制。
    pub max_connection: u32,
}

/// 分配失败的原因（参考 `Allocate` 返回 `nil`）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocateError {
    /// 会话表已关闭。
    #[error("mux session manager closed")]
    Closed,
    /// 活跃会话数达到 `MaxConcurrency`。
    #[error("mux session concurrency limit reached")]
    ConcurrencyLimit,
    /// 累计会话数达到 `MaxConnection`。
    #[error("mux session connection limit reached")]
    ConnectionLimit,
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `Closed()`。
    #[must_use]
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// `Size()`：活跃会话数。
    #[must_use]
    pub fn size(&self) -> usize {
        self.sessions.len()
    }

    /// `Count()`：累计分配过的会话数。
    #[must_use]
    pub fn count(&self) -> u16 {
        self.count
    }

    /// `Allocate`：分配一个新的会话 ID。
    ///
    /// 参考在 `closed || (MaxConcurrency>0 && len>=MaxConcurrency) ||
    /// (MaxConnection>0 && count>=MaxConnection)` 时返回 `nil`。
    pub fn allocate(&mut self, strategy: &Strategy) -> Result<u16, AllocateError> {
        if self.closed {
            return Err(AllocateError::Closed);
        }
        if strategy.max_concurrency > 0 && self.sessions.len() >= strategy.max_concurrency as usize
        {
            return Err(AllocateError::ConcurrencyLimit);
        }
        if strategy.max_connection > 0 && self.count >= strategy.max_connection as u16 {
            return Err(AllocateError::ConnectionLimit);
        }
        // 参考 `m.count++` 后取 `ID: m.count`；u16 回绕在 65535 时不被参考处理，
        // 本层同样照抄（不额外校验），但用 wrapping 避免 debug 构建 panic。
        self.count = self.count.wrapping_add(1);
        Ok(self.count)
    }

    /// `Add`：把（已分配 ID 的）会话登记进表；表已关闭时返回 false 并且**不**登记。
    pub fn add(&mut self, id: u16, state: SessionState) -> bool {
        if self.closed {
            return false;
        }
        self.sessions.insert(id, state);
        true
    }

    /// `Remove`。
    pub fn remove(&mut self, id: u16) {
        if self.closed {
            return;
        }
        self.sessions.remove(&id);
    }

    /// `Get`。
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&SessionState> {
        if self.closed {
            return None;
        }
        self.sessions.get(&id)
    }

    /// `CloseIfNoSessionAndIdle`：无活跃会话且 `count` 与观察点一致时才关闭。
    pub fn close_if_no_session_and_idle(&mut self, check_size: usize, check_count: u16) -> bool {
        if self.closed {
            return true;
        }
        if !self.sessions.is_empty() || check_size != 0 || check_count != self.count {
            return false;
        }
        self.closed = true;
        self.sessions.clear();
        true
    }

    /// `Close`。
    pub fn close(&mut self) {
        self.closed = true;
        self.sessions.clear();
    }
}
