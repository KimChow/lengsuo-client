//! 审批流机械结构（原样保留，已测透）：Slot/Pending 挂起、120s 超时→deny、
//! 一次性应答、过期应答降级。判定逻辑见同目录 mod.rs / resource.rs。

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use uuid::Uuid;

use crate::error::CoreError;
use crate::schema::{ApprovalOutcome, ApprovalRequest};

use super::{now_ms, PermissionGate};

/// 单个审批的应答槽（wait/respond 汇合点）。
#[derive(Default)]
struct SlotState {
    /// 是否已应答（应答后不可重复）。
    answered: bool,
    /// 应答/超时结果；`wait` 取走后置回 `None`。
    outcome: Option<ApprovalOutcome>,
}

struct Slot {
    state: Mutex<SlotState>,
    changed: Condvar,
    /// 单调时钟截止点：晚于此刻的应答一律按过期 deny 处理，`wait` 也以此封顶。
    deadline: Instant,
}

impl Slot {
    /// `deadline` 为 `None`（超大超时溢出）时 fail-closed：视为已过期。
    fn new(deadline: Option<Instant>) -> Self {
        Self {
            state: Mutex::new(SlotState::default()),
            changed: Condvar::new(),
            deadline: deadline.unwrap_or_else(Instant::now),
        }
    }

    /// 已产生的结果（不移除；供应答判重）。
    fn answered(&self) -> bool {
        self.state.lock().map(|s| s.answered).unwrap_or(true)
    }

    /// 是否已到达截止点（单调时钟，不受系统时间回拨影响）。
    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// 距截止点的剩余时间（已过期为 0）。
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// 挂起审批的索引项。
pub(crate) struct Pending {
    pub(crate) session_id: String,
    slot: Arc<Slot>,
}

impl PermissionGate {
    /// 发起审批：生成挂起请求（摘要已脱敏，不含凭据值）。
    pub fn request_approval(&self, session_id: &str, tool: &str, args: &Value) -> ApprovalRequest {
        let id = Uuid::new_v4();
        let summary = self.redactor.summarize_args(args);
        let reason = format!("{tool} 需要用户确认");
        let expires_at_ms = now_ms().saturating_add(self.approval_timeout.as_millis() as u64);
        // 单调截止点：超大超时无法表示时 fail-closed（立即视为过期）。
        let deadline = Instant::now().checked_add(self.approval_timeout);
        let entry = Pending {
            session_id: session_id.to_string(),
            slot: Arc::new(Slot::new(deadline)),
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id, entry);
        }
        ApprovalRequest {
            id,
            session_id: session_id.to_string(),
            tool_name: tool.to_string(),
            summary,
            reason,
            expires_at_ms,
        }
    }

    /// 某会话仍未应答的审批 id（升序）。
    pub fn list_pending(&self, session_id: &str) -> Vec<Uuid> {
        let Ok(pending) = self.pending.lock() else {
            return Vec::new();
        };
        let mut ids: Vec<Uuid> = pending
            .iter()
            .filter(|(_, entry)| entry.session_id == session_id && !entry.slot.answered())
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// 应答审批（一次性）。
    pub fn respond(&self, id: Uuid, approved: bool) -> Result<ApprovalOutcome, CoreError> {
        let slot = {
            let pending = self
                .pending
                .lock()
                .map_err(|_| CoreError::InvalidConfig("审批锁毒化".into()))?;
            let Some(entry) = pending.get(&id) else {
                return Err(CoreError::ApprovalNotFound(id));
            };
            Arc::clone(&entry.slot)
        };
        let requested = ApprovalOutcome {
            approved,
            timed_out: false,
        };
        let outcome = {
            let mut state = slot
                .state
                .lock()
                .map_err(|_| CoreError::InvalidConfig("审批槽锁毒化".into()))?;
            if state.answered {
                return Err(CoreError::ApprovalAnswered(id));
            }
            state.answered = true;
            // 晚于截止点的应答不得批准：落为过期 deny，仍占掉一次性应答位。
            let final_outcome = if slot.expired() {
                ApprovalOutcome {
                    approved: false,
                    timed_out: true,
                }
            } else {
                requested
            };
            state.outcome = Some(final_outcome);
            final_outcome
        };
        slot.changed.notify_all();
        Ok(outcome)
    }

    /// 等待审批结果，带超时；超时按 deny 语义返回并清理挂起项。
    pub fn wait(&self, id: Uuid, timeout: Duration) -> Result<ApprovalOutcome, CoreError> {
        let slot = {
            let pending = self
                .pending
                .lock()
                .map_err(|_| CoreError::InvalidConfig("审批锁毒化".into()))?;
            let Some(entry) = pending.get(&id) else {
                return Err(CoreError::ApprovalNotFound(id));
            };
            Arc::clone(&entry.slot)
        };
        // 等待上限取「调用方 timeout」与「创建时截止点剩余」的较短值；
        // 加法溢出时 fail-closed（按已到期处理，立即 deny）。
        let budget = timeout.min(slot.remaining());
        let deadline = Instant::now()
            .checked_add(budget)
            .unwrap_or_else(Instant::now);
        let mut guard = slot
            .state
            .lock()
            .map_err(|_| CoreError::InvalidConfig("审批槽锁毒化".into()))?;
        loop {
            if let Some(outcome) = guard.outcome.take() {
                drop(guard);
                self.forget(id);
                return Ok(outcome);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(guard);
                self.forget(id);
                return Ok(ApprovalOutcome {
                    approved: false,
                    timed_out: true,
                });
            }
            let (next, _wait_result) = slot
                .changed
                .wait_timeout(guard, remaining)
                .map_err(|_| CoreError::InvalidConfig("审批条件变量毒化".into()))?;
            guard = next;
        }
    }

    /// 挂起审批总数（观测用）。
    pub fn pending_count(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or_default()
    }

    fn forget(&self, id: Uuid) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&id);
        }
    }
}
