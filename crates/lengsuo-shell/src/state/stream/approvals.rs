//! 审批区状态：至多一条挂起（串行审批语义）+ 按 id 保存的历史结论。

use std::collections::BTreeMap;

use super::{ApprovalDecision, PendingApproval};

/// 审批的历史结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Resolved {
    pub(super) decision: ApprovalDecision,
    pub(super) at_ms: u64,
    /// 是否由超时自动落为 deny。
    pub(super) by_timeout: bool,
}

/// 审批区状态：至多一条挂起（协议 §4 的串行审批语义），历史按 id 保存。
#[derive(Debug, Clone, Default)]
pub struct ApprovalState {
    pub(super) pending: Option<PendingApproval>,
    pub(super) resolved: BTreeMap<String, Resolved>,
}

impl ApprovalState {
    /// 当前挂起的审批。
    #[must_use]
    pub fn pending(&self) -> Option<&PendingApproval> {
        self.pending.as_ref()
    }

    /// 某个审批的结论（若已作出）。
    #[must_use]
    pub fn decision_of(&self, id: &str) -> Option<ApprovalDecision> {
        self.resolved.get(id).map(|r| r.decision)
    }

    /// 已记录的审批数量（挂起 + 历史）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.resolved.len() + usize::from(self.pending.is_some())
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
