//! 单会话消息流状态：事件追加 + 审批挂起/应答 + 模式切换的相位机。
//!
//! 语义来源：
//! - 消息四类与「历史重放不重跑工具」（AGENT-KICKOFF.md §3、参考客户端 基线）。
//! - 审批默认 120s 超时 → deny（§4）；UI 只能提交 allow/deny。
//! - `seq` 是会话内单调递增的分页回溯锚点（§3 N12）：序号断裂必须显式报错，
//!   由上层触发全量重放，本层不猜测缺失事件。
//!
//! 按职责拆分：协议域类型在 `domain`，审批区在 `approvals`，网关事件路由在
//! `events`，事件载荷探测在 `payload`；本文件保留 [`SessionStreamState`] 本体、
//! 默认超时常量与命令接口，并用 `pub use` 保持 crate 内外引用路径不变。

mod approvals;
mod domain;
mod events;
mod payload;

pub use approvals::ApprovalState;
pub use domain::{
    ApprovalDecision, MessageRole, PendingApproval, SessionMessage, SessionMode, StreamPhase,
    ToolRef,
};

use self::approvals::Resolved;
use super::StateError;

/// 协议 §4 冻结的默认审批超时。
pub const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 120_000;

/// 单会话消息流状态。
#[derive(Debug, Clone)]
pub struct SessionStreamState {
    session_id: String,
    mode: SessionMode,
    phase: StreamPhase,
    last_seq: Option<u64>,
    messages: Vec<SessionMessage>,
    approvals: ApprovalState,
    /// 审批超时（毫秒），协议默认 120s。
    approval_timeout_ms: u64,
    /// 审批超时落定的 deny 记录（供 `take_timed_out` 触发一次 RPC）。
    timed_out: Vec<(String, u64)>,
}

impl SessionStreamState {
    /// 新建会话流状态。
    #[must_use]
    pub fn new(session_id: &str, mode: SessionMode) -> Self {
        Self {
            session_id: session_id.to_string(),
            mode,
            phase: StreamPhase::Idle,
            last_seq: None,
            messages: Vec::new(),
            approvals: ApprovalState::default(),
            approval_timeout_ms: DEFAULT_APPROVAL_TIMEOUT_MS,
            timed_out: Vec::new(),
        }
    }

    /// 覆盖审批超时（仅用于测试与将来的可配置场景；默认保持协议值）。
    #[must_use]
    pub fn with_approval_timeout_ms(mut self, ms: u64) -> Self {
        self.approval_timeout_ms = ms;
        self
    }

    /// 会话 id。
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 当前模式。
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    /// 当前相位。
    #[must_use]
    pub fn phase(&self) -> StreamPhase {
        self.phase
    }

    /// 已追加消息（UI 直接渲染这一份）。
    #[must_use]
    pub fn messages(&self) -> &[SessionMessage] {
        &self.messages
    }

    /// 审批区。
    #[must_use]
    pub fn approvals(&self) -> &ApprovalState {
        &self.approvals
    }

    /// 下一个期望序号（用于断点续传/重放锚点展示）。
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.last_seq.map(|s| s + 1).unwrap_or(0)
    }

    /// 用户提交输入：`Idle → Running`，并追加一条 user 消息。
    pub fn submit_user(&mut self, content: &str, ts_ms: u64) -> Result<(), StateError> {
        if self.phase.is_terminal() {
            return Err(StateError::Sealed(self.session_id.clone()));
        }
        if matches!(self.phase, StreamPhase::AwaitingApproval) {
            return Err(StateError::InvalidTransition {
                phase: "awaiting_approval".to_string(),
                action: "submit_user".to_string(),
            });
        }
        self.messages.push(SessionMessage {
            role: MessageRole::User,
            content: content.to_string(),
            tool: None,
            ts_ms,
            thinking: false,
        });
        self.phase = StreamPhase::Running;
        Ok(())
    }

    /// UI 提交审批结果：`AwaitingApproval → Running`。
    pub fn respond_approval(
        &mut self,
        id: &str,
        decision: ApprovalDecision,
        at_ms: u64,
    ) -> Result<(), StateError> {
        if self.phase.is_terminal() {
            return Err(StateError::Sealed(self.session_id.clone()));
        }
        match &self.approvals.pending {
            Some(pending) if pending.id == id => {}
            _ => return Err(StateError::UnknownApproval(id.to_string())),
        }
        let pending = self.approvals.pending.take().expect("上面已确认存在");
        self.approvals.resolved.insert(
            pending.id,
            Resolved {
                decision,
                at_ms,
                by_timeout: false,
            },
        );
        self.phase = StreamPhase::Running;
        Ok(())
    }

    /// 按当前时间把已超时的挂起审批落为 deny（deny-by-default）。
    /// 返回需要向网关补发 `approval:respond` 的 id 列表。
    pub fn sweep_approval_timeout(&mut self, now_ms: u64) -> Vec<String> {
        let Some(pending) = self.approvals.pending.as_ref() else {
            return Vec::new();
        };
        if now_ms.saturating_sub(pending.requested_at_ms) < self.approval_timeout_ms {
            return Vec::new();
        }
        let id = pending.id.clone();
        self.approvals.pending = None;
        self.approvals.resolved.insert(
            id.clone(),
            Resolved {
                decision: ApprovalDecision::Deny,
                at_ms: now_ms,
                by_timeout: true,
            },
        );
        if self.phase == StreamPhase::AwaitingApproval {
            self.phase = StreamPhase::Running;
        }
        self.timed_out.push((id.clone(), now_ms));
        vec![id]
    }

    /// 取走超时落定的审批（每个只上报一次）。
    pub fn take_timed_out(&mut self) -> Vec<(String, u64)> {
        std::mem::take(&mut self.timed_out)
    }

    /// 模式切换（`session_update` 之外的本地显式迁移）：
    /// 挂起审批期间禁止切换，避免审批语义与工具白名单错位。
    pub fn switch_mode(&mut self, mode: SessionMode) -> Result<(), StateError> {
        if self.approvals.pending.is_some() {
            return Err(StateError::InvalidTransition {
                phase: "awaiting_approval".to_string(),
                action: format!("switch_mode:{}", mode.as_str()),
            });
        }
        if self.phase.is_terminal() {
            return Err(StateError::Sealed(self.session_id.clone()));
        }
        self.mode = mode;
        Ok(())
    }

    /// 标记失败（RPC 侧错误或用户中断后网关确认失败）。
    pub fn fail(&mut self) {
        self.approvals.pending = None;
        self.phase = StreamPhase::Failed;
    }

    /// 全量重放准备：保留已显示消息，清除序号锚点，使下一次事件从任意 seq 重新对齐。
    pub fn reset_seq_anchor(&mut self) {
        self.last_seq = None;
    }
}
