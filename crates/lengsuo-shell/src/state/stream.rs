//! 单会话消息流状态：事件追加 + 审批挂起/应答 + 模式切换的相位机。
//!
//! 语义来源：
//! - 消息四类与「历史重放不重跑工具」（AGENT-KICKOFF.md §3、参照平台基线）。
//! - 审批默认 120s 超时 → deny（§4）；UI 只能提交 allow/deny。
//! - `seq` 是会话内单调递增的分页回溯锚点（§3 N12）：序号断裂必须显式报错，
//!   由上层触发全量重放，本层不猜测缺失事件。

use std::collections::BTreeMap;

use crate::gateway::{EventKind, GatewayEvent};

use super::StateError;

/// 会话模式（协议 §3 的 5 个名字）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// 快问快答：无工具。
    Quick,
    /// 只读问答。
    Ask,
    /// 先出计划。
    Plan,
    /// 允许工具执行。
    Craft,
    /// 全权限（仍受网关权限门约束）。
    Expert,
}

impl SessionMode {
    /// 解析协议名；未知值返回 `None`（不猜测）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "quick" => Some(Self::Quick),
            "ask" => Some(Self::Ask),
            "plan" => Some(Self::Plan),
            "craft" => Some(Self::Craft),
            "expert" => Some(Self::Expert),
            _ => None,
        }
    }

    /// 协议名。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Ask => "ask",
            Self::Plan => "plan",
            Self::Craft => "craft",
            Self::Expert => "expert",
        }
    }

    /// 该模式在 UI 侧是否允许出现工具消息。`quick` 无工具（§4），其它模式由
    /// 网关权限门决定是否真的执行；这里只保证 UI 不会显示与模式矛盾的内容。
    #[must_use]
    pub fn tools_visible(self) -> bool {
        !matches!(self, Self::Quick)
    }
}

/// 消息角色（协议 §3 四类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    /// 用户输入。
    User,
    /// 助手正文（含 thinking 增量合并后的文本，见 `thinking` 标记）。
    Assistant,
    /// 工具调用。
    ToolCall,
    /// 工具结果。
    ToolResult,
}

/// 工具引用信息：大结果只存引用，不进 `content`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRef {
    /// 工具名。
    pub name: String,
    /// 参数引用（可为 `None`，例如无参工具）。
    pub args_ref: Option<String>,
    /// 结果引用（`tool_result` 之后才有）。
    pub result_ref: Option<String>,
    /// 耗时（毫秒）。
    pub ms: u64,
}

/// 一条消息。`thinking` 与正文分开保存，UI 可自行折叠（脱敏已由网关侧完成）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMessage {
    /// 角色。
    pub role: MessageRole,
    /// 正文（小字段；大结果走 `tool.result_ref`）。
    pub content: String,
    /// 工具信息，仅 `ToolCall`/`ToolResult` 有。
    pub tool: Option<ToolRef>,
    /// 事件时间戳（毫秒）。
    pub ts_ms: u64,
    /// 是否为思考增量合并而来。
    pub thinking: bool,
}

/// UI 可提交的审批结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// 放行。
    Allow,
    /// 拒绝。
    Deny,
}

impl ApprovalDecision {
    /// 协议字符串。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// 挂起中的审批。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    /// 审批 id。
    pub id: String,
    /// 触发的工具名。
    pub tool: String,
    /// 展示给用户的理由（网关已脱敏）。
    pub reason: String,
    /// 请求时间戳（毫秒），用于 UI 倒计时与超时判定。
    pub requested_at_ms: u64,
}

/// 审批的历史结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resolved {
    decision: ApprovalDecision,
    at_ms: u64,
    /// 是否由超时自动落为 deny。
    by_timeout: bool,
}

/// 审批区状态：至多一条挂起（协议 §4 的串行审批语义），历史按 id 保存。
#[derive(Debug, Clone, Default)]
pub struct ApprovalState {
    pending: Option<PendingApproval>,
    resolved: BTreeMap<String, Resolved>,
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

/// 消息流相位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPhase {
    /// 空闲：等待用户输入。
    Idle,
    /// 运行中：正在接收增量。
    Running,
    /// 等待审批：挂起在 `approval_request`。
    AwaitingApproval,
    /// 本轮结束（收到 `done`）。
    Finished,
    /// 失败（网关显式告知或序号断裂后未恢复）。
    Failed,
}

impl StreamPhase {
    /// 终态相位：不再接受事件与追加。
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Finished | Self::Failed)
    }
}

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

/// 协议 §4 冻结的默认审批超时。
pub const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 120_000;

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

    /// 应用一条网关事件。序号断裂返回 [`StateError::SeqGap`] 且**不修改任何状态**，
    /// 上层据此发起全量重放。
    pub fn apply_event(&mut self, event: GatewayEvent) -> Result<(), StateError> {
        self.check_seq(event.seq)?;
        let outcome = self.route(&event);
        // 序号只在成功路由后推进，保证断裂时状态未被污染。
        self.last_seq = Some(event.seq);
        outcome
    }

    fn check_seq(&self, seq: u64) -> Result<(), StateError> {
        match self.last_seq {
            Some(last) if seq != last + 1 => Err(StateError::SeqGap {
                session: self.session_id.clone(),
                expected: last + 1,
                actual: seq,
            }),
            _ => Ok(()),
        }
    }

    fn route(&mut self, event: &GatewayEvent) -> Result<(), StateError> {
        if self.phase.is_terminal() {
            return Err(StateError::Sealed(self.session_id.clone()));
        }
        let text = extract_text(event);
        match event.kind {
            EventKind::Thinking => {
                self.push_or_merge(true, &text, event.ts_ms);
                self.phase = StreamPhase::Running;
                Ok(())
            }
            EventKind::Text => {
                self.push_or_merge(false, &text, event.ts_ms);
                self.phase = StreamPhase::Running;
                Ok(())
            }
            EventKind::ToolUse => {
                if !self.mode.tools_visible() {
                    return Err(StateError::InvalidTransition {
                        phase: format!("mode:{}", self.mode.as_str()),
                        action: "tool_use".to_string(),
                    });
                }
                let name = field_str(event, "name").unwrap_or_else(|| "unknown".to_string());
                self.messages.push(SessionMessage {
                    role: MessageRole::ToolCall,
                    content: text,
                    tool: Some(ToolRef {
                        name,
                        args_ref: field_str(event, "args_ref"),
                        result_ref: None,
                        ms: field_u64(event, "ms").unwrap_or(0),
                    }),
                    ts_ms: event.ts_ms,
                    thinking: false,
                });
                self.phase = StreamPhase::Running;
                Ok(())
            }
            EventKind::ToolResult => {
                if !self.mode.tools_visible() {
                    return Err(StateError::InvalidTransition {
                        phase: format!("mode:{}", self.mode.as_str()),
                        action: "tool_result".to_string(),
                    });
                }
                self.messages.push(SessionMessage {
                    role: MessageRole::ToolResult,
                    content: text,
                    tool: Some(ToolRef {
                        name: field_str(event, "name").unwrap_or_else(|| "unknown".to_string()),
                        args_ref: None,
                        result_ref: field_str(event, "result_ref"),
                        ms: field_u64(event, "ms").unwrap_or(0),
                    }),
                    ts_ms: event.ts_ms,
                    thinking: false,
                });
                Ok(())
            }
            EventKind::ApprovalRequest => {
                let id = field_str(event, "approval_id")
                    .or_else(|| field_str(event, "id"))
                    .ok_or_else(|| StateError::InvalidTransition {
                        phase: "approval_request".to_string(),
                        action: "缺少 approval_id".to_string(),
                    })?;
                if self.approvals.pending.is_some() {
                    // v0 串行审批：同时挂两条属于协议违规，拒绝而不是排队猜测。
                    return Err(StateError::InvalidTransition {
                        phase: "awaiting_approval".to_string(),
                        action: "第二个 approval_request".to_string(),
                    });
                }
                self.approvals.pending = Some(PendingApproval {
                    id,
                    tool: field_str(event, "name").unwrap_or_else(|| "unknown".to_string()),
                    reason: field_str(event, "reason").unwrap_or_default(),
                    requested_at_ms: event.ts_ms,
                });
                self.phase = StreamPhase::AwaitingApproval;
                Ok(())
            }
            EventKind::Files => {
                // 文件产出以引用呈现，内容不进状态（协议 §3）。
                self.messages.push(SessionMessage {
                    role: MessageRole::Assistant,
                    content: text,
                    tool: None,
                    ts_ms: event.ts_ms,
                    thinking: false,
                });
                Ok(())
            }
            EventKind::Done => {
                self.approvals.pending = None;
                self.phase = StreamPhase::Finished;
                Ok(())
            }
            EventKind::SessionUpdate => {
                if let Some(raw) = field_str(event, "mode") {
                    let mode =
                        SessionMode::parse(&raw).ok_or_else(|| StateError::InvalidTransition {
                            phase: "session_update".to_string(),
                            action: format!("未知模式 {raw}"),
                        })?;
                    self.mode = mode;
                }
                if field_str(event, "status").as_deref() == Some("failed") {
                    self.approvals.pending = None;
                    self.phase = StreamPhase::Failed;
                }
                Ok(())
            }
        }
    }

    /// 追加或合并增量：同角色 + 同 `thinking` 标记 + 相邻的最新消息会被合并，
    /// 使「一行一个 JSON」的细粒度增量不至于把列表打爆。
    fn push_or_merge(&mut self, thinking: bool, text: &str, ts_ms: u64) {
        if text.is_empty() {
            return;
        }
        if let Some(last) = self.messages.last_mut() {
            if last.role == MessageRole::Assistant
                && last.tool.is_none()
                && last.thinking == thinking
            {
                last.content.push_str(text);
                last.ts_ms = ts_ms;
                return;
            }
        }
        self.messages.push(SessionMessage {
            role: MessageRole::Assistant,
            content: text.to_string(),
            tool: None,
            ts_ms,
            thinking,
        });
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

/// 事件文本：优先 `text`，其次 `content`，都没有则为空。
fn extract_text(event: &GatewayEvent) -> String {
    field_str(event, "text")
        .or_else(|| field_str(event, "content"))
        .unwrap_or_default()
}

/// 从 `payload` 取字符串字段。
fn field_str(event: &GatewayEvent, key: &str) -> Option<String> {
    event
        .payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// 从 `payload` 取整数字段。
fn field_u64(event: &GatewayEvent, key: &str) -> Option<u64> {
    event.payload.get(key).and_then(serde_json::Value::as_u64)
}
