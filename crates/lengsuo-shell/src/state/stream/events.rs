//! 网关事件 → 状态迁移：序号校验、按事件种类路由，以及增量合并。
//!
//! 原子性约束（[`SessionStreamState::apply_event`] 的文档）：被拒绝的事件
//! 不消费 `last_seq`、不留下任何状态痕迹，全部先校验后写入。

use crate::gateway::{EventKind, GatewayEvent};
use crate::state::StateError;

use super::payload::{
    extract_text, extract_tool_result_text, field_str, field_u64, tool_result_ref,
};
use super::{
    MessageRole, PendingApproval, SessionMessage, SessionMode, SessionStreamState, StreamPhase,
    ToolRef,
};

impl SessionStreamState {
    /// 应用一条网关事件。**被拒绝的事件不消费 `last_seq`、不留下任何状态痕迹**：
    /// - 序号断裂返回 [`StateError::SeqGap`]，锚点保持不动，上层据此发起全量重放；
    /// - 模式/相位不允许、载荷非法（缺 `approval_id`、未知 `mode`、重复挂起审批）、
    ///   终态之后的事件（[`StateError::Sealed`]）都在 [`Self::route`] 内**先校验后写入**，
    ///   因此失败时既不改消息/模式/相位/审批，也不推进 `last_seq`。
    ///
    /// 由此，同一 `seq` 被无效事件拒掉后，紧随的合法事件仍可成功应用；
    /// 合法的重复/断序冻结规则本身不变（仍是 `seq != last + 1` 即 `SeqGap`）。
    pub fn apply_event(&mut self, event: GatewayEvent) -> Result<(), StateError> {
        self.check_seq(event.seq)?;
        // 失败即返回：序号只在成功路由后推进，保证被拒事件零副作用。
        self.route(&event)?;
        self.last_seq = Some(event.seq);
        Ok(())
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
                    content: extract_tool_result_text(event, &text),
                    tool: Some(ToolRef {
                        name: field_str(event, "name").unwrap_or_else(|| "unknown".to_string()),
                        args_ref: None,
                        result_ref: tool_result_ref(event),
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
}
