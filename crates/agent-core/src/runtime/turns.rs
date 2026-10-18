//! 回合执行：send_text、run_turn、工具调用/结果记录与 check_tool。

use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::CoreError;
use crate::permission::Decision;
use crate::provider::ProviderStep;
use crate::schema::{Message, Role, Session, SessionStatus, ToolInfo};

use super::{narrow, now_ms, Runtime, TurnReceipt, CONTENT_PREVIEW_CHARS};

impl Runtime {
    /// 发送一条用户输入，跑一个回合（echo provider 下即回显）。
    pub fn send_text(&self, id: Uuid, text: &str) -> Result<TurnReceipt, CoreError> {
        // 先取本轮之前的历史快照：送入 Provider 的 history 必然不含本轮输入。
        let history = self.get_session(id)?.messages;
        self.push_message(id, Role::User, text.to_string(), None)?;
        self.run_turn(id, text, &history)
    }

    fn run_turn(
        &self,
        id: Uuid,
        text: &str,
        history: &[Message],
    ) -> Result<TurnReceipt, CoreError> {
        let session = self.get_session(id)?;
        if matches!(session.status, SessionStatus::Done | SessionStatus::Failed) {
            return Err(CoreError::SessionClosed(id));
        }
        let mut events = Vec::new();
        let context = self.build_turn_context(&session, history, text);
        let steps = self.provider.next_steps_with_context(&context)?;
        for step in steps {
            match step {
                ProviderStep::Thinking(note) => {
                    events.push(self.emit(
                        &session,
                        "thinking",
                        json!({ "text": self.redact(&note) }),
                    )?);
                }
                ProviderStep::Text(reply) => {
                    let reply = self.redact(&reply);
                    events.push(self.emit(&session, "text", json!({ "text": reply }))?);
                    self.push_message(id, Role::Assistant, reply, None)?;
                }
                ProviderStep::ToolCall { name, args } => {
                    let args = self.redactor.redact_json(&args);
                    events.push(self.emit(
                        &session,
                        "tool_use",
                        json!({ "name": name, "args": args }),
                    )?);
                }
                ProviderStep::Finished => {
                    events.push(self.emit(&session, "done", json!({}))?);
                }
            }
        }
        let current = self.get_session(id)?;
        let last_seq = current.last_seq;
        Ok(TurnReceipt {
            session_id: id,
            events,
            last_seq,
        })
    }

    /// 记录一次工具结果：大输出进 blob，消息只留摘要（§3 防分页打爆）。
    pub fn record_tool_result(
        &self,
        id: Uuid,
        tool: &str,
        args: Value,
        result: &str,
    ) -> Result<Message, CoreError> {
        let args = self.redactor.redact_json(&args);
        let args_ref = self
            .blobs
            .put(args.to_string().as_bytes())
            .map(|r| r.0)
            .ok();
        let raw = self.redactor.redact_str(result);
        let (preview, result_ref) = if raw.chars().count() > CONTENT_PREVIEW_CHARS {
            let blob = self.blobs.put(raw.as_bytes())?;
            (narrow(&raw, CONTENT_PREVIEW_CHARS), Some(blob.0))
        } else {
            (raw.clone(), None)
        };
        let message = Message {
            role: Role::ToolResult,
            content: preview.clone(),
            tool: Some(ToolInfo {
                name: tool.to_string(),
                args_ref,
                result_ref: result_ref.clone(),
                ms: None,
            }),
            ts_ms: now_ms(),
        };
        let session = self.push_message(
            id,
            Role::ToolResult,
            preview,
            Some(message.tool.clone().expect("刚构造")),
        )?;
        self.emit(
            &session,
            "tool_result",
            json!({ "name": tool, "chars": raw.chars().count(), "resultRef": result_ref, "preview": message.content }),
        )?;
        Ok(message)
    }

    /// 追加工具调用消息（权限门放行后由宿主调用）。
    pub fn record_tool_call(
        &self,
        id: Uuid,
        tool: &str,
        args: &Value,
    ) -> Result<Session, CoreError> {
        let args = self.redactor.redact_json(args);
        let args_ref = self
            .blobs
            .put(args.to_string().as_bytes())
            .map(|r| r.0)
            .ok();
        let summary = self.redactor.summarize_args(&args);
        self.push_message(
            id,
            Role::ToolCall,
            summary,
            Some(ToolInfo {
                name: tool.to_string(),
                args_ref,
                result_ref: None,
                ms: None,
            }),
        )
    }

    /// 权限判定（工具执行前的唯一入口）。
    pub fn check_tool(&self, id: Uuid, tool: &str, args: &Value) -> Result<Decision, CoreError> {
        let session = self.get_session(id)?;
        if matches!(session.status, SessionStatus::Done | SessionStatus::Failed) {
            return Err(CoreError::SessionClosed(id));
        }
        Ok(self
            .gate
            .check(session.mode, session.permission_mode, tool, args))
    }
}
