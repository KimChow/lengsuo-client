//! 回合执行：send_text（单队列投递）、run_turn（步驱循环）、工具调用/结果记录与 check_tool。
//!
//! 步语义：一步 = 一次逻辑 LLM 调用。
//! - 每步只发一次 provider 调用；步在**首个工具调用**处终结，同批尾随的文本/结束项
//!   不在本步内存里续消费，由重读历史后的新一步重新产出；
//! - 工具调用先落进会话历史，本步随即以「待宿主执行」结果结算；下一步**重读会话历史**
//!   （ToolCall 与 ToolResult 成对在列）后再发起新的一次调用；
//! - 运行时不含工具执行器：真实结果由宿主经 [`Runtime::record_tool_result`] 回填；
//! - 步数达上限仍未收敛 ⇒ 以 `done{status:"max_steps_reached"}` 收口（沿用既有熔断事件形状）。

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::CoreError;
use crate::permission::Decision;
use crate::provider::ProviderStep;
use crate::r#loop::DEFAULT_MAX_STEPS;
use crate::schema::{Event, Message, Role, Session, SessionStatus, ToolInfo};

use super::{narrow, now_ms, Runtime, TurnReceipt, CONTENT_PREVIEW_CHARS};

/// 单回合步数上限（一步 = 一次逻辑 LLM 调用）；复用 agent loop 的熔断阈值，不另造。
const MAX_TURN_STEPS: usize = DEFAULT_MAX_STEPS;

/// 工具步的占位结算结果：运行时无执行器，先把「待宿主执行」写进历史，
/// 使续步重读到的历史里 ToolCall/ToolResult 成对；真实结果由宿主回填。
const PENDING_TOOL_RESULT: &str =
    r#"{"status":"pending","note":"工具调用已持久化，执行由宿主承担"}"#;

impl Runtime {
    /// 发送一条用户输入，跑一个回合（echo provider 下即回显）。
    ///
    /// 单队列投递：同一会话的回合串行执行；后到的输入在回合之外排队，
    /// 不插入进行中的步驱循环。
    pub fn send_text(&self, id: Uuid, text: &str) -> Result<TurnReceipt, CoreError> {
        let drain = self.drain_lock(id)?;
        let _queued = drain.lock().expect("会话投递锁不得毒化");
        // 首步 history 取本轮输入推入之前的快照（本轮输入只作为 user_text 出现）。
        let history = self.get_session(id)?.messages;
        self.push_message(id, Role::User, text.to_string(), None)?;
        self.run_turn(id, text, &history)
    }

    /// 取会话投递锁（同一会话的回合据此串行，不穿插步边界）。
    fn drain_lock(&self, id: Uuid) -> Result<Arc<Mutex<()>>, CoreError> {
        let guard = self.sessions.lock().expect("会话表锁不得毒化");
        guard
            .get(&id)
            .map(|hot| Arc::clone(&hot.drain))
            .ok_or(CoreError::SessionNotFound(id))
    }

    /// 步驱循环：一步一次调用；工具步结算后重读历史开新步；到限熔断收口。
    fn run_turn(
        &self,
        id: Uuid,
        text: &str,
        history: &[Message],
    ) -> Result<TurnReceipt, CoreError> {
        let mut events: Vec<Event> = Vec::new();
        // 首步用「回合前历史 + 本轮输入」；续步重读会话历史（本轮输入已在其中）。
        let mut pre_turn = Some(history.to_vec());
        let mut steps = 0usize;

        loop {
            let session = self.get_session(id)?;
            if matches!(session.status, SessionStatus::Done | SessionStatus::Failed) {
                return Err(CoreError::SessionClosed(id));
            }
            let (step_history, user_text) = match pre_turn.take() {
                Some(pre) => (pre, text),
                None => (session.messages.clone(), ""),
            };
            let context = self.build_turn_context(&session, &step_history, user_text);
            let batch = self.provider.next_steps_with_context(&context)?;
            steps += 1;

            let Some((name, args)) = self.consume_step(id, &session, batch, &mut events)? else {
                // 本步无工具调用 ⇒ 回合收敛。
                events.push(self.emit(
                    &session,
                    "done",
                    json!({ "status": "completed", "steps": steps }),
                )?);
                break;
            };

            // 工具步：调用先持久化，再以占位结果结算本步，下一步重读历史。
            self.record_tool_call(id, &name, &args)?;
            let args = self.redactor.redact_json(&args);
            events.push(self.emit(
                &session,
                "tool_use",
                json!({ "name": name.clone(), "args": args.clone() }),
            )?);
            self.push_tool_result(id, &name, args, PENDING_TOOL_RESULT)?;

            if steps >= MAX_TURN_STEPS {
                events.push(self.emit(
                    &session,
                    "done",
                    json!({
                        "status": "max_steps_reached",
                        "steps": steps,
                        "maxSteps": MAX_TURN_STEPS,
                    }),
                )?);
                break;
            }
        }

        let current = self.get_session(id)?;
        Ok(TurnReceipt {
            session_id: id,
            events,
            last_seq: current.last_seq,
        })
    }

    /// 消费一步的产出：逐条落事件，遇工具调用或结束即止（批内尾随项属新一步）。
    /// 返回本步终结处的工具调用；`None` 表示本步无工具调用 ⇒ 回合收敛。
    fn consume_step(
        &self,
        id: Uuid,
        session: &Session,
        batch: Vec<ProviderStep>,
        events: &mut Vec<Event>,
    ) -> Result<Option<(String, Value)>, CoreError> {
        for item in batch {
            match item {
                ProviderStep::Thinking(note) => {
                    events.push(self.emit(
                        session,
                        "thinking",
                        json!({ "text": self.redact(&note) }),
                    )?);
                }
                ProviderStep::Text(reply) => {
                    let reply = self.redact(&reply);
                    events.push(self.emit(session, "text", json!({ "text": reply }))?);
                    self.push_message(id, Role::Assistant, reply, None)?;
                }
                // 本步止于首个工具调用；同批尾随项不在此消费。
                ProviderStep::ToolCall { name, args } => return Ok(Some((name, args))),
                ProviderStep::Finished => return Ok(None),
            }
        }
        Ok(None)
    }

    /// 把工具结果写进会话历史（大输出进 blob，消息只留摘要），不落事件。
    ///
    /// 事件流里的 `tool_result` 只由真实结果（宿主经 [`Runtime::record_tool_result`]
    /// 回填）产生；工具步的占位结算不冒充真实结果。
    fn push_tool_result(
        &self,
        id: Uuid,
        tool: &str,
        args: Value,
        result: &str,
    ) -> Result<(Message, Value), CoreError> {
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
        let tool_info = ToolInfo {
            name: tool.to_string(),
            args_ref,
            result_ref: result_ref.clone(),
            ms: None,
        };
        let message = Message {
            role: Role::ToolResult,
            content: preview.clone(),
            tool: Some(tool_info.clone()),
            ts_ms: now_ms(),
        };
        self.push_message(id, Role::ToolResult, preview, Some(tool_info))?;
        let payload = json!({
            "name": tool,
            "chars": raw.chars().count(),
            "resultRef": result_ref,
            "preview": message.content,
        });
        Ok((message, payload))
    }

    /// 记录一次工具结果：大输出进 blob，消息只留摘要（§3 防分页打爆）。
    pub fn record_tool_result(
        &self,
        id: Uuid,
        tool: &str,
        args: Value,
        result: &str,
    ) -> Result<Message, CoreError> {
        let (message, payload) = self.push_tool_result(id, tool, args, result)?;
        let session = self.get_session(id)?;
        self.emit(&session, "tool_result", payload)?;
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
