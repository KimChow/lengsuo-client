//! 八步回合驱动：消息历史构建、chat 调用、工具请求分发、完成判定与熔断。

use std::collections::BTreeSet;

use serde_json::json;

use crate::schema::{EventKind, Mode};

use super::guard::CallOutcome;
use super::support::tool_result;
use super::types::{LoopOutcome, LoopStatus};
use super::AgentLoop;

/// 交付物意图关键词（卡面冻结：创建/写入/修改）。
const DELIVERABLE_KEYWORDS: [&str; 3] = ["创建", "写入", "修改"];

impl<'a> AgentLoop<'a> {
    /// 跑一个完整回合序列。
    pub fn run(&mut self, user_input: &str) -> Result<LoopOutcome, String> {
        let mut messages = vec![
            json!({
                "role": "system",
                "content": format!("{}\n\n{}", self.policy.template, crate::mode::HARD_RULES),
            }),
            json!({ "role": "user", "content": user_input }),
        ];
        let mut tool_defs = self.tool_defs();
        let mut steps = 0usize;
        let mut final_text = String::new();
        let mut denied_tools: BTreeSet<String> = BTreeSet::new();

        loop {
            if steps >= self.limits.max_steps {
                self.emit(
                    EventKind::Done.as_str(),
                    json!({
                        "status": "max_steps_reached",
                        "steps": steps,
                        "maxSteps": self.limits.max_steps,
                    }),
                );
                return Ok(LoopOutcome {
                    status: LoopStatus::MaxStepsReached,
                    steps,
                    final_text,
                });
            }
            let turn = self.provider.chat(&messages, &tool_defs)?;
            steps += 1;
            if !turn.text.is_empty() {
                self.emit(EventKind::Text.as_str(), json!({"text": turn.text}));
                final_text = turn.text.clone();
            }
            messages.push(json!({"role": "assistant", "content": turn.text}));

            if turn.tool_calls.is_empty() {
                if self.needs_reminder(user_input) {
                    self.reminder_used = true;
                    let note = "尚未调用任何写/执行工具：请实际执行并给出交付物，不要声称已完成。";
                    self.emit(EventKind::Thinking.as_str(), json!({"reminder": note}));
                    messages.push(json!({"role": "user", "content": note}));
                    continue;
                }
                self.emit(
                    EventKind::Done.as_str(),
                    json!({
                        "status": "completed",
                        "steps": steps,
                    }),
                );
                return Ok(LoopOutcome {
                    status: LoopStatus::Completed,
                    steps,
                    final_text,
                });
            }

            for call in &turn.tool_calls {
                self.emit(
                    EventKind::ToolUse.as_str(),
                    json!({"id": call.id, "name": call.name, "args": call.args}),
                );
                let outcome = self.handle_call(call, &mut denied_tools)?;
                match outcome {
                    CallOutcome::Aborted(reason) => {
                        let denied = json!({"status": "denied", "reason": reason});
                        messages.push(tool_result(&call.id, &call.name, &denied, true));
                        self.emit(
                            EventKind::ToolResult.as_str(),
                            json!({"id": call.id, "name": call.name, "result": denied, "isError": true}),
                        );
                        self.emit(
                            EventKind::Done.as_str(),
                            json!({
                                "status": "aborted",
                                "steps": steps,
                                "tool": call.name,
                            }),
                        );
                        return Ok(LoopOutcome {
                            status: LoopStatus::Aborted,
                            steps,
                            final_text,
                        });
                    }
                    CallOutcome::FatalDenied => {
                        self.emit(
                            EventKind::Done.as_str(),
                            json!({
                                "status": "denied",
                                "steps": steps,
                                "tool": call.name,
                            }),
                        );
                        return Ok(LoopOutcome {
                            status: LoopStatus::Denied {
                                tool: call.name.clone(),
                            },
                            steps,
                            final_text,
                        });
                    }
                    CallOutcome::Handled { result, is_error } => {
                        messages.push(tool_result(&call.id, &call.name, &result, is_error));
                        self.emit(
                            EventKind::ToolResult.as_str(),
                            json!({"id": call.id, "name": call.name, "result": result, "isError": is_error}),
                        );
                    }
                }
            }
            // 门禁/白名单可能在 `plan.enter` / `plan.exit` 后变化：重建可见工具面。
            tool_defs = self.tool_defs();
        }
    }

    /// 交付物提醒：仅 Craft/Expert、任务文本含写意图、且从未成功调用写/执行工具。
    fn needs_reminder(&self, user_input: &str) -> bool {
        !self.reminder_used
            && !self.write_called
            && matches!(self.mode, Mode::Craft | Mode::Expert)
            && DELIVERABLE_KEYWORDS.iter().any(|k| user_input.contains(k))
    }
}
