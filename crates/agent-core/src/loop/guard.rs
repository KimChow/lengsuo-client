//! 单工具请求的门禁处理：白名单 + 规划态拒绝 + plan.enter/plan.exit + 执行分发。

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::mode::ModePolicy;
use crate::schema::{EventKind, Mode};

use super::support::is_write_tool;
use super::types::ToolCall;
use super::AgentLoop;

/// 工具请求的三种处理结果。
pub(super) enum CallOutcome {
    /// 已产生回填结果。
    Handled { result: Value, is_error: bool },
    /// 规划未获批准 ⇒ 终止。
    Aborted(String),
    /// 同一工具重复被拒 ⇒ 终止。
    FatalDenied,
}

impl<'a> AgentLoop<'a> {
    /// 单工具请求：白名单 + 规划门禁 + 执行。
    pub(super) fn handle_call(
        &mut self,
        call: &ToolCall,
        denied: &mut BTreeSet<String>,
    ) -> Result<CallOutcome, String> {
        if let Some(reason) = self.refusal(&call.name) {
            // 同一工具被拒后再次请求 ⇒ 终止，避免空转。
            if denied.contains(&call.name) {
                return Ok(CallOutcome::FatalDenied);
            }
            denied.insert(call.name.clone());
            return Ok(CallOutcome::Handled {
                result: json!({"status": "denied", "reason": reason}),
                is_error: true,
            });
        }
        if call.name == crate::mode::PLAN_ENTER {
            self.enter_plan();
            return Ok(CallOutcome::Handled {
                result: json!({"status": "planning", "mode": self.mode.as_str()}),
                is_error: false,
            });
        }
        if call.name == crate::mode::PLAN_EXIT {
            let approved = call
                .args
                .get("approved")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            self.plan_gate.approved = approved;
            if !approved {
                return Ok(CallOutcome::Aborted(
                    "plan.exit approved=false：规划未获批准，本次执行终止".to_string(),
                ));
            }
            self.exit_plan_to_craft();
            return Ok(CallOutcome::Handled {
                result: json!({"status": "approved", "mode": self.mode.as_str()}),
                is_error: false,
            });
        }
        match self.executor.execute(&call.name, &call.args) {
            Ok(value) => {
                if is_write_tool(&call.name) {
                    self.write_called = true;
                }
                Ok(CallOutcome::Handled {
                    result: value,
                    is_error: false,
                })
            }
            Err(message) => Ok(CallOutcome::Handled {
                result: json!({"status": "error", "message": message}),
                is_error: true,
            }),
        }
    }

    /// 拒绝原因：`None` 表示允许执行。
    fn refusal(&self, tool: &str) -> Option<String> {
        if !self.policy.allows(tool) {
            return Some(format!(
                "{tool} 不在 {} 模式白名单（未执行）",
                self.mode.as_str()
            ));
        }
        if self.plan_gate.active && is_write_tool(tool) {
            return Some(format!(
                "规划态拒绝写/执行类工具: {tool}（需 plan.exit 批准）"
            ));
        }
        None
    }

    /// 显式进入规划态（Expert 可用；Plan 模式本已 active）。
    fn enter_plan(&mut self) {
        self.plan_gate.active = true;
        self.plan_gate.approved = false;
        if self.mode != Mode::Plan {
            self.set_mode(Mode::Plan);
        }
    }

    /// 批准后退出规划态并切 Craft 继续。
    fn exit_plan_to_craft(&mut self) {
        self.plan_gate.active = false;
        if self.mode != Mode::Craft {
            self.set_mode(Mode::Craft);
        }
    }

    fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.policy = ModePolicy::of(mode);
        self.emit(
            EventKind::SessionUpdate.as_str(),
            json!({
                "mode": mode.as_str(),
                "planActive": self.plan_gate.active,
                "planApproved": self.plan_gate.approved,
            }),
        );
    }
}
