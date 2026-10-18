//! Agent loop v0（波次 1 卡 3）：参照平台 8 步回合 + 五模式白名单 + Plan 门禁 + maxSteps 熔断。
//!
//! 回合骨架（对应卡面 8 步）：
//! 1. 理解：Quick/Ask 之外才带工具面；系统消息 = 模式模板 + 全模式硬规则；
//! 2. chat：调 [`ChatProvider::chat`] 取回文本与工具请求（v0 同步整段文本，流式由网关侧切分）；
//! 3. 选工具：按 [`crate::mode::mode_policy`] 白名单过滤，白名单外**不执行**，直接回填 `denied` 结果；
//! 4. 权限门：调用方（网关/宿主）已做，本层不重复判定；
//! 5. 执行：[`ToolExecutor::execute`] → 结果回填消息；
//! 6. 观察：结果进入消息历史后继续下一回合；
//! 7. 完成：某回合**无工具请求**即完成；Craft/Expert 若从未调用任何写/执行工具而任务文本含
//!    创建/写入/修改意图，追加一次提醒回合（整个 run 最多一次）；
//! 8. 最终回复：`LoopOutcome.final_text` + `done` 事件。
//!
//! 门禁与熔断：
//! - `Plan` 模式进入即 `PlanGate { active: true }`；除 `plan.exit` 外写/执行类工具一律拒绝（回填不中断）；
//!   `plan.exit(approved = true)` 切到 Craft 继续，`approved = false` ⇒ [`LoopStatus::Aborted`]；
//! - `plan.enter` 用于非规划模式（Expert）显式进入规划态；
//! - 同一工具在被拒绝后再次请求 ⇒ [`LoopStatus::Denied`]（防对同一被拒工具空转）；
//! - 回合数达 `LoopLimits::max_steps` 仍未收敛 ⇒ [`LoopStatus::MaxStepsReached`]。
//!
//! 本卡不接真实工具与真实模型：trait 由宿主实现，`EchoProvider` 之外另有测试用 Mock。

use std::collections::BTreeSet;

use serde_json::{json, Value};
use uuid::Uuid;

use crate::mode::{ModePolicy, WRITE_TOOLS};
use crate::schema::{Event, EventKind, Mode};

/// 默认熔断回合数（卡面：maxSteps 默认 30）。
pub const DEFAULT_MAX_STEPS: usize = 30;

/// 回合熔断配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopLimits {
    /// 最多调用 provider 的回合数。
    pub max_steps: usize,
}

impl Default for LoopLimits {
    fn default() -> Self {
        Self {
            max_steps: DEFAULT_MAX_STEPS,
        }
    }
}

/// 回合终止状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopStatus {
    /// 某回合无工具请求 ⇒ 完成。
    Completed,
    /// 达 `max_steps` 仍未收敛。
    MaxStepsReached,
    /// 同一工具被拒绝后再次请求 ⇒ 终止（携带工具名）。
    Denied { tool: String },
    /// Plan 门禁未获批准（`plan.exit` 的 `approved != true`）。
    Aborted,
}

impl LoopStatus {
    /// 事件/日志用的短名。
    pub fn as_str(&self) -> &'static str {
        match self {
            LoopStatus::Completed => "completed",
            LoopStatus::MaxStepsReached => "max_steps_reached",
            LoopStatus::Denied { .. } => "denied",
            LoopStatus::Aborted => "aborted",
        }
    }
}

/// 一次 run 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopOutcome {
    /// 终止状态。
    pub status: LoopStatus,
    /// 实际消耗的回合数（provider 调用次数）。
    pub steps: usize,
    /// 最终文本（完成/熔断时为最后一个回合的文本）。
    pub final_text: String,
}

/// 一次工具请求。
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    /// provider 侧的调用 id（结果回填时对应）。
    pub id: String,
    /// 逻辑工具名。
    pub name: String,
    /// 参数。
    pub args: Value,
}

/// 一个回合的产出。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ChatTurn {
    /// 文本（可能为空）。
    pub text: String,
    /// 工具请求（空 ⇒ 本回合即完成）。
    pub tool_calls: Vec<ToolCall>,
}

/// 工具执行方（宿主实现；真实工具接 `agent-tools` 在合并期做）。
pub trait ToolExecutor {
    /// 执行逻辑工具，返回可序列化结果；`Err` 为执行失败说明。
    fn execute(&self, name: &str, args: &Value) -> Result<Value, String>;
}

/// 模型提供方（本层只看整段文本 + 工具请求；流式由上层切分）。
pub trait ChatProvider {
    /// 依据消息历史与当前可见工具产出下一回合。
    fn chat(&self, msgs: &[Value], tools: &[Value]) -> Result<ChatTurn, String>;
}

/// Plan 门禁状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlanGate {
    /// 是否处于规划态（规划态拒写/执行）。
    pub active: bool,
    /// 是否已获批准退出规划态。
    pub approved: bool,
}

/// 交付物意图关键词（卡面冻结：创建/写入/修改）。
const DELIVERABLE_KEYWORDS: [&str; 3] = ["创建", "写入", "修改"];

/// Agent loop。
pub struct AgentLoop<'a> {
    provider: &'a dyn ChatProvider,
    executor: &'a dyn ToolExecutor,
    mode: Mode,
    limits: LoopLimits,
    plan_gate: PlanGate,
    emit: &'a dyn Fn(Event),
    session_id: Uuid,
    seq: u64,
    policy: ModePolicy,
    /// 已成功执行过的写/执行类工具。
    write_called: bool,
    /// 提醒回合是否已用过（整个 run 最多一次）。
    reminder_used: bool,
}

impl<'a> AgentLoop<'a> {
    /// 组装：provider/executor 由宿主提供；`Plan` 模式进入即规划态。
    pub fn new(
        provider: &'a dyn ChatProvider,
        executor: &'a dyn ToolExecutor,
        mode: Mode,
        limits: LoopLimits,
        plan_gate: PlanGate,
        emit: &'a dyn Fn(Event),
    ) -> Self {
        let gate_active = mode == Mode::Plan || plan_gate.active;
        Self {
            provider,
            executor,
            mode,
            limits,
            plan_gate: PlanGate {
                active: gate_active,
                approved: plan_gate.approved,
            },
            emit,
            session_id: Uuid::nil(),
            seq: 0,
            policy: ModePolicy::of(mode),
            write_called: false,
            reminder_used: false,
        }
    }

    /// 设置事件归属的会话 id。
    #[must_use]
    pub fn session_id(mut self, id: Uuid) -> Self {
        self.session_id = id;
        self
    }

    /// 起始 seq（会话内事件续接锚点）。
    #[must_use]
    pub fn seq_base(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    /// 当前白名单。
    pub fn tools(&self) -> &BTreeSet<String> {
        &self.policy.tools
    }

    /// 当前门禁状态。
    pub fn plan_gate(&self) -> PlanGate {
        self.plan_gate
    }

    /// 当前模式（`plan.exit` 批准后切 Craft）。
    pub fn mode(&self) -> Mode {
        self.mode
    }

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

    /// 单工具请求：白名单 + 规划门禁 + 执行。
    fn handle_call(
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

    /// 交付物提醒：仅 Craft/Expert、任务文本含写意图、且从未成功调用写/执行工具。
    fn needs_reminder(&self, user_input: &str) -> bool {
        !self.reminder_used
            && !self.write_called
            && matches!(self.mode, Mode::Craft | Mode::Expert)
            && DELIVERABLE_KEYWORDS.iter().any(|k| user_input.contains(k))
    }

    fn tool_defs(&self) -> Vec<Value> {
        self.policy
            .tools
            .iter()
            .map(|name| json!({"name": name}))
            .collect()
    }

    /// 发一个事件（seq 会话内单调递增）。
    fn emit(&mut self, kind: &str, payload: Value) {
        self.seq += 1;
        (self.emit)(Event {
            seq: self.seq,
            session_id: self.session_id,
            kind: kind.to_string(),
            payload,
            ts_ms: now_ms(),
        });
    }
}

/// 工具请求的三种处理结果。
enum CallOutcome {
    /// 已产生回填结果。
    Handled { result: Value, is_error: bool },
    /// 规划未获批准 ⇒ 终止。
    Aborted(String),
    /// 同一工具重复被拒 ⇒ 终止。
    FatalDenied,
}

/// 写/执行类工具判定。
fn is_write_tool(name: &str) -> bool {
    WRITE_TOOLS.contains(&name)
}

/// 工具结果消息（大结果由宿主落盘为引用，本层只回填 JSON）。
fn tool_result(id: &str, name: &str, result: &Value, is_error: bool) -> Value {
    json!({
        "role": "tool_result",
        "content": result.to_string(),
        "tool": {"id": id, "name": name, "isError": is_error},
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}
