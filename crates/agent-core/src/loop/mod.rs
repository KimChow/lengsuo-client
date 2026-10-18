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
//!
//! 按职责拆分：`types`（公开词汇与 trait 契约）、`run`（八步回合驱动）、
//! `guard`（白名单与规划门禁处理）、`support`（共用小工具）。

mod guard;
mod run;
mod support;
mod types;

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::mode::ModePolicy;
use crate::schema::{Event, Mode};

pub use types::{
    ChatProvider, ChatTurn, LoopLimits, LoopOutcome, LoopStatus, PlanGate, ToolCall, ToolExecutor,
    DEFAULT_MAX_STEPS,
};

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
}
