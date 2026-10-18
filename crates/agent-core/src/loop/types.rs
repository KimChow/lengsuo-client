//! Agent loop 的公开词汇：熔断配置、终止状态、回合产物与宿主 trait 契约。

use serde_json::Value;

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
