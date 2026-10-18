//! 会话流状态的协议域类型：模式、消息四类、工具引用、审批值与相位枚举。
//!
//! 这些类型只描述数据与协议名映射，不含状态迁移逻辑（迁移见
//! [`super::SessionStreamState`] 与 [`super::events`]）。

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
