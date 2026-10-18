//! ACP 核心方法的 params/result 类型（27 册 §2 方法面 + 18 册 B.*/V.* 双面）。
//!
//! 方法名常量集中在 [`method`] 模块，按 27 册斜杠写法；会话族取 18 册
//! 客户端→agent 面的 P1 子集：`initialize`、`authenticate`、`session/new`、
//! `session/load`、`session/resume`、`session/prompt`、`session/cancel`（通知）、
//! `session/update`（通知）、`session/set_mode`、`session/request_permission`、
//! `elicitation/create` / `elicitation/complete`。
//!
//! `session/update` 的载荷 [`SessionUpdate`] 按 19 册 §2 事件目录建型
//! （内部标签字段 `sessionUpdate`，即 bundle 实证 `u.sessionUpdate` 判别式）。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 对端实现信息（名称 + 版本），initialize 双向交换。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Implementation {
    /// 实现名（如 `reference-platform-desktop`）。
    pub name: String,
    /// 语义化版本串。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `initialize` 请求参数。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    /// 协议版本协商值（整数代际，ACP 现行 `protocolVersion`）。
    pub protocol_version: u32,
    /// 客户端实现信息（18 册 B.* 面的 client_info）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<Implementation>,
    /// 客户端能力位；未知键原样保留（前向兼容）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_capabilities: Option<Value>,
}

/// `initialize` 响应结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// 协商落定的协议版本。
    pub protocol_version: u32,
    /// agent 实现信息。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_info: Option<Implementation>,
    /// agent 能力位（如 loadCapabilities / promptCapabilities）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_capabilities: Option<Value>,
    /// 可用认证方式目录（Authenticate 的 methodId 取值域）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_methods: Option<Vec<Value>>,
}

/// `authenticate` 请求参数（18 册 B.authenticate）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateParams {
    /// 选定的认证方式 id（initialize 返回的目录内取值）。
    pub method_id: String,
}

/// `session/new` 请求参数。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSessionParams {
    /// 会话工作区绝对路径（18 册：工作区边界即权限边界）。
    pub cwd: String,
    /// 附加能力声明（原样保留）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_servers: Option<Vec<Value>>,
}

/// 会话 id：ACP 字符串形态。
pub type SessionId = String;

/// `session/new` 响应结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSessionResult {
    /// 新建会话 id。
    pub session_id: SessionId,
    /// 可用模式目录（plan/agent 等，18 册 set_mode 的取值域）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modes: Option<Value>,
}

/// `session/load` / `session/resume` 请求参数（历史代际恢复用，19 册 §4）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadSessionParams {
    /// 目标会话 id。
    pub session_id: SessionId,
    /// 工作区路径。
    pub cwd: String,
}

/// `session/load` 响应结果：历史重放以 `session/update` 通知流回传，
/// 结果体本身只确认成功。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoadSessionResult {
    /// 可恢复标记（缺省视为 true）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered: Option<bool>,
}

/// `session/resume` 参数：与 load 同形（18 册生命周期：resume→RUNNING）。
pub type ResumeSessionParams = LoadSessionParams;

/// `session/resume` 结果。
pub type ResumeSessionResult = LoadSessionResult;

/// 内容块：prompt 与消息流的通用单元。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// 文本块。
    Text(TextContent),
    /// 资源块（文件/URI 引用；内部结构 P1 原样保留）。
    Resource(Value),
}

/// 文本内容。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextContent {
    /// 文本正文。
    pub text: String,
}

impl TextContent {
    /// 快捷构造。
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// prompt 的单条输入（用户消息片段序列）。
pub type InputContent = ContentBlock;

/// `session/prompt` 请求参数（18 册 B.session_prompt：逐轮推进）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptParams {
    /// 目标会话。
    pub session_id: SessionId,
    /// 本轮用户输入块序列。
    pub prompt: Vec<InputContent>,
}

/// 回合停止原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// 正常结束回合。
    EndTurn,
    /// 被用户取消（session/cancel 生效）。
    Cancelled,
    /// 等待用户输入（max_tokens 类截断的对应位）。
    MaxTokens,
}

/// `session/prompt` 响应结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromptResult {
    /// 回合停止原因。
    pub stop_reason: StopReason,
}

/// `session/cancel` 通知参数（当前轮取消，无响应）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelNotification {
    /// 目标会话。
    pub session_id: SessionId,
}

/// `session/set_mode` 请求参数（运行中可切，18 册生命周期）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSessionModeParams {
    /// 目标会话。
    pub session_id: SessionId,
    /// 模式 id（取自 session/new 返回的 modes 目录）。
    pub mode_id: String,
}

/// `session/update` 通知参数：会话增量事件流的信封。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionNotification {
    /// 所属会话。
    pub session_id: SessionId,
    /// 增量事件本体（判别式 `sessionUpdate`）。
    pub update: SessionUpdate,
}

/// 会话增量事件（19 册 §2 事件类型目录，ACP 标准型）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "sessionUpdate", rename_all = "snake_case")]
pub enum SessionUpdate {
    /// 正文流式增量。
    AgentMessageChunk(ContentBlock),
    /// 思考流式增量。
    AgentThoughtChunk(ContentBlock),
    /// 用户输入回显。
    UserMessageChunk(ContentBlock),
    /// 工具调用开始（19 册 §3 捕获源）。
    ToolCall(ToolCallUpdate),
    /// 工具调用更新（状态/结果演进）。
    ToolCallUpdate(ToolCallUpdate),
    /// plan 模式方案更新（19 册：出现最频率的一等事件）。
    #[serde(rename_all = "camelCase")]
    Plan {
        /// 方案条目数组（内部结构 P1 原样保留）。
        entries: Value,
    },
    /// 当前模式变更。
    #[serde(rename_all = "camelCase")]
    CurrentMode {
        /// 变更后的模式 id。
        mode_id: String,
    },
    /// 可用命令清单变更。
    #[serde(rename_all = "camelCase")]
    AvailableCommands {
        /// 命令目录（内部结构 P1 原样保留）。
        commands: Value,
    },
}

/// 工具调用状态机（tool_call / tool_call_update 的 status 取值域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallStatus {
    /// 已开始未执行。
    Pending,
    /// 执行中。
    InProgress,
    /// 完成。
    Completed,
    /// 失败。
    Failed,
}

/// 工具类别（ACP 标准枚举；未知值反序列化失败即协议违例，fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    /// 读文件。
    Read,
    /// 写/改文件。
    Edit,
    /// 删除。
    Delete,
    /// 移动。
    Move,
    /// 搜索。
    Search,
    /// 执行命令。
    Execute,
    /// 思考/规划类。
    Think,
    /// 其他。
    Other,
}

/// 工具调用事件载荷（19 册 §3：toolCallId 必有；字段按 bundle 实证 camelCase）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallUpdate {
    /// 调用 id（关联 rawInput/rawOutput 的主键）。
    pub tool_call_id: String,
    /// 标题（人类可读一行）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// 工具类别。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ToolKind>,
    /// 状态。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ToolCallStatus>,
    /// 原始入参（原样保留）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_input: Option<Value>,
    /// 原始出参（原样保留）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<Value>,
    /// 厂商私有元数据（27 册 `codebuddy.ai/*` 命名空间的载体；wire 键 `_meta`）。
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// `session/request_permission` 请求参数（18 册 V.session_request_permission：
/// 权限闸的协议层，agent→客户端方向）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPermissionParams {
    /// 目标会话。
    pub session_id: SessionId,
    /// 待授权的工具调用。
    pub tool_call: ToolCallUpdate,
    /// 可选项目录（outcome.optionId 的取值域；结构 P1 原样保留）。
    pub options: Vec<Value>,
}

/// 权限决议回带（用户选定项）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionOutcome {
    /// 决议类型。
    pub outcome: PermissionOutcomeKind,
    /// 选定的 optionId（selected 时存在）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub option_id: Option<String>,
}

/// 权限决议二分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionOutcomeKind {
    /// 用户选定某项。
    Selected,
    /// 用户取消（未作答）。
    Cancelled,
}

/// `elicitation/create` 参数（18 册 V.elicitation_create：向用户要结构化输入）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElicitationCreateParams {
    /// 目标会话。
    pub session_id: SessionId,
    /// 提问消息。
    pub message: String,
    /// 期望的输入模式（JSON Schema 形态；P1 原样保留）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_schema: Option<Value>,
}

/// `elicitation/complete` 参数（客户端作答回传）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElicitationCompleteParams {
    /// 目标会话。
    pub session_id: SessionId,
    /// 作答内容（schema 对应；P1 原样保留）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
}

/// 方法名集中表：与上面类型一一对应（27 册斜杠方法名）。
pub mod method {
    /// `initialize`
    pub const INITIALIZE: &str = "initialize";
    /// `authenticate`
    pub const AUTHENTICATE: &str = "authenticate";
    /// `session/new`
    pub const SESSION_NEW: &str = "session/new";
    /// `session/load`
    pub const SESSION_LOAD: &str = "session/load";
    /// `session/resume`
    pub const SESSION_RESUME: &str = "session/resume";
    /// `session/prompt`
    pub const SESSION_PROMPT: &str = "session/prompt";
    /// `session/cancel`（通知）
    pub const SESSION_CANCEL: &str = "session/cancel";
    /// `session/update`（通知）
    pub const SESSION_UPDATE: &str = "session/update";
    /// `session/set_mode`
    pub const SESSION_SET_MODE: &str = "session/set_mode";
    /// `session/request_permission`
    pub const SESSION_REQUEST_PERMISSION: &str = "session/request_permission";
    /// `logout`
    pub const LOGOUT: &str = "logout";
    /// `elicitation/create`
    pub const ELICITATION_CREATE: &str = "elicitation/create";
    /// `elicitation/complete`
    pub const ELICITATION_COMPLETE: &str = "elicitation/complete";
}

/// `B.logout`（18 册认证族）的参数占位：无参数即空对象。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LogoutParams {}
