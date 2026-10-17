//! 会话/消息/事件 schema v0（开工说明 §3）。
//!
//! 冻结点：字段名与枚举字符串值。序列化采用 camelCase 字段名、snake_case 枚举值，
//! 与网关信封一致，轨道 E 直接依赖。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// 事件文件与 schema 的版本号，自第一天写入文件头。
pub const SCHEMA_VERSION: u32 = 1;

/// 会话模式（quick|ask|plan|craft|expert）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Quick,
    Ask,
    Plan,
    Craft,
    Expert,
}

impl Mode {
    pub const ALL: [Mode; 5] = [
        Mode::Quick,
        Mode::Ask,
        Mode::Plan,
        Mode::Craft,
        Mode::Expert,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Quick => "quick",
            Mode::Ask => "ask",
            Mode::Plan => "plan",
            Mode::Craft => "craft",
            Mode::Expert => "expert",
        }
    }
}

/// 权限模式（readonly|full）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum PermissionMode {
    /// 只允许只读类工具，写/执行/网络一律拒绝。
    #[default]
    #[serde(rename = "readonly")]
    ReadOnly,
    /// 允许非只读工具，但仍受白名单、auto 集与敏感动作规则约束。
    #[serde(rename = "full")]
    Full,
}

impl PermissionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PermissionMode::ReadOnly => "readonly",
            PermissionMode::Full => "full",
        }
    }
}

/// 会话状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Idle,
    Done,
    Failed,
}

/// 消息角色四类（参照平台基线：历史重放不重跑工具）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    ToolCall,
    ToolResult,
}

/// 隔离键（用户/租户/环境）；v0 单用户本地，字段预留。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Isolation {
    pub user_id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_id: Option<String>,
}

impl Isolation {
    /// 本地单用户默认键（v0）。
    pub fn local_default() -> Self {
        Self {
            user_id: "local".into(),
            tenant_id: "local".into(),
            env_id: None,
        }
    }

    /// 事件流订阅用的隔离键字符串（文件名单一段）。
    pub fn key(&self) -> String {
        format!("{}-{}", self.user_id, self.tenant_id)
    }
}

/// 工具调用/结果的附属信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
    /// 工具执行耗时（毫秒）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
}

/// 会话内一条消息。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub role: Role,
    /// 展示文本；大结果不进此字段，改走 `tool.result_ref`。
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolInfo>,
    pub ts_ms: u64,
}

/// 会话（热态内存对象）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub title: String,
    pub workspace_root: String,
    pub mode: Mode,
    pub permission_mode: PermissionMode,
    /// 环境绑定预留（浏览器/指纹环境 id）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_binding: Option<String>,
    pub isolation: Isolation,
    pub messages: Vec<Message>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub status: SessionStatus,
    /// 会话内已产生的最大事件 seq（分页回溯锚点，N12）。
    #[serde(default)]
    pub last_seq: u64,
    /// 三层记忆组装摘要（memory.enabled 时由 create_session 注入；agent-memory-spec §4）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_digest: Option<String>,
}

impl Session {
    /// 会话摘要：列表视图用，不带消息体。
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "id": self.id.to_string(),
            "title": self.title,
            "mode": self.mode,
            "permissionMode": self.permission_mode,
            "envBinding": self.env_binding,
            "status": self.status,
            "messageCount": self.messages.len(),
            "lastSeq": self.last_seq,
            "createdAtMs": self.created_at_ms,
            "updatedAtMs": self.updated_at_ms,
        })
    }
}

/// 事件种类（参照平台基线 §5 + `session_update`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Thinking,
    Text,
    ToolUse,
    ToolResult,
    ApprovalRequest,
    ApprovalResolved,
    Files,
    Done,
    Error,
    SessionUpdate,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Thinking => "thinking",
            EventKind::Text => "text",
            EventKind::ToolUse => "tool_use",
            EventKind::ToolResult => "tool_result",
            EventKind::ApprovalRequest => "approval_request",
            EventKind::ApprovalResolved => "approval_resolved",
            EventKind::Files => "files",
            EventKind::Done => "done",
            EventKind::Error => "error",
            EventKind::SessionUpdate => "session_update",
        }
    }

    pub fn parse(raw: &str) -> Option<EventKind> {
        Some(match raw {
            "thinking" => EventKind::Thinking,
            "text" => EventKind::Text,
            "tool_use" => EventKind::ToolUse,
            "tool_result" => EventKind::ToolResult,
            "approval_request" => EventKind::ApprovalRequest,
            "approval_resolved" => EventKind::ApprovalResolved,
            "files" => EventKind::Files,
            "done" => EventKind::Done,
            "error" => EventKind::Error,
            "session_update" => EventKind::SessionUpdate,
            _ => return None,
        })
    }
}

/// 一条事件：`seq` 会话内单调递增。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub seq: u64,
    pub session_id: Uuid,
    pub kind: String,
    pub payload: Value,
    pub ts_ms: u64,
}

impl Event {
    /// 推送给订阅者的行（事件流每行一个 JSON 对象）。
    pub fn to_envelope(&self) -> Value {
        serde_json::json!({
            "seq": self.seq,
            "sessionId": self.session_id.to_string(),
            "kind": self.kind,
            "payload": self.payload,
            "tsMs": self.ts_ms,
        })
    }
}

/// 挂起的审批请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub session_id: String,
    pub tool_name: String,
    /// 参数摘要（已脱敏，不含凭据值）。
    pub summary: String,
    pub reason: String,
    pub expires_at_ms: u64,
}

/// 审批应答结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalOutcome {
    pub approved: bool,
    pub timed_out: bool,
}

/// 会话快照的事件载荷（`session_update`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionUpdatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default)]
    pub message_count: usize,
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}
