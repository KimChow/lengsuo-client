//! 厂商私有 control 信封（18 册 §2 实证）。
//!
//! bundle 实证的 agent→客户端形态：
//! `{type:"control_request", request_id, request:{subtype:"elicitation_create",…}}`，
//! 客户端完成时回 `control_notification`。这是 JSON-RPC 三分类**之外**的一层
//! 信封（顶层 `type` 判别而非 `method`），故单独建型，且只能出现在帧体解析
//! 之后由路由层分派（P2）。
//!
//! subtype 目录按 18 册 V.* 回调面取开放枚举：已知值强类型，未知值保留
//! 原文（`Unknown`），新 subtype 不破坏解码。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::message::RequestId;

/// 信封内携带的子类型判别（18 册 V.* 面）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlSubtype {
    /// agent 向用户要结构化输入（发起）。
    ElicitationCreate,
    /// elicitation 作答完成（回传）。
    ElicitationComplete,
    /// agent 请求用户授权（权限闸协议层）。
    SessionRequestPermission,
    /// agent 推送会话增量。
    SessionUpdate,
    /// 委托客户端读文件。
    FsReadTextFile,
    /// 委托客户端写文件。
    FsWriteTextFile,
    /// 委托客户端创建终端。
    TerminalCreate,
    /// 委托客户端终止终端。
    TerminalKill,
    /// 读取终端输出。
    TerminalOutput,
    /// 释放终端资源。
    TerminalRelease,
    /// 等待终端退出。
    TerminalWaitForExit,
    /// 未知/新增 subtype：原文保留，路由层决定拒绝或透传。
    #[serde(other)]
    Unknown,
}

impl ControlSubtype {
    /// wire 拼写（`Unknown` 无法还原原文，返回占位串仅供日志）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ElicitationCreate => "elicitation_create",
            Self::ElicitationComplete => "elicitation_complete",
            Self::SessionRequestPermission => "session_request_permission",
            Self::SessionUpdate => "session_update",
            Self::FsReadTextFile => "fs_read_text_file",
            Self::FsWriteTextFile => "fs_write_text_file",
            Self::TerminalCreate => "terminal_create",
            Self::TerminalKill => "terminal_kill",
            Self::TerminalOutput => "terminal_output",
            Self::TerminalRelease => "terminal_release",
            Self::TerminalWaitForExit => "terminal_wait_for_exit",
            Self::Unknown => "unknown",
        }
    }
}

/// control 请求载荷：`request` 字段内是 `{subtype, …}`，其余键原样保留。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlRequestBody {
    /// 子类型判别。
    pub subtype: ControlSubtype,
    /// 其余参数（形态随 subtype 变化；P1 原样保留）。
    #[serde(flatten)]
    pub payload: Value,
}

/// `{type:"control_request"}` 信封（18 册实证字段：type/request_id/request）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlRequest {
    /// 恒为 `"control_request"`（判别标签）。
    #[serde(rename = "type")]
    pub kind: ControlRequestTag,
    /// 关联 id：客户端应答时回显。
    pub request_id: RequestId,
    /// 请求载荷（含 subtype）。
    pub request: ControlRequestBody,
}

/// `control_request` 标签类型：反序列化只接受该拼写。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequestTag {
    /// 固定值 `control_request`。
    #[serde(rename = "control_request")]
    ControlRequest,
}

/// `{type:"control_notification"}` 信封：control 请求的完成回传或单向事件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlNotification {
    /// 恒为 `"control_notification"`。
    #[serde(rename = "type")]
    pub kind: ControlNotificationTag,
    /// 载荷（含 subtype 与应答内容；P1 原样保留）。
    #[serde(flatten)]
    pub payload: Value,
}

/// `control_notification` 标签类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlNotificationTag {
    /// 固定值 `control_notification`。
    #[serde(rename = "control_notification")]
    ControlNotification,
}

/// control 面的响应信封：对 `control_request` 的按 id 答复。
///
/// 注意：18 册实证完成回传走 `control_notification`；本类型覆盖同一信封族里
/// `request_id + response` 的应答形态（bundle 里 control 请求存在两回法，
/// P2 路由时以实际互通为准取舍）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlResponse {
    /// 恒为 `"control_response"`。
    #[serde(rename = "type")]
    pub kind: ControlResponseTag,
    /// 回显的请求 id。
    pub request_id: RequestId,
    /// 应答载荷（原样保留）。
    pub response: Value,
}

/// `control_response` 标签类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlResponseTag {
    /// 固定值 `control_response`。
    #[serde(rename = "control_response")]
    ControlResponse,
}

/// 帧体顶层判别结果：标准 JSON-RPC 消息或 control 信封。
///
/// [`crate::codec`] 只负责切帧；顶层归类由此枚举承担，供 P2 路由分派。
#[derive(Debug, Clone, PartialEq)]
pub enum TopLevel {
    /// 标准 JSON-RPC 三分类之一。
    Rpc(crate::message::Message),
    /// control 请求信封。
    ControlRequest(ControlRequest),
    /// control 通知信封。
    ControlNotification(ControlNotification),
    /// control 应答信封。
    ControlResponse(ControlResponse),
}

impl TopLevel {
    /// 按顶层 `type` / `method` 字段归类一帧 JSON。
    ///
    /// # Errors
    /// [`crate::Error::MalformedMessage`]：既不是 JSON-RPC 形态也不是 control 形态。
    pub fn classify(v: Value) -> crate::Result<Self> {
        if let Some(t) = v.get("type").and_then(Value::as_str) {
            return match t {
                "control_request" => serde_json::from_value(v)
                    .map(Self::ControlRequest)
                    .map_err(crate::Error::from),
                "control_notification" => serde_json::from_value(v)
                    .map(Self::ControlNotification)
                    .map_err(crate::Error::from),
                "control_response" => serde_json::from_value(v)
                    .map(Self::ControlResponse)
                    .map_err(crate::Error::from),
                other => Err(crate::Error::MalformedMessage {
                    reason: format!("未知顶层 type: {other:?}"),
                }),
            };
        }
        crate::message::Message::from_value(&v).map(Self::Rpc)
    }
}
