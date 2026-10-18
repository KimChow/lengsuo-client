//! JSON-RPC 2.0 线格式类型：id、错误对象、入站/出站消息与写侧信封。
//!
//! 纯类型定义，无逻辑；分类与解析见 [`super::classify`]。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;

/// JSON-RPC 请求 id。字符串与数字都合法（服务端也可能用它自己的字符串 id
/// 发起请求），因此分类时只比较、不做算术。
/// 排序只为让在途请求表用 [`std::collections::BTreeMap`]（不引入 `HashMap`
/// 的随机哈希种子，诊断输出可复现）；数字与字符串不比较语义，只按变体顺序。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
}

impl RequestId {
    /// 诊断文本（不含载荷）。
    #[must_use]
    pub fn as_text(&self) -> String {
        match self {
            Self::Number(n) => n.to_string(),
            Self::String(s) => s.clone(),
        }
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_text())
    }
}

/// JSON-RPC 2.0 保留错误码：请求方法不存在（也用于拒绝服务端发起的请求）。
pub const METHOD_NOT_FOUND: i64 = -32601;

/// JSON-RPC 2.0 保留错误码：参数非法。
pub const INVALID_PARAMS: i64 = -32602;

/// JSON-RPC 2.0 保留错误码：internal error。
pub const INTERNAL_ERROR: i64 = -32603;

/// JSON-RPC 2.0 `error` 对象。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcErrorObject {
    /// 保留错误码：method not found。
    #[must_use]
    pub fn method_not_found(message: impl Into<String>) -> Self {
        Self {
            code: METHOD_NOT_FOUND,
            message: message.into(),
            data: None,
        }
    }

    /// 映射为类型化错误。`data` 只保留标量文本（字符串/数字/布尔），对象
    /// 与数组压平为 `Debug` 文本，避免把工具结果整块塞进错误信息与日志。
    #[must_use]
    pub fn to_error(&self) -> Error {
        let data = self.data.as_ref().map(summarize_data);
        Error::JsonRpc {
            code: self.code,
            message: self.message.clone(),
            data,
        }
    }
}

fn summarize_data(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        // 结构化载荷序列化为紧凑 JSON 文本：不泄漏 Rust Debug 形态，保持字节级可复现。
        other => serde_json::to_string(other).unwrap_or_else(|_| "<unserializable>".into()),
    }
}

/// 一条已完成的服务端响应。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Response {
    pub id: RequestId,
    /// `true` 表示 `error` 分支。
    pub is_error: bool,
    pub result: Option<Value>,
    pub error: Option<JsonRpcErrorObject>,
}

impl Response {
    /// 归一为投递给等待方的负载。`is_error` 与实际字段不一致时以字段为准，
    /// 两者都缺（理论上分类器已拦截）则视为空结果。
    #[must_use]
    pub fn payload(&self) -> ResponsePayload {
        match (&self.error, &self.result) {
            (Some(e), _) => ResponsePayload::Error(e.clone()),
            (None, Some(r)) => ResponsePayload::Result(r.clone()),
            (None, None) => ResponsePayload::Result(Value::Null),
        }
    }
}

/// 服务端主动通知（无 `id` 且带 `method`）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Notification {
    pub method: String,
    pub params: Option<Value>,
}

/// 一条服务端主动通知的投递体（发给订阅端）。`params` 原样保留：v0 不实现
/// progress/logging 的具体语义，只保证不丢帧。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub method: String,
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// 通知方法名。
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
}

/// 服务端发起的请求（带 `id` 且带 `method`）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerRequest {
    pub id: RequestId,
    pub method: String,
    pub params: Option<Value>,
}

/// 从字节流解出的一条 JSON-RPC 消息。响应体是客户端等待的，通知与服务端
/// 请求是服务端主动写来的，因此响应单独成一项（含 `Other` 兜底），避免
/// 三个变体字段完全相同、调用方还得手工判别。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Inbound {
    /// 与某个本地请求关联的响应。
    Response(Response),
    /// 服务端主动通知。
    Notification(Notification),
    /// 服务端发起的请求（v0 只上报，不处理）。
    ServerRequest(ServerRequest),
    /// 既无 `id` 也无 `method`，但仍是合法 JSON-RPC 响应形状的报文。
    Other(Value),
}

/// 入站消息的线格式分类结果（reader 循环使用）。
#[derive(Debug, Clone, PartialEq)]
pub enum WireMessage {
    /// 与某个在途请求匹配的响应体。
    Response(Response),
    /// 服务端主动通知。
    Notification(JsonRpcNotification),
    /// 服务端发起的请求（v0 记录并自动拒绝）。
    ServerRequest(ServerRequest),
}

/// 响应负载：`result` 或 `error` 二选一（由 [`Response::payload`] 归一）。
#[derive(Debug, Clone, PartialEq)]
pub enum ResponsePayload {
    Result(Value),
    Error(JsonRpcErrorObject),
}

/// 客户端出站请求。
#[derive(Debug, Clone, PartialEq)]
pub struct OutRequest<'a> {
    pub id: &'a RequestId,
    pub method: &'a str,
    /// `None` 时不写 `params` 字段（规范允许省略）。
    pub params: Option<&'a Value>,
}

/// 客户端出站通知。
#[derive(Debug, Clone, PartialEq)]
pub struct OutNotification<'a> {
    pub method: &'a str,
    pub params: Option<&'a Value>,
}

/// 客户端出站响应（回应服务端请求）。
#[derive(Debug, Clone, PartialEq)]
pub struct OutResponse<'a> {
    pub id: &'a RequestId,
    pub result: Option<Value>,
    pub error: Option<JsonRpcErrorObject>,
}

/// 请求信封（写侧）。`params` 为 `None` 时 serde 跳过该字段。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct RequestEnvelope {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: RequestId,
    pub(crate) method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) params: Option<Value>,
}

/// 通知信封（写侧）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct NotificationEnvelope {
    pub(crate) jsonrpc: &'static str,
    pub(crate) method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) params: Option<Value>,
}
