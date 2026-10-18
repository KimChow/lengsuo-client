//! JSON-RPC 2.0 三分类：Request / Response / Notification。
//!
//! 判别规则（标准 JSON-RPC，与 27 册斜杠方法面一致）：
//! - 有 `method` 且有 `id` → [JsonRpcRequest]（等响应）；
//! - 有 `method` 无 `id` → [JsonRpcNotification]（不等响应，如 `session/update`）；
//! - 有 `id` 且有 `result` 或 `error` → [JsonRpcResponse]。
//!
//! `id` 允许字符串或数字（[RequestId]）。未知字段一律保留（serde 默认放行），
//! 便于对端扩展前向兼容。

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// JSON-RPC 协议的 `jsonrpc` 字段：只接受 `"2.0"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonRpcVersion;

impl<'de> Deserialize<'de> for JsonRpcVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == "2.0" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "jsonrpc 版本只支持 \"2.0\"，收到 {s:?}"
            )))
        }
    }
}

impl Serialize for JsonRpcVersion {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str("2.0")
    }
}

/// 请求/响应关联 id：ACP 实证同时存在字符串与数字两种形态。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// 数字 id。
    Number(i64),
    /// 字符串 id。
    String(String),
}

impl RequestId {
    /// 展示形态（错误信息用）。
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Number(n) => n.to_string(),
            Self::String(s) => s.clone(),
        }
    }
}

/// JSON-RPC error 对象（响应 `error` 字段）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcErrorObject {
    /// 错误码：标准族见 `JSONRPC_ERROR_*` 常量，私有码原样保留。
    pub code: i64,
    /// 人类可读摘要。
    pub message: String,
    /// 附加数据（可选，原样保留）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// 标准 JSON-RPC 错误码：解析失败。
pub const JSONRPC_ERROR_PARSE: i64 = -32700;
/// 标准 JSON-RPC 错误码：方法不存在。
pub const JSONRPC_ERROR_METHOD_NOT_FOUND: i64 = -32601;
/// 标准 JSON-RPC 错误码：无效请求。
pub const JSONRPC_ERROR_INVALID_REQUEST: i64 = -32600;
/// 标准 JSON-RPC 错误码：参数无效。
pub const JSONRPC_ERROR_INVALID_PARAMS: i64 = -32602;

/// 带 id、等响应的请求。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// 协议版本，恒为 2.0。
    pub jsonrpc: JsonRpcVersion,
    /// 关联 id。
    pub id: RequestId,
    /// 方法名（斜杠族，如 `session/new`）。
    pub method: String,
    /// 参数对象；无参数时为 `None`（序列化时省略）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// 组装请求；`params` 为 `Value::Null` 时按无参数处理。
    #[must_use]
    pub fn new(id: RequestId, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            id,
            method: method.into(),
            params: if params.is_null() { None } else { Some(params) },
        }
    }

    /// 把 `params` 反序列化成强类型；缺省或类型不符报错。
    ///
    /// # Errors
    /// [`crate::Error::MalformedMessage`]：`params` 缺失或反序列化失败。
    pub fn params_as<T: serde::de::DeserializeOwned>(&self) -> crate::Result<T> {
        let params = self
            .params
            .as_ref()
            .ok_or_else(|| crate::Error::MalformedMessage {
                reason: format!("请求 {} 缺少 params", self.method),
            })?;
        T::deserialize(params).map_err(crate::Error::from)
    }
}

/// 不带 id、不等响应的通知。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// 协议版本，恒为 2.0。
    pub jsonrpc: JsonRpcVersion,
    /// 方法名（如 `session/update`、`session/cancel`）。
    pub method: String,
    /// 参数对象（可选）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// 组装通知。
    #[must_use]
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            method: method.into(),
            params: if params.is_null() { None } else { Some(params) },
        }
    }

    /// 把 `params` 反序列化成强类型。
    ///
    /// # Errors
    /// [`crate::Error::MalformedMessage`]：`params` 缺失或反序列化失败。
    pub fn params_as<T: serde::de::DeserializeOwned>(&self) -> crate::Result<T> {
        let params = self
            .params
            .as_ref()
            .ok_or_else(|| crate::Error::MalformedMessage {
                reason: format!("通知 {} 缺少 params", self.method),
            })?;
        T::deserialize(params).map_err(crate::Error::from)
    }
}

/// 带 id 的响应（对 Request 的答复）。`result` 与 `error` 至少有一个存在，
/// 由 [`Message::from_value`] 判别保证。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// 协议版本，恒为 2.0。
    pub jsonrpc: JsonRpcVersion,
    /// 回显请求 id。
    pub id: RequestId,
    /// 成功结果（与 `error` 互斥）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// 错误对象（与 `result` 互斥）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorObject>,
}

impl JsonRpcResponse {
    /// 成功响应。
    #[must_use]
    pub fn ok(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            id,
            result: Some(result),
            error: None,
        }
    }

    /// 失败响应。
    #[must_use]
    pub fn err(id: RequestId, error: JsonRpcErrorObject) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            id,
            result: None,
            error: Some(error),
        }
    }

    /// 读取结果：Ok 反序列化成强类型，Err 返回错误对象。
    ///
    /// # Errors
    /// [`crate::Error::MalformedMessage`]：既无 result 又无 error。
    pub fn result_as<T: serde::de::DeserializeOwned>(
        &self,
    ) -> crate::Result<std::result::Result<T, JsonRpcErrorObject>> {
        if let Some(e) = &self.error {
            return Ok(Err(e.clone()));
        }
        let result = self
            .result
            .as_ref()
            .ok_or_else(|| crate::Error::MalformedMessage {
                reason: format!("响应 {} 既无 result 也无 error", self.id.display()),
            })?;
        T::deserialize(result).map(Ok).map_err(crate::Error::from)
    }
}

/// 一条完整的 ACP wire 消息（JSON-RPC 三分类）。
///
/// 判别顺序由 untagged 保证：响应（有 result/error）→ 请求（method+id）→
/// 通知（method 无 id）。无法归类的形态报 [`crate::Error::MalformedMessage`]。
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// 请求。
    Request(JsonRpcRequest),
    /// 响应。
    Response(JsonRpcResponse),
    /// 通知。
    Notification(JsonRpcNotification),
}

impl Message {
    /// 从 JSON 值分类。
    ///
    /// # Errors
    /// [`crate::Error::MalformedMessage`]：不符合三分类任何一种。
    pub fn from_value(v: &Value) -> crate::Result<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| crate::Error::MalformedMessage {
                reason: "wire 消息必须是 JSON 对象".into(),
            })?;
        let has_id = obj.contains_key("id");
        let has_result_or_error = obj.contains_key("result") || obj.contains_key("error");
        if obj.contains_key("method") {
            // method 存在：带 id 是请求，不带 id 是通知。
            if has_id {
                return serde_json::from_value::<JsonRpcRequest>(v.clone())
                    .map(Self::Request)
                    .map_err(crate::Error::from);
            }
            return serde_json::from_value::<JsonRpcNotification>(v.clone())
                .map(Self::Notification)
                .map_err(crate::Error::from);
        }
        if has_id && has_result_or_error {
            return serde_json::from_value::<JsonRpcResponse>(v.clone())
                .map(Self::Response)
                .map_err(crate::Error::from);
        }
        Err(crate::Error::MalformedMessage {
            reason: "消息缺少 method，或响应缺少 result/error".into(),
        })
    }

    /// 请求/响应的关联 id（通知为 None）。
    #[must_use]
    pub fn id(&self) -> Option<&RequestId> {
        match self {
            Self::Request(r) => Some(&r.id),
            Self::Response(r) => Some(&r.id),
            Self::Notification(_) => None,
        }
    }

    /// 序列化成 JSON 值。
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Request(r) => serde_json::to_value(r).expect("request 总能序列化"),
            Self::Response(r) => serde_json::to_value(r).expect("response 总能序列化"),
            Self::Notification(n) => serde_json::to_value(n).expect("notification 总能序列化"),
        }
    }
}

impl Serialize for Message {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.to_value().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Self::from_value(&v).map_err(serde::de::Error::custom)
    }
}
