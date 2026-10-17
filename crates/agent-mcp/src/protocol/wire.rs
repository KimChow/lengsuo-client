//! JSON-RPC 2.0 线格式：消息分类、入站/出站结构与线信封。
//!
//! 分类规则按 JSON-RPC 2.0 与 MCP 规范：`method` 存在即请求或通知（`id`
//! 存在为请求），否则必须是带 `id` 的响应（`result` 与 `error` 恰有其一）。
//! 无法分类的报文一律 [`Error::MalformedMessage`]，不 panic、不静默丢弃。

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

/// 把一条 JSON-RPC 报文（帧体）分类为 [`Inbound`]。
///
/// # Errors
/// [`Error::MalformedMessage`]：不是合法 JSON-RPC 2.0 消息（缺 `jsonrpc`、
/// `result` 与 `error` 同时存在或同时缺失、`id` 类型非法等）。
pub fn classify(raw: &Value) -> std::result::Result<Inbound, Error> {
    let obj = obj_of(raw)?;
    match obj.get("jsonrpc") {
        Some(Value::String(v)) if v == "2.0" => {}
        Some(other) => {
            return Err(Error::MalformedMessage {
                reason: format!("jsonrpc 字段必须为 \"2.0\"，实际 {other}"),
            })
        }
        None => {
            return Err(Error::MalformedMessage {
                reason: "缺少 jsonrpc 字段".to_string(),
            })
        }
    }
    let has_method = obj.get("method").is_some();
    let id = obj.get("id");
    if has_method {
        let method = match id {
            Some(v) => Some(id_and_method(v, obj)?.1),
            None => obj["method"].as_str().map(str::to_string),
        };
        let params = obj.get("params").cloned();
        match (method, id) {
            (Some(m), Some(id)) => Ok(Inbound::ServerRequest(ServerRequest {
                id: id_value(id)?,
                method: m,
                params,
            })),
            (Some(m), None) => Ok(Inbound::Notification(Notification { method: m, params })),
            (None, _) => Err(Error::MalformedMessage {
                reason: "method 字段必须是字符串".to_string(),
            }),
        }
    } else {
        let Some(id) = id else {
            return Err(Error::MalformedMessage {
                reason: "报文既无 method 也无 id".to_string(),
            });
        };
        if matches!(id, Value::Null) {
            return Err(Error::MalformedMessage {
                reason: "响应缺少 id".to_string(),
            });
        }
        check_id(id)?;
        let result = obj.get("result");
        let error = obj.get("error");
        match (result, error) {
            (Some(_), Some(_)) => Err(Error::MalformedMessage {
                reason: "result 与 error 同时存在".to_string(),
            }),
            (None, None) => Err(Error::MalformedMessage {
                reason: "result 与 error 同时缺失".to_string(),
            }),
            (_, Some(e)) => {
                let err: JsonRpcErrorObject =
                    serde_json::from_value(e.clone()).map_err(|err| Error::MalformedMessage {
                        reason: format!("error 对象不合法：{err}"),
                    })?;
                Ok(Inbound::Response(Response {
                    id: id_value(id)?,
                    is_error: true,
                    result: None,
                    error: Some(err),
                }))
            }
            (Some(r), None) => Ok(Inbound::Response(Response {
                id: id_value(id)?,
                is_error: false,
                result: Some(r.clone()),
                error: None,
            })),
        }
    }
}

fn obj_of(raw: &Value) -> std::result::Result<&serde_json::Map<String, Value>, Error> {
    raw.as_object().ok_or_else(|| Error::MalformedMessage {
        reason: format!("报文不是 JSON 对象：{}", shape(raw)),
    })
}

pub(crate) fn shape(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn check_id(id: &Value) -> std::result::Result<(), Error> {
    match id {
        Value::String(_) | Value::Number(_) => Ok(()),
        Value::Null => Err(Error::MalformedMessage {
            reason: "id 为 null".to_string(),
        }),
        other => Err(Error::MalformedMessage {
            reason: format!("id 类型非法：{}", shape(other)),
        }),
    }
}

/// `Value` → [`RequestId`]。浮点与非整数数字线格式不接受（JSON-RPC 2.0
/// 允许，但会让 id 比较语义变得不确定），一律 `MalformedMessage` 并计数。
fn id_value(id: &Value) -> std::result::Result<RequestId, Error> {
    check_id(id)?;
    match id {
        Value::String(s) => Ok(RequestId::String(s.clone())),
        Value::Number(n) => {
            n.as_i64()
                .map(RequestId::Number)
                .ok_or_else(|| Error::MalformedMessage {
                    reason: format!("id 不是整数：{n}"),
                })
        }
        other => Err(Error::MalformedMessage {
            reason: format!("id 类型非法：{}", shape(other)),
        }),
    }
}

fn id_and_method(
    id: &Value,
    obj: &serde_json::Map<String, Value>,
) -> std::result::Result<(RequestId, String), Error> {
    let rid = id_value(id)?;
    let method = obj["method"]
        .as_str()
        .ok_or_else(|| Error::MalformedMessage {
            reason: "method 字段必须是字符串".to_string(),
        })?;
    Ok((rid, method.to_string()))
}

impl Serialize for OutRequest<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("req", if self.params.is_some() { 4 } else { 3 })?;
        st.serialize_field("jsonrpc", "2.0")?;
        st.serialize_field("id", self.id)?;
        st.serialize_field("method", self.method)?;
        if let Some(p) = self.params {
            st.serialize_field("params", p)?;
        }
        st.end()
    }
}

impl Serialize for OutNotification<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("notif", if self.params.is_some() { 3 } else { 2 })?;
        st.serialize_field("jsonrpc", "2.0")?;
        st.serialize_field("method", self.method)?;
        if let Some(p) = self.params {
            st.serialize_field("params", p)?;
        }
        st.end()
    }
}

impl Serialize for OutResponse<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let error_only = self.result.is_none();
        let mut st = s.serialize_struct("resp", if error_only { 3 } else { 4 })?;
        st.serialize_field("jsonrpc", "2.0")?;
        st.serialize_field("id", self.id)?;
        if error_only {
            st.serialize_field("error", &self.error)?;
        } else {
            st.serialize_field("result", &self.result)?;
            if let Some(e) = &self.error {
                st.serialize_field("error", e)?;
            }
        }
        st.end()
    }
}

/// 从一条已解码的 JSON-RPC 报文分类出线消息。
fn classify_inbound(value: &Value) -> std::result::Result<WireMessage, Error> {
    match classify(value)? {
        Inbound::Response(r) => Ok(WireMessage::Response(r)),
        Inbound::Notification(n) => Ok(WireMessage::Notification(JsonRpcNotification {
            method: n.method,
            params: n.params,
        })),
        Inbound::ServerRequest(req) => Ok(WireMessage::ServerRequest(req)),
        Inbound::Other(v) => Err(Error::MalformedMessage {
            reason: format!("无法分类的报文：{}", shape(&v)),
        }),
    }
}

/// 解析一条帧体（UTF-8 JSON）为 [`WireMessage`]。
///
/// # Errors
/// [`Error::MalformedFrame`]：非 UTF-8 或 JSON 解析失败；
/// [`Error::MalformedMessage`]：JSON 合法但不是合法 JSON-RPC 2.0 消息
/// （分帧仍对齐，调用方可安全忽略并计数）。
pub fn parse_wire_message(raw: &[u8]) -> std::result::Result<WireMessage, Error> {
    let text = std::str::from_utf8(raw).map_err(|e| Error::MalformedFrame {
        reason: format!("帧体不是合法 UTF-8：{e}"),
    })?;
    let value: Value = serde_json::from_str(text).map_err(|e| Error::MalformedFrame {
        reason: format!("帧体不是合法 JSON：{e}"),
    })?;
    classify_inbound(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(s: &str) -> Value {
        serde_json::from_str(s).expect("fixture json")
    }

    #[test]
    fn classify_response_and_error() {
        let ok = classify(&v(r#"{"jsonrpc":"2.0","id":3,"result":{"a":1}}"#)).unwrap();
        assert!(matches!(
            ok,
            Inbound::Response(Response {
                id: RequestId::Number(3),
                is_error: false,
                ..
            })
        ));
        let err = classify(&v(
            r#"{"jsonrpc":"2.0","id":"x","error":{"code":-32601,"message":"no"}}"#,
        ))
        .unwrap();
        match err {
            Inbound::Response(r) => {
                assert!(r.is_error);
                assert_eq!(r.id, RequestId::String("x".into()));
                let mapped = r.error.unwrap().to_error();
                assert!(matches!(
                    mapped,
                    Error::JsonRpc {
                        code: -32601,
                        message,
                        ..
                    } if message == "no"
                ));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn classify_notification_and_server_request() {
        let n = classify(&v(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#,
        ))
        .unwrap();
        assert!(matches!(
            n,
            Inbound::Notification(Notification { ref method, .. }) if method == "notifications/message"
        ));
        let r = classify(&v(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)).unwrap();
        assert!(matches!(r, Inbound::ServerRequest(_)));
    }

    #[test]
    fn classify_rejects_malformed_without_panic() {
        for bad in [
            "null",
            "[1,2]",
            "\"str\"",
            r#"{"id":1}"#,
            r#"{"method":"x","jsonrpc":"1.0"}"#,
            r#"{"jsonrpc":"2.0","method":"x","id":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0","id":null,"result":1}"#,
            r#"{"jsonrpc":"2.0","method":5,"id":1}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"result":1}"#,
        ] {
            let parsed = serde_json::from_str::<Value>(bad).unwrap();
            let e = classify(&parsed);
            assert!(
                matches!(e, Err(Error::MalformedMessage { .. })),
                "{bad} -> {e:?}"
            );
        }
    }

    #[test]
    fn error_data_summary_does_not_leak_structures() {
        let e = JsonRpcErrorObject {
            code: -32000,
            message: "boom".into(),
            data: Some(json!({"secret": "value"})),
        }
        .to_error();
        match e {
            Error::JsonRpc { data, .. } => assert!(data.unwrap().starts_with('{')),
            other => panic!("{other:?}"),
        }
        let e2 = JsonRpcErrorObject {
            code: -32000,
            message: "boom".into(),
            data: Some(json!("plain")),
        }
        .to_error();
        match e2 {
            Error::JsonRpc { data, .. } => assert_eq!(data.unwrap(), "plain"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn method_not_found_helper_uses_reserved_code() {
        let e = JsonRpcErrorObject::method_not_found("nope");
        assert_eq!(e.code, METHOD_NOT_FOUND);
        assert!(e.data.is_none());
    }

    #[test]
    fn out_request_omits_params_when_none() {
        let id = RequestId::Number(7);
        let req = OutRequest {
            id: &id,
            method: "ping",
            params: None,
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#
        );
        let req2 = OutRequest {
            id: &RequestId::String("s".into()),
            method: "tools/call",
            params: Some(&json!({"name": "echo"})),
        };
        assert_eq!(
            serde_json::to_string(&req2).unwrap(),
            r#"{"jsonrpc":"2.0","id":"s","method":"tools/call","params":{"name":"echo"}}"#
        );
    }

    #[test]
    fn out_notification_and_response_encode() {
        let n = OutNotification {
            method: "notifications/initialized",
            params: None,
        };
        assert_eq!(
            serde_json::to_string(&n).unwrap(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        );
        let id = RequestId::Number(1);
        let r = OutResponse {
            id: &id,
            result: Some(json!({})),
            error: None,
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
        );
        let e = OutResponse {
            id: &id,
            result: None,
            error: Some(JsonRpcErrorObject {
                code: -32601,
                message: "no".into(),
                data: None,
            }),
        };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#
        );
    }

    #[test]
    fn request_id_text_and_display() {
        assert_eq!(RequestId::Number(-5).as_text(), "-5");
        assert_eq!(RequestId::String("a".into()).as_text(), "a");
        assert_eq!(format!("{}", RequestId::Number(3)), "3");
    }

    #[test]
    fn response_payload_prefers_error_branch() {
        let r = Response {
            id: RequestId::Number(1),
            is_error: true,
            result: Some(json!({"a":1})),
            error: Some(JsonRpcErrorObject {
                code: -32603,
                message: "boom".into(),
                data: None,
            }),
        };
        assert!(matches!(
            r.payload(),
            ResponsePayload::Error(JsonRpcErrorObject { code: -32603, .. })
        ));
        let ok = Response {
            id: RequestId::Number(2),
            is_error: false,
            result: Some(json!("v")),
            error: None,
        };
        assert!(matches!(ok.payload(), ResponsePayload::Result(_)));
    }

    #[test]
    fn parse_wire_message_splits_frame_vs_message_errors() {
        // 非 UTF-8 / 非 JSON：帧错误。
        assert!(matches!(
            parse_wire_message(&[0xff, 0xfe]),
            Err(Error::MalformedFrame { .. })
        ));
        assert!(matches!(
            parse_wire_message(b"{not json"),
            Err(Error::MalformedFrame { .. })
        ));
        // JSON 合法但形状非法：消息错误。
        assert!(matches!(
            parse_wire_message(br#"{"jsonrpc":"2.0"}"#),
            Err(Error::MalformedMessage { .. })
        ));
        let w = parse_wire_message(br#"{"jsonrpc":"2.0","method":"x","params":{"a":1}}"#).unwrap();
        assert!(matches!(w, WireMessage::Notification(_)));
    }

    #[test]
    fn envelopes_omit_params_and_carry_jsonrpc() {
        let req = RequestEnvelope {
            jsonrpc: "2.0",
            id: RequestId::Number(4),
            method: "ping".to_string(),
            params: None,
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#
        );
        let note = NotificationEnvelope {
            jsonrpc: "2.0",
            method: "notifications/initialized".to_string(),
            params: Some(json!({})),
        };
        assert_eq!(
            serde_json::to_string(&note).unwrap(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#
        );
    }
}
