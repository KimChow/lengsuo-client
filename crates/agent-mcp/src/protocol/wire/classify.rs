//! JSON-RPC 2.0 报文分类与帧解析。
//!
//! 分类规则按 JSON-RPC 2.0 与 MCP 规范：`method` 存在即请求或通知（`id`
//! 存在为请求），否则必须是带 `id` 的响应（`result` 与 `error` 恰有其一）。
//! 无法分类的报文一律 [`Error::MalformedMessage`]，不 panic、不静默丢弃。

use serde::Serialize;
use serde_json::Value;

use super::types::{
    Inbound, JsonRpcErrorObject, JsonRpcNotification, Notification, OutNotification, OutRequest,
    OutResponse, RequestId, Response, ServerRequest, WireMessage,
};
use crate::error::Error;

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
