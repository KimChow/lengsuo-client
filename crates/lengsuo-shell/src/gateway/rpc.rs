//! `POST /rpc` 请求编解码与信封解析（AGENT-KICKOFF.md §2）。
//!
//! 冻结语义：
//! - 单入口 `POST /rpc`，请求体 `{action: "<域>:<动作>", payload}`。
//! - 所有请求带 `X-Gateway-Token` 头，失败 403。
//! - 响应信封 `{code, msg, data}`：`code == 0` 成功；404 未注册动作、
//!   403 鉴权拒绝、408 超时；其余按 server-contract 错误码段原样上抛。
//! - 默认超时 30s。
//!
//! v0 动作面固定为 `session:list/create/get/send/stop`、`approval:respond`、
//! `config:get/set`、`tool:list`、`sys:ping`；其余动作服务端返回 404，客户端不预留。

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::http::{self, HttpError, HttpResponse};

/// 协议冻结的默认 RPC 超时（30s）。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// v0 动作名：只允许 `域:动作` 形态（一个冒号，两段非空）。
fn is_valid_action(action: &str) -> bool {
    let (domain, name) = match action.split_once(':') {
        Some(parts) => parts,
        None => return false,
    };
    action.matches(':').count() == 1
        && !domain.is_empty()
        && !name.is_empty()
        && action
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-'))
}

/// 网关响应信封。`data` 保留为 [`Value`]，由各动作的返回类型再解。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// 业务码，`0` 为成功。
    pub code: i64,
    /// 人类可读信息；错误时可能为空字符串。
    #[serde(default)]
    pub msg: String,
    /// 业务数据；失败时可能为 `null`。
    #[serde(default)]
    pub data: Value,
}

/// RPC 请求体。
#[derive(Debug, Clone, PartialEq, Serialize)]
struct RpcRequest<'a> {
    action: &'a str,
    payload: &'a Value,
}

/// 把一条 HTTP 响应解释成 RPC 结果。
///
/// 错误优先级：HTTP 层错误 > 信封非法 > 业务码非 0。映射表单独拆出，便于单测全覆盖。
pub fn interpret(response: &HttpResponse) -> Result<Value, RpcError> {
    // HTTP 403：token 不匹配，网关不解析业务语义，直接判定鉴权拒绝。
    if response.status == 403 {
        return Err(RpcError::Unauthorized);
    }
    if response.status == 404 && !looks_like_envelope(&response.body) {
        // 网关不认识的 HTTP 路径（协议实现偏差），与「动作未注册」区分开。
        return Err(RpcError::Http {
            status: response.status,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        });
    }
    if response.status == 408 && !looks_like_envelope(&response.body) {
        return Err(RpcError::Timeout);
    }
    if !(200..300).contains(&response.status) && !looks_like_envelope(&response.body) {
        return Err(RpcError::Http {
            status: response.status,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        });
    }
    let envelope: Envelope = serde_json::from_slice(&response.body)
        .map_err(|e| RpcError::MalformedEnvelope(format!("信封 JSON 非法：{e}")))?;
    if envelope.code == 0 {
        return Ok(envelope.data);
    }
    match envelope.code {
        403 => Err(RpcError::Unauthorized),
        404 => Err(RpcError::ActionNotFound { msg: envelope.msg }),
        408 => Err(RpcError::Timeout),
        other => Err(RpcError::Business {
            code: other,
            msg: envelope.msg,
        }),
    }
}

/// 判断响应体是否形如信封（用于区分 HTTP 层错误与业务码错误）。
fn looks_like_envelope(body: &[u8]) -> bool {
    serde_json::from_slice::<Map<String, Value>>(body)
        .map(|m| m.contains_key("code"))
        .unwrap_or(false)
}

/// 编码一条 RPC 请求体。动作名非法直接拒绝，不发给网关。
pub fn encode_request(action: &str, payload: &Value) -> Result<Vec<u8>, RpcError> {
    if !is_valid_action(action) {
        return Err(RpcError::InvalidAction(action.to_string()));
    }
    let req = RpcRequest {
        action,
        payload: &payload.clone(),
    };
    serde_json::to_vec(&req).map_err(|e| RpcError::InvalidAction(format!("载荷编码失败：{e}")))
}

/// RPC 侧错误。鉴权与「动作未注册」分开，壳层据此给出不同 UI 提示。
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// 传输/字节层错误（连接失败、响应不完整、超时以外的 IO）。
    #[error("网关 RPC 传输错误")]
    Transport(#[from] HttpError),
    /// 客户端侧等待超时（默认 30s）。
    #[error("网关 RPC 超时")]
    Timeout,
    /// token 缺失或不匹配（HTTP 403 或信封 code 403）。
    #[error("网关鉴权拒绝：token 无效或缺失")]
    Unauthorized,
    /// 动作未注册（信封 code 404）。
    #[error("网关未注册该动作（{msg}）")]
    ActionNotFound {
        /// 服务端信息，可能为空。
        msg: String,
    },
    /// 其他业务错误码，原样上抛。
    #[error("网关业务错误 code={code}：{msg}")]
    Business {
        /// 业务码。
        code: i64,
        /// 服务端信息。
        msg: String,
    },
    /// 响应不是合法信封。
    #[error("网关信封非法：{0}")]
    MalformedEnvelope(String),
    /// 非 2xx 且无信封的 HTTP 响应。
    #[error("网关返回 HTTP {status}：{body}")]
    Http {
        /// HTTP 状态码。
        status: u16,
        /// 响应体（已截断）。
        body: String,
    },
    /// 客户端侧就把动作名或载荷拒了，不产生网络请求。
    #[error("非法的 v0 动作名或载荷：{0}")]
    InvalidAction(String),
}

impl From<tokio::time::error::Elapsed> for RpcError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        RpcError::Timeout
    }
}

/// 供 `GatewayClient` 使用的组合：建立连接 + 发送 + 解释。
pub(crate) async fn roundtrip(
    stream: &mut tokio::net::TcpStream,
    token: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<Value, RpcError> {
    let headers = [
        ("X-Gateway-Token", token),
        ("Content-Type", "application/json"),
    ];
    let response = http::request(stream, "POST", "/rpc", &headers, body, timeout).await?;
    interpret(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn envelope_success_returns_data() {
        let r = response(200, r#"{"code":0,"msg":"ok","data":{"sessions":[]}}"#);
        let data = interpret(&r).expect("成功信封应返回 data");
        assert_eq!(data["sessions"], Value::Array(Vec::new()));
    }

    #[test]
    fn action_not_found_maps_to_404_code() {
        let r = response(200, r#"{"code":404,"msg":"browser:open","data":null}"#);
        match interpret(&r) {
            Err(RpcError::ActionNotFound { msg }) => assert_eq!(msg, "browser:open"),
            other => panic!("期望 ActionNotFound，实际 {other:?}"),
        }
    }

    #[test]
    fn http_403_is_unauthorized_without_parsing_body() {
        let r = response(403, "nope");
        assert!(matches!(interpret(&r), Err(RpcError::Unauthorized)));
    }

    #[test]
    fn envelope_403_is_also_unauthorized() {
        let r = response(200, r#"{"code":403,"msg":"bad token","data":null}"#);
        assert!(matches!(interpret(&r), Err(RpcError::Unauthorized)));
    }

    #[test]
    fn envelope_408_is_timeout_and_other_codes_stay_business() {
        let r = response(200, r#"{"code":408,"msg":"gateway timeout","data":null}"#);
        assert!(matches!(interpret(&r), Err(RpcError::Timeout)));
        let r = response(200, r#"{"code":1042,"msg":"会话不存在","data":null}"#);
        match interpret(&r) {
            Err(RpcError::Business { code, msg }) => {
                assert_eq!(code, 1042);
                assert_eq!(msg, "会话不存在");
            }
            other => panic!("期望 Business，实际 {other:?}"),
        }
    }

    #[test]
    fn malformed_envelope_is_rejected() {
        let r = response(200, "<html>not json</html>");
        assert!(matches!(interpret(&r), Err(RpcError::MalformedEnvelope(_))));
        let r = response(200, r#"{"msg":"no code field"}"#);
        assert!(matches!(interpret(&r), Err(RpcError::MalformedEnvelope(_))));
    }

    #[test]
    fn non_2xx_without_envelope_becomes_http_error() {
        let r = response(500, "boom");
        match interpret(&r) {
            Err(RpcError::Http { status, body }) => {
                assert_eq!(status, 500);
                assert_eq!(body, "boom");
            }
            other => panic!("期望 Http，实际 {other:?}"),
        }
    }

    #[test]
    fn v0_action_names_are_accepted_and_others_rejected() {
        for action in [
            "session:list",
            "session:create",
            "session:get",
            "session:send",
            "session:stop",
            "approval:respond",
            "config:get",
            "config:set",
            "tool:list",
            "sys:ping",
        ] {
            assert!(is_valid_action(action), "{action} 应在 v0 动作面内");
        }
        for action in [
            "session",
            "session:",
            ":list",
            "a:b:c",
            "session list",
            "sys/PING",
        ] {
            assert!(!is_valid_action(action), "{action} 不是合法 域:动作");
        }
        assert!(is_valid_action("file:read_all"));
    }

    #[test]
    fn request_body_shape_is_action_plus_payload() {
        let body =
            encode_request("session:get", &serde_json::json!({"id": "s1"})).expect("编码成功");
        let value: Value = serde_json::from_slice(&body).expect("请求体是合法 JSON");
        assert_eq!(value["action"], "session:get");
        assert_eq!(value["payload"]["id"], "s1");
        assert!(
            encode_request("session:list", &Value::Null).is_ok(),
            "null 载荷在 v0 允许"
        );
        // 客户端只做「域:动作」语法校验，v0 动作面白名单归服务端：
        // 语法正确但未注册的动作照样编码发出，由网关回 404（见 §2 与本模块头部）。
        assert!(
            encode_request("browser:open", &Value::Null).is_ok(),
            "未注册但语法合法的动作由服务端判 404，不在客户端拦截"
        );
        assert!(matches!(
            encode_request("browser open", &Value::Null),
            Err(RpcError::InvalidAction(_))
        ));
    }
}
