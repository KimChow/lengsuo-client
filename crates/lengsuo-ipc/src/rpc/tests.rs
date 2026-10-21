//! `rpc` 模块的单元测试：只测信封映射与动作名语法，不走 socket。
//!
//! 走真 socket 的回环用例在 `crates/lengsuo-ipc/tests/gateway_roundtrip.rs`。

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
    let body = encode_request("session:get", &serde_json::json!({"id": "s1"})).expect("编码成功");
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
