use crate::error::Error;
use crate::protocol::wire::{
    classify, parse_wire_message, Inbound, JsonRpcErrorObject, Notification, NotificationEnvelope,
    OutNotification, OutRequest, OutResponse, RequestEnvelope, RequestId, Response,
    ResponsePayload, WireMessage, METHOD_NOT_FOUND,
};
use serde_json::{json, Value};

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
