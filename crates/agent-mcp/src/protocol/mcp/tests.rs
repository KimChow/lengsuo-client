use serde_json::{json, Value};

use super::*;
use crate::error::Error;

#[test]
fn initialize_result_strict_requires_version_and_server_info() {
    let e = InitializeResult::from_value_strict(&json!({"capabilities": {}})).unwrap_err();
    assert!(matches!(
        e,
        Error::InvalidInitializeResult {
            field: "protocolVersion"
        }
    ));
    let e2 =
        InitializeResult::from_value_strict(&json!({"protocolVersion": "2025-06-18"})).unwrap_err();
    assert!(matches!(
        e2,
        Error::InvalidInitializeResult {
            field: "serverInfo"
        }
    ));
    let e3 = InitializeResult::from_value_strict(&json!("nope")).unwrap_err();
    assert!(matches!(e3, Error::MalformedMessage { .. }));
    let e4 = InitializeResult::from_value_strict(&json!({
        "protocolVersion": 1, "serverInfo": {"name":"s","version":"1"}
    }))
    .unwrap_err();
    assert!(matches!(
        e4,
        Error::InvalidInitializeResult {
            field: "protocolVersion"
        }
    ));
}

#[test]
fn initialize_result_tolerates_missing_capabilities_and_unknown_fields() {
    let r = InitializeResult::from_value_strict(&json!({
        "protocolVersion": "2024-11-05",
        "serverInfo": {"name": "fixture", "version": "0", "extra": 1},
        "futureField": {"a": 1}
    }))
    .unwrap();
    assert_eq!(r.protocol_version, "2024-11-05");
    assert_eq!(r.server_name(), "fixture");
    assert!(!r.capabilities.has_tools());
    assert!(r.instructions.is_none());
}

#[test]
fn version_negation_rejects_unsupported() {
    let r = InitializeResult {
        protocol_version: "1999-01-01".to_string(),
        capabilities: ServerCapabilities::default(),
        server_info: Some(Implementation {
            name: "s".into(),
            title: None,
            version: "1".into(),
        }),
        instructions: None,
    };
    let supported = SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    let e = r.validate_against(&supported).unwrap_err();
    assert!(matches!(e, Error::VersionMismatch(_)), "{e}");
    assert!(r.validate_against(&["1999-01-01".to_string()]).is_ok());
}

#[test]
fn tools_list_cursor_null_and_empty_are_no_next_page() {
    for raw in [
        json!({"tools": [], "nextCursor": Value::Null}),
        json!({"tools": [], "nextCursor": ""}),
        json!({"tools": []}),
    ] {
        let r: ToolsListResult = serde_json::from_value(raw).unwrap();
        assert!(!r.has_more());
    }
    let r: ToolsListResult =
        serde_json::from_value(json!({"tools": [{"name": "t"}], "nextCursor": "c1"})).unwrap();
    assert!(r.has_more());
    assert_eq!(r.tools[0].name, "t");
    assert_eq!(r.tools[0].input_schema, Value::Null);
}

#[test]
fn tool_call_result_handles_missing_and_unknown_content() {
    let r: ToolCallResult = serde_json::from_value(json!({})).unwrap();
    assert!(r.content.is_empty());
    assert!(!r.is_error);
    assert_eq!(r.combined_text(), "");
    let r2: ToolCallResult = serde_json::from_value(json!({
        "content": [
            {"type": "text", "text": "a"},
            {"type": "resource_link", "name": "x", "uri": "u", "mimeType": "text/plain"},
            {"type": "text", "text": "b"}
        ],
        "isError": true
    }))
    .unwrap();
    assert!(r2.is_error);
    assert_eq!(r2.content.len(), 3);
    assert!(matches!(r2.content[1], ContentBlock::Unknown));
    assert_eq!(r2.combined_text(), "a\nb");
}

#[test]
fn initialize_params_encode_camel_case() {
    let p = InitializeParams {
        protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
        capabilities: ClientCapabilities::default(),
        client_info: Implementation {
            name: "c".into(),
            title: Some("Client".into()),
            version: "1".into(),
        },
    };
    let s = serde_json::to_string(&p).unwrap();
    assert!(s.contains("\"protocolVersion\":\"2025-06-18\""), "{s}");
    assert!(
        s.contains("\"clientInfo\":{\"name\":\"c\",\"title\":\"Client\",\"version\":\"1\"}"),
        "{s}"
    );
    // 默认能力为空时仍写出 capabilities（规范必需字段）。
    assert!(s.contains("\"capabilities\":{}"), "{s}");
}

#[test]
fn progress_params_roundtrip() {
    let p: ProgressParams = serde_json::from_value(json!({
        "progressToken": "t1", "progress": 1.0, "total": 4.0, "message": "half"
    }))
    .unwrap();
    assert_eq!(p.progress, 1.0);
    assert_eq!(p.message.as_deref(), Some("half"));
    let minimal: ProgressParams =
        serde_json::from_value(json!({"progressToken": 3, "progress": 2.0})).unwrap();
    assert!(minimal.total.is_none() && minimal.message.is_none());
}
