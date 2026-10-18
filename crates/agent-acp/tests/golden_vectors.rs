//! serde 金向量测试：每种消息 1 个 round-trip + 1 个按 wb 文档抄录/还原的
//! 真实样例 JSON 反序列化。
//!
//! 样例 JSON 的出处：
//! - control_request 信封形态 = 18 册 §2 原文逐字抄录（`{type:"control_request",
//!   request_id, request:{subtype:"elicitation_create",…}}`）；
//! - 方法名 = 27 册 §2 斜杠方法全表（session/new、session/prompt、session/update、
//!   session/cancel、elicitation/create、elicitation/complete）+ 18 册 §2 表
//!   （authenticate、session_set_mode→session/set_mode、request_permission）；
//! - 字段拼写 = 19 册 bundle 实证 camelCase（sessionId/toolCallId/sessionUpdate）
//!   与 27 册 §1 `_meta['codebuddy.ai/toolName']` 私有键。
//!
//! 文档未给出逐字 JSON 报文，样例按上述实证字段还原。
//! control_request 信封与帧编解码的测试按主题拆至同目录 `codec_control.rs`
//! （断言语义与原文件逐字一致，未改动）。

use agent_acp::{
    decode_message, encode_frame, AuthenticateParams, ContentBlock, ElicitationCompleteParams,
    ElicitationCreateParams, InitializeParams, InitializeResult, LoadSessionParams, Message,
    NewSessionParams, NewSessionResult, PermissionOutcome, PermissionOutcomeKind, PromptParams,
    PromptResult, RequestId, RequestPermissionParams, SessionNotification, SessionUpdate,
    SetSessionModeParams, StopReason, TextContent, ToolCallStatus, ToolCallUpdate, ToolKind,
    JSONRPC_ERROR_METHOD_NOT_FOUND,
};
use serde_json::{json, Value};

fn round_trip<T>(v: &T)
where
    T: PartialEq + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
{
    let text = serde_json::to_string(v).expect("序列化");
    let back: T = serde_json::from_str(&text).expect("反序列化");
    assert_eq!(&back, v);
}

/// 请求 round-trip 通用化：params 用强类型装进 Value。
fn request_round_trip(method: &str, params: &impl serde::Serialize) {
    let req = Message::Request(agent_acp::JsonRpcRequest::new(
        RequestId::Number(1),
        method,
        serde_json::to_value(params).expect("params 序列化"),
    ));
    let bytes = encode_frame(&req).expect("编码");
    let back = decode_message(&bytes).expect("解码");
    assert_eq!(req, back);
}

#[test]
fn initialize_round_trip_and_doc_sample() {
    let params = InitializeParams {
        protocol_version: 1,
        client_info: Some(agent_acp::Implementation {
            name: "lengsuo-client".into(),
            version: Some("0.1.0".into()),
        }),
        client_capabilities: Some(json!({"fs": {"readTextFile": true}})),
    };
    round_trip(&params);
    request_round_trip(agent_acp::method::INITIALIZE, &params);

    // 样例：18 册 §2 客户端→agent 面（B.authenticate 同族 initialize），
    // 字段名取文档关键词（client_info/capabilities），形态按 JSON-RPC 组装。
    let sample = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"reference-platform-desktop","version":"1.0.0"},"clientCapabilities":{"fs":{"readTextFile":true,"writeTextFile":true}}}}"#;
    let msg = decode_message(sample.as_bytes()).expect("样例解码");
    let Message::Request(req) = msg else {
        panic!("应为 Request，得到 {msg:?}");
    };
    assert_eq!(req.method, "initialize");
    let parsed: InitializeParams = req.params_as().expect("强类型 params");
    assert_eq!(parsed.protocol_version, 1);
    assert_eq!(
        parsed.client_info.as_ref().map(|i| i.name.as_str()),
        Some("reference-platform-desktop")
    );

    let result = InitializeResult {
        protocol_version: 1,
        agent_info: Some(agent_acp::Implementation {
            name: "codebuddy-cli".into(),
            version: None,
        }),
        agent_capabilities: Some(json!({"prompt": {"image": true}})),
        auth_methods: Some(vec![json!({"id": "terminal", "type": "stdio"})]),
    };
    round_trip(&result);
}

#[test]
fn authenticate_round_trip_and_doc_sample() {
    let params = AuthenticateParams {
        method_id: "terminal_auth".into(),
    };
    round_trip(&params);
    request_round_trip(agent_acp::method::AUTHENTICATE, &params);

    // 样例：18 册 B.authenticate；methodId 拼写照 ACP 现行 wire 形态。
    let sample = r#"{"jsonrpc":"2.0","id":"auth-1","method":"authenticate","params":{"methodId":"terminal_auth"}}"#;
    let Message::Request(req) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Request");
    };
    assert_eq!(req.id, RequestId::String("auth-1".into()));
    let parsed: AuthenticateParams = req.params_as().expect("params");
    assert_eq!(parsed.method_id, "terminal_auth");
}

#[test]
fn session_new_round_trip_and_doc_sample() {
    let params = NewSessionParams {
        cwd: "/home/user/project".into(),
        mcp_servers: Some(vec![json!({"name": "files", "command": "mcp-files"})]),
    };
    round_trip(&params);
    request_round_trip(agent_acp::method::SESSION_NEW, &params);

    // 样例：27 册 §2 `session/new`。
    let sample = r#"{"jsonrpc":"2.0","id":7,"method":"session/new","params":{"cwd":"/home/user/project","mcpServers":[{"name":"files","command":"mcp-files"}]}}"#;
    let Message::Request(req) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Request");
    };
    assert_eq!(req.method, "session/new");
    let parsed: NewSessionParams = req.params_as().expect("params");
    assert_eq!(parsed.cwd, "/home/user/project");

    let result = NewSessionResult {
        session_id: "sess-42".into(),
        modes: Some(json!({"current":"agent","available":[{"id":"plan"},{"id":"agent"}]})),
    };
    round_trip(&result);
}

#[test]
fn session_load_round_trip_and_doc_sample() {
    let params = LoadSessionParams {
        session_id: "sess-42".into(),
        cwd: "/home/user/project".into(),
    };
    round_trip(&params);
    request_round_trip(agent_acp::method::SESSION_LOAD, &params);

    // 样例：27 册 §2 `session/load`（19 册 §1 sessionId 实证）。
    let sample = r#"{"jsonrpc":"2.0","id":8,"method":"session/load","params":{"sessionId":"sess-42","cwd":"/home/user/project"}}"#;
    let Message::Request(req) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Request");
    };
    let parsed: LoadSessionParams = req.params_as().expect("params");
    assert_eq!(parsed.session_id, "sess-42");
}

#[test]
fn prompt_round_trip_and_doc_sample() {
    let params = PromptParams {
        session_id: "sess-42".into(),
        prompt: vec![ContentBlock::Text(TextContent::new("把报告改成中文"))],
    };
    round_trip(&params);
    request_round_trip(agent_acp::method::SESSION_PROMPT, &params);

    // 样例：27 册 §2 `session/prompt`（18 册 B.session_prompt 逐轮推进）。
    let sample = r#"{"jsonrpc":"2.0","id":9,"method":"session/prompt","params":{"sessionId":"sess-42","prompt":[{"type":"text","text":"把报告改成中文"}]}}"#;
    let Message::Request(req) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Request");
    };
    let parsed: PromptParams = req.params_as().expect("params");
    assert_eq!(parsed.prompt.len(), 1);

    let result = PromptResult {
        stop_reason: StopReason::EndTurn,
    };
    round_trip(&result);
}

#[test]
fn cancel_notification_round_trip_and_doc_sample() {
    let n = agent_acp::CancelNotification {
        session_id: "sess-42".into(),
    };
    round_trip(&n);
    let msg = Message::Notification(agent_acp::JsonRpcNotification::new(
        agent_acp::method::SESSION_CANCEL,
        serde_json::to_value(&n).expect("params"),
    ));
    let bytes = encode_frame(&msg).expect("编码");
    assert_eq!(msg, decode_message(&bytes).expect("解码"));

    // 样例：27 册 §2 `session/cancel`（通知族：无 id）。
    let sample = r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"sess-42"}}"#;
    let Message::Notification(notif) = decode_message(sample.as_bytes()).expect("样例解码")
    else {
        panic!("应为 Notification");
    };
    assert_eq!(notif.method, "session/cancel");
}

#[test]
fn session_update_all_variants_round_trip() {
    let updates = vec![
        SessionUpdate::AgentMessageChunk(ContentBlock::Text(TextContent::new("好的"))),
        SessionUpdate::AgentThoughtChunk(ContentBlock::Text(TextContent::new("先想想"))),
        SessionUpdate::UserMessageChunk(ContentBlock::Text(TextContent::new("继续"))),
        SessionUpdate::ToolCall(ToolCallUpdate {
            tool_call_id: "tc-1".into(),
            title: Some("读取 Cargo.toml".into()),
            kind: Some(ToolKind::Read),
            status: Some(ToolCallStatus::InProgress),
            raw_input: Some(json!({"path": "Cargo.toml"})),
            raw_output: None,
            meta: None,
        }),
        SessionUpdate::ToolCallUpdate(ToolCallUpdate {
            tool_call_id: "tc-1".into(),
            title: None,
            kind: None,
            status: Some(ToolCallStatus::Completed),
            raw_input: None,
            raw_output: Some(json!("[package]")),
            meta: Some(json!({"codebuddy.ai/toolName": "Read"})),
        }),
        SessionUpdate::Plan {
            entries: json!([{"content": "步骤一", "status": "pending"}]),
        },
        SessionUpdate::CurrentMode {
            mode_id: "plan".into(),
        },
        SessionUpdate::AvailableCommands {
            commands: json!([{"name": "/review"}]),
        },
    ];
    for u in &updates {
        round_trip(u);
    }

    // 19 册 §2 全目录逐个覆盖（agent_message_chunk / agent_thought_chunk /
    // user_message_chunk / tool_call / tool_call_update / plan / current_mode /
    // available_commands）。
    assert_eq!(updates.len(), 8);
}

#[test]
fn session_update_doc_sample_tool_call() {
    // 样例：19 册 §3 captureToolResultFromUpdate 实证字段
    // （u.sessionUpdate='tool_call_update'、toolCallId、_meta['codebuddy.ai/toolName']、
    //  status/rawInput/rawOutput）。
    let sample = r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"sess-42","update":{"sessionUpdate":"tool_call_update","toolCallId":"tc-1","status":"completed","rawOutput":"[package]","_meta":{"codebuddy.ai/toolName":"Read"}}}}"#;
    let Message::Notification(notif) = decode_message(sample.as_bytes()).expect("样例解码")
    else {
        panic!("应为 Notification");
    };
    assert_eq!(notif.method, "session/update");
    let parsed: SessionNotification = notif.params_as().expect("params");
    assert_eq!(parsed.session_id, "sess-42");
    let SessionUpdate::ToolCallUpdate(tc) = parsed.update else {
        panic!("应为 tool_call_update");
    };
    assert_eq!(tc.tool_call_id, "tc-1");
    assert_eq!(tc.status, Some(ToolCallStatus::Completed));
    assert_eq!(
        tc.meta
            .as_ref()
            .and_then(|m| m.get("codebuddy.ai/toolName"))
            .and_then(Value::as_str),
        Some("Read")
    );
}

#[test]
fn request_permission_round_trip_and_sample() {
    let params = RequestPermissionParams {
        session_id: "sess-42".into(),
        tool_call: ToolCallUpdate {
            tool_call_id: "tc-2".into(),
            title: Some("rm -rf target".into()),
            kind: Some(ToolKind::Execute),
            status: Some(ToolCallStatus::Pending),
            raw_input: Some(json!({"command": "rm -rf target"})),
            raw_output: None,
            meta: None,
        },
        options: vec![json!({"optionId": "allow", "name": "Allow", "kind": "allow_once"})],
    };
    round_trip(&params);
    request_round_trip(agent_acp::method::SESSION_REQUEST_PERMISSION, &params);

    // 样例：18 册 V.session_request_permission（权限闸协议层，agent→客户端请求）。
    let sample = r#"{"jsonrpc":"2.0","id":11,"method":"session/request_permission","params":{"sessionId":"sess-42","toolCall":{"toolCallId":"tc-2","title":"rm -rf target","kind":"execute","status":"pending"},"options":[{"optionId":"allow","name":"Allow","kind":"allow_once"}]}}"#;
    let Message::Request(req) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Request");
    };
    let parsed: RequestPermissionParams = req.params_as().expect("params");
    assert_eq!(parsed.tool_call.kind, Some(ToolKind::Execute));

    let outcome = PermissionOutcome {
        outcome: PermissionOutcomeKind::Selected,
        option_id: Some("allow".into()),
    };
    round_trip(&outcome);
}

#[test]
fn set_mode_round_trip_and_sample() {
    let params = SetSessionModeParams {
        session_id: "sess-42".into(),
        mode_id: "plan".into(),
    };
    round_trip(&params);
    request_round_trip(agent_acp::method::SESSION_SET_MODE, &params);

    // 样例：18 册 B.session_set_mode（wire 方法名按 27 册斜杠族写 session/set_mode）。
    let sample = r#"{"jsonrpc":"2.0","id":12,"method":"session/set_mode","params":{"sessionId":"sess-42","modeId":"plan"}}"#;
    let Message::Request(req) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Request");
    };
    let parsed: SetSessionModeParams = req.params_as().expect("params");
    assert_eq!(parsed.mode_id, "plan");
}

#[test]
fn elicitation_types_round_trip_and_sample() {
    let create = ElicitationCreateParams {
        session_id: "sess-42".into(),
        message: "请输入部署目标环境".into(),
        requested_schema: Some(json!({"type": "object"})),
    };
    round_trip(&create);
    let complete = ElicitationCompleteParams {
        session_id: "sess-42".into(),
        content: Some(json!({"env": "prod"})),
    };
    round_trip(&complete);

    // 样例：27 册 §2 elicitation/create / elicitation/complete 方法面。
    let sample = r#"{"jsonrpc":"2.0","id":13,"method":"elicitation/create","params":{"sessionId":"sess-42","message":"请输入部署目标环境","requestedSchema":{"type":"object"}}}"#;
    let Message::Request(req) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Request");
    };
    let parsed: ElicitationCreateParams = req.params_as().expect("params");
    assert_eq!(parsed.message, "请输入部署目标环境");
}

#[test]
fn response_error_round_trip_and_method_not_found() {
    let resp = Message::Response(agent_acp::JsonRpcResponse::err(
        RequestId::Number(3),
        agent_acp::JsonRpcErrorObject {
            code: JSONRPC_ERROR_METHOD_NOT_FOUND,
            message: "unknown method".into(),
            data: None,
        },
    ));
    let bytes = encode_frame(&resp).expect("编码");
    assert_eq!(resp, decode_message(&bytes).expect("解码"));

    // 样例：28 册实证 JSON-RPC -32601 应答形态（无 method 带 id + error）。
    let sample = r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"unknown method"}}"#;
    let Message::Response(r) = decode_message(sample.as_bytes()).expect("样例解码") else {
        panic!("应为 Response");
    };
    assert_eq!(r.error.as_ref().map(|e| e.code), Some(-32601));
}
