//! `tool_result` 事件载荷兼容测试。
//!
//! 只读契约来源：`crates/agent-core/src/runtime.rs` 的 `record_tool_result` 发射
//! `json!({ "name": tool, "chars": ..., "resultRef": ..., "preview": ... })`
//! （键名 `resultRef` / `preview`），而壳 `SessionStreamState` 历史上只读
//! `text` / `content` 与 `result_ref`。本文件锁定两种形态：
//! - 真实 agent-core 载荷必须展示摘要与引用；
//! - 旧的 `text` / `content` + `result_ref` 形态继续可用（兼容不破坏）。
//!
//! 同时锁定一条安全边界：状态层只保存引用字符串，**不得**因存在引用而
//! 声称已读取文件内容（`content` 仍是摘要，不变成全文）。

use lengsuo_shell::state::{MessageRole, SessionMode, SessionStreamState};
use lengsuo_shell::{EventKind, GatewayEvent};
use serde_json::json;

/// 用 `serde_json::Value` 构造一条真实形态的网关事件（不依赖网关服务端）。
fn event(kind: EventKind, seq: u64, payload: serde_json::Value) -> GatewayEvent {
    GatewayEvent {
        seq,
        session_id: "s1".to_string(),
        kind,
        payload,
        ts_ms: 1_700_000_000_000 + seq,
    }
}

/// 起一个允许工具消息的会话流。
fn running() -> SessionStreamState {
    let mut state = SessionStreamState::new("s1", SessionMode::Craft);
    state
        .apply_event(event(EventKind::Text, 1, json!({ "text": "开始处理" })))
        .expect("seq=1 应被接受");
    state
}

#[test]
fn agent_core_payload_shape_is_displayed() {
    // 逐字段照抄 agent-core/runtime.rs::record_tool_result 的 json! 形态。
    let mut state = running();
    state
        .apply_event(event(
            EventKind::ToolResult,
            2,
            json!({
                "name": "fs.read",
                "chars": 65536usize,
                "resultRef": "blob-abc",
                "preview": "第一行摘要",
            }),
        ))
        .expect("真实 agent-core 载荷应被接受");

    let msg = state
        .messages()
        .iter()
        .rev()
        .find(|m| m.role == MessageRole::ToolResult)
        .expect("应追加一条 tool_result 消息");
    assert_eq!(
        msg.content, "第一行摘要",
        "preview 必须作为摘要正文显示，实际 {:?}",
        msg.content
    );
    let tool = msg.tool.clone().expect("tool_result 必须带工具引用");
    assert_eq!(tool.name, "fs.read");
    assert_eq!(
        tool.result_ref.as_deref(),
        Some("blob-abc"),
        "resultRef 必须映射到 ToolRef.result_ref"
    );
}

#[test]
fn legacy_text_and_result_ref_shape_still_works() {
    let mut state = running();
    state
        .apply_event(event(
            EventKind::ToolResult,
            2,
            json!({
                "name": "shell.exec",
                "text": "旧形态正文",
                "result_ref": "legacy-ref",
            }),
        ))
        .expect("旧 text 形态应继续可用");
    let msg = state
        .messages()
        .iter()
        .rev()
        .find(|m| m.role == MessageRole::ToolResult)
        .expect("消息");
    assert_eq!(msg.content, "旧形态正文");
    assert_eq!(
        msg.tool.as_ref().expect("tool").result_ref.as_deref(),
        Some("legacy-ref")
    );

    let mut state = running();
    state
        .apply_event(event(
            EventKind::ToolResult,
            2,
            json!({ "name": "shell.exec", "content": "content 形态正文" }),
        ))
        .expect("旧 content 形态应继续可用");
    let msg = state
        .messages()
        .iter()
        .rev()
        .find(|m| m.role == MessageRole::ToolResult)
        .expect("消息");
    assert_eq!(msg.content, "content 形态正文");
    assert_eq!(msg.tool.as_ref().expect("tool").result_ref, None);
}

#[test]
fn preview_only_when_no_reference_stays_inline() {
    // 小结果：agent-core 不发 resultRef（Value::Null），preview 即全部可见内容。
    let mut state = running();
    state
        .apply_event(event(
            EventKind::ToolResult,
            2,
            json!({ "name": "fs.read", "chars": 4usize, "resultRef": null, "preview": "abcd" }),
        ))
        .expect("无引用的小结果应被接受");
    let msg = state
        .messages()
        .iter()
        .rev()
        .find(|m| m.role == MessageRole::ToolResult)
        .expect("消息");
    assert_eq!(msg.content, "abcd");
    assert_eq!(msg.tool.as_ref().expect("tool").result_ref, None);
}

#[test]
fn reference_is_not_treated_as_file_content() {
    // 有 resultRef 时 content 只能是 preview 摘要，不得被展开成"已读取"的全文。
    let full = "y".repeat(4096);
    let preview: String = full.chars().take(512).collect();
    let mut state = running();
    state
        .apply_event(event(
            EventKind::ToolResult,
            2,
            json!({
                "name": "fs.read",
                "chars": full.chars().count(),
                "resultRef": "blob-huge",
                "preview": preview,
            }),
        ))
        .expect("大结果事件应被接受");
    let msg = state
        .messages()
        .iter()
        .rev()
        .find(|m| m.role == MessageRole::ToolResult)
        .expect("消息");
    assert_eq!(msg.content.len(), 512, "状态层只保存摘要");
    assert_ne!(msg.content, full, "引用不等于读取全文");
    assert!(
        msg.tool.as_ref().expect("tool").result_ref.is_some(),
        "引用必须原样保留供后续显式读取"
    );
}

#[test]
fn quick_mode_rejects_tool_result_without_mutating_state() {
    let mut state = SessionStreamState::new("s1", SessionMode::Quick);
    state
        .apply_event(event(EventKind::Text, 1, json!({ "text": "hi" })))
        .expect("seq=1");
    let before = state.messages().to_vec();
    let err = state
        .apply_event(event(
            EventKind::ToolResult,
            2,
            json!({ "name": "fs.read", "preview": "p", "resultRef": "r" }),
        ))
        .expect_err("quick 模式不显示工具消息");
    assert!(matches!(
        err,
        lengsuo_shell::state::StateError::InvalidTransition { .. }
    ));
    assert_eq!(
        state.messages().to_vec(),
        before,
        "被拒绝的事件不得污染消息"
    );
}
