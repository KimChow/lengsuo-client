//! 网关事件载荷（JSON）的只读探测：文本提取与字段取值。
//!
//! 本层只取摘要文本与引用句柄，不据引用读取内容（AGENTS.md §3）。

use crate::gateway::GatewayEvent;

/// 事件文本：优先 `text`，其次 `content`，都没有则为空。
pub(super) fn extract_text(event: &GatewayEvent) -> String {
    field_str(event, "text")
        .or_else(|| field_str(event, "content"))
        .unwrap_or_default()
}

/// `tool_result` 正文：优先 agent-core 真实形态的 `preview`，其次旧形态
/// `text` / `content`（由 `extract_text` 得出），都没有则为空。
///
/// 只取摘要文本：状态层不会因为存在引用而展开或读取全文（AGENTS.md §3）。
pub(super) fn extract_tool_result_text(event: &GatewayEvent, fallback: &str) -> String {
    match field_str(event, "preview") {
        Some(preview) => preview,
        None => fallback.to_string(),
    }
}

/// `tool_result` 结果引用：优先 agent-core 真实形态的 `resultRef`，其次旧形态
/// `result_ref`。两者都没有时为 `None`（引用只是句柄，本层不据此读取内容）。
pub(super) fn tool_result_ref(event: &GatewayEvent) -> Option<String> {
    field_str(event, "resultRef").or_else(|| field_str(event, "result_ref"))
}

/// 从 `payload` 取字符串字段。
pub(super) fn field_str(event: &GatewayEvent, key: &str) -> Option<String> {
    event
        .payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// 从 `payload` 取整数字段。
pub(super) fn field_u64(event: &GatewayEvent, key: &str) -> Option<u64> {
    event.payload.get(key).and_then(serde_json::Value::as_u64)
}
