//! 共用小工具：写/执行工具判定、结果回填消息、可见工具面、事件发射与时钟。

use serde_json::{json, Value};

use crate::mode::WRITE_TOOLS;
use crate::schema::Event;

use super::AgentLoop;

/// 写/执行类工具判定。
pub(super) fn is_write_tool(name: &str) -> bool {
    WRITE_TOOLS.contains(&name)
}

/// 工具结果消息（大结果由宿主落盘为引用，本层只回填 JSON）。
pub(super) fn tool_result(id: &str, name: &str, result: &Value, is_error: bool) -> Value {
    json!({
        "role": "tool_result",
        "content": result.to_string(),
        "tool": {"id": id, "name": name, "isError": is_error},
    })
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

impl<'a> AgentLoop<'a> {
    pub(super) fn tool_defs(&self) -> Vec<Value> {
        self.policy
            .tools
            .iter()
            .map(|name| json!({"name": name}))
            .collect()
    }

    /// 发一个事件（seq 会话内单调递增）。
    pub(super) fn emit(&mut self, kind: &str, payload: Value) {
        self.seq += 1;
        (self.emit)(Event {
            seq: self.seq,
            session_id: self.session_id,
            kind: kind.to_string(),
            payload,
            ts_ms: now_ms(),
        });
    }
}
