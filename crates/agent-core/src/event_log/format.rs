//! 记录格式：文件头行、会话文件名解析、事件行解析与时间戳。

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use uuid::Uuid;

use crate::schema::{Event, SCHEMA_VERSION};

/// 文件头行。
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HeadLine {
    pub(crate) schema_version: u32,
    pub(crate) kind: String,
    pub(crate) session_id: String,
}

impl HeadLine {
    pub(crate) fn new(session_id: Uuid) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: "header".into(),
            session_id: session_id.to_string(),
        }
    }
}

/// 从文件名解析会话 id（非事件文件返回 `None`）。
pub(crate) fn session_id_of(path: &Path) -> Option<Uuid> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("events-")?.strip_suffix(".jsonl")?;
    Uuid::parse_str(rest).ok()
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

pub(crate) fn parse_event(value: &Value, session_id: Uuid) -> Option<Event> {
    let seq = value.get("seq")?.as_u64()?;
    let kind = value.get("kind")?.as_str()?.to_string();
    let sid = value.get("sessionId")?.as_str()?;
    if Uuid::parse_str(sid).ok()? != session_id {
        return None;
    }
    let payload = value.get("payload").cloned().unwrap_or(Value::Null);
    let ts_ms = value
        .get("tsMs")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    Some(Event {
        seq,
        session_id,
        kind,
        payload,
        ts_ms,
    })
}
