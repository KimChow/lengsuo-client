//! 启动回放与缺陷修复：读取规范化会话文件、整文件重写。

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use serde_json::Value;
use uuid::Uuid;

use crate::error::CoreError;
use crate::event_log::format::{self, HeadLine};
use crate::event_log::jsonl::SessionState;
use crate::schema::{Event, SCHEMA_VERSION};

/// 读取并规范化一个会话文件；返回（状态，是否修复过缺陷）。
pub(crate) fn load_session(
    path: &Path,
    session_id: Uuid,
) -> Result<(SessionState, bool), CoreError> {
    let mut raw = String::new();
    let mut file = File::open(path).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.read_to_string(&mut raw).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut lines = raw.lines().filter(|l| !l.trim().is_empty());
    let mut events: BTreeMap<u64, Event> = BTreeMap::new();
    let mut repaired = false;
    let mut seen = 0usize;
    let mut expected = 0usize;
    let mut last_seq = 0u64;
    let Some(first) = lines.next() else {
        return Ok((
            SessionState {
                events,
                next_seq: 0,
                path: path.to_path_buf(),
            },
            false,
        ));
    };
    match serde_json::from_str::<HeadLine>(first) {
        Ok(head) if head.kind == "header" => {
            if head.schema_version != SCHEMA_VERSION {
                return Err(CoreError::SchemaVersion {
                    found: head.schema_version,
                    supported: SCHEMA_VERSION,
                });
            }
            if head.session_id != session_id.to_string() {
                repaired = true;
            }
        }
        _ => {
            return Err(CoreError::SchemaVersion {
                found: 0,
                supported: SCHEMA_VERSION,
            })
        }
    }
    for line in lines {
        expected += 1;
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            repaired = true;
            continue;
        };
        let Some(event) = format::parse_event(&value, session_id) else {
            repaired = true;
            continue;
        };
        if event.seq <= last_seq {
            repaired = true; // 乱序
        }
        last_seq = last_seq.max(event.seq);
        if let std::collections::btree_map::Entry::Vacant(v) = events.entry(event.seq) {
            v.insert(event);
        } else {
            repaired = true; // 重复 seq，保留先出现的
        }
        seen += 1;
    }
    if seen != expected {
        repaired = true;
    }
    // 尾部必须是完整行
    if !raw.is_empty() && !raw.ends_with('\n') {
        repaired = true;
    }
    let _ = seen;
    Ok((
        SessionState {
            events,
            next_seq: last_seq,
            path: path.to_path_buf(),
        },
        repaired,
    ))
}

/// 整文件重写（发现缺陷时的修复路径）。
pub(crate) fn rewrite(
    path: &Path,
    session_id: Uuid,
    events: &BTreeMap<u64, Event>,
) -> Result<(), CoreError> {
    let tmp = path.with_extension("jsonl.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| CoreError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    let head = serde_json::to_string(&HeadLine::new(session_id)).map_err(CoreError::Json)?;
    file.write_all(head.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| CoreError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    for event in events.values() {
        let line = serde_json::to_string(event).map_err(CoreError::Json)?;
        file.write_all(line.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|e| CoreError::Io {
                path: tmp.clone(),
                source: e,
            })?;
    }
    file.sync_data().ok();
    std::fs::rename(&tmp, path).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}
