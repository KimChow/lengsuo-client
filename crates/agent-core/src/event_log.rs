//! EventLog：JSONL 追加实现与启动回放（开工说明 §5）。
//!
//! - 每会话一个文件 `events-<sessionUuid>.jsonl`，首行为文件头（带 `schemaVersion`）。
//! - `seq` 会话内单调递增；启动时扫描目录回放，恢复会话索引与 seq 计数器。
//! - 容错：断行/坏行丢弃、乱序按 seq 排序、重复 seq 只留先出现的；发现缺陷则整文件重写修复。
//! - fjall 实现后置（trait 已隔离，接口不变）。

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use uuid::Uuid;

use crate::error::CoreError;
use crate::schema::{Event, SCHEMA_VERSION};

/// 单行字节上限：防止大输出打爆分页回溯（大结果走 `result_ref`）。
pub const MAX_LINE_BYTES: usize = 2 * 1024 * 1024;
/// 默认回放分页大小。
pub const DEFAULT_PAGE_LIMIT: usize = 500;

/// 事件日志抽象；实现者保证 `seq` 会话内单调。
pub trait EventLog: Send + Sync {
    /// 追加一条事件，返回带 seq/ts 的事件。
    fn append(&self, session_id: Uuid, kind: &str, payload: Value) -> Result<Event, CoreError>;

    /// 回放：返回 `seq > after_seq` 的最多 `limit` 条，按 seq 升序。
    fn replay(
        &self,
        session_id: Uuid,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Event>, CoreError>;

    /// 会话当前最大 seq；无事件返回 `None`。
    fn last_seq(&self, session_id: Uuid) -> Option<u64>;

    /// 已存在的会话（启动回放恢复的索引）。
    fn sessions(&self) -> Vec<Uuid>;
}

/// 单会话状态。
#[derive(Default)]
struct SessionState {
    events: BTreeMap<u64, Event>,
    next_seq: u64,
    path: PathBuf,
}

/// JSONL 追加实现。
pub struct JsonlEventLog {
    dir: PathBuf,
    inner: Mutex<Index>,
}

struct Index {
    sessions: BTreeMap<Uuid, SessionState>,
}

impl JsonlEventLog {
    /// 打开（或创建）日志目录并启动回放。
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, CoreError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| CoreError::Io {
            path: dir.clone(),
            source: e,
        })?;
        let mut index = Index {
            sessions: BTreeMap::new(),
        };
        for entry in std::fs::read_dir(&dir).map_err(|e| CoreError::Io {
            path: dir.clone(),
            source: e,
        })? {
            let entry = entry.map_err(|e| CoreError::Io {
                path: dir.clone(),
                source: e,
            })?;
            let path = entry.path();
            let Some(session_id) = session_id_of(&path) else {
                continue;
            };
            let (state, repaired) = load_session(&path, session_id)?;
            if repaired {
                rewrite(&path, session_id, &state.events)?;
            }
            index.sessions.insert(session_id, state);
        }
        Ok(Self {
            dir,
            inner: Mutex::new(index),
        })
    }

    fn path_for(&self, session_id: Uuid) -> PathBuf {
        self.dir.join(format!("events-{session_id}.jsonl"))
    }
}

impl EventLog for JsonlEventLog {
    fn append(&self, session_id: Uuid, kind: &str, payload: Value) -> Result<Event, CoreError> {
        // 一个串行临界区完成：seq 分配 → 行序列化与行长校验 → 落盘 → 内存索引提交。
        // 校验或落盘失败时直接返回，索引与 next_seq 保持原样，因此不会发布幽灵事件，
        // 也不会把别人的已提交 seq 回退（磁盘与内存始终一致）。
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| CoreError::InvalidConfig("日志索引锁毒化".into()))?;
        let fresh_session = !guard.sessions.contains_key(&session_id);
        let state = guard
            .sessions
            .entry(session_id)
            .or_insert_with(|| SessionState {
                path: self.path_for(session_id),
                ..Default::default()
            });
        let seq = state.next_seq + 1;
        if state.events.contains_key(&seq) {
            // 重复 seq 只可能来自外部写入的坏文件；不推进计数器、不落盘。
            return Err(CoreError::InvalidConfig(format!(
                "会话 {session_id} seq 重复: {seq}"
            )));
        }
        let event = Event {
            seq,
            session_id,
            kind: kind.to_string(),
            payload,
            ts_ms: now_ms(),
        };
        let line = serde_json::to_string(&event)?;
        if line.len() > MAX_LINE_BYTES {
            return Err(CoreError::LineTooLarge {
                limit: MAX_LINE_BYTES,
                actual: line.len(),
            });
        }
        let path = state.path.clone();
        if let Err(e) = append_line(&path, session_id, &line) {
            // 落盘失败：本次新建的空会话不留在索引里，视图与磁盘保持一致。
            if fresh_session {
                guard.sessions.remove(&session_id);
            }
            return Err(e);
        }
        let state = guard
            .sessions
            .get_mut(&session_id)
            .expect("落盘成功后索引仍在");
        state.next_seq = seq;
        state.events.insert(seq, event.clone());
        Ok(event)
    }

    fn replay(
        &self,
        session_id: Uuid,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Event>, CoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CoreError::InvalidConfig("日志索引锁毒化".into()))?;
        let Some(state) = guard.sessions.get(&session_id) else {
            return Ok(Vec::new());
        };
        Ok(state
            .events
            .range((after_seq + 1)..)
            .take(limit.clamp(1, DEFAULT_PAGE_LIMIT))
            .map(|(_, e)| e.clone())
            .collect())
    }

    fn last_seq(&self, session_id: Uuid) -> Option<u64> {
        let guard = self.inner.lock().ok()?;
        guard
            .sessions
            .get(&session_id)
            .and_then(|s| s.events.keys().next_back().copied())
    }

    fn sessions(&self) -> Vec<Uuid> {
        let guard = self
            .inner
            .lock()
            .map(|g| g.sessions.keys().copied().collect());
        guard.unwrap_or_default()
    }
}

/// 文件头行。
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeadLine {
    schema_version: u32,
    kind: String,
    session_id: String,
}

impl HeadLine {
    fn new(session_id: Uuid) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: "header".into(),
            session_id: session_id.to_string(),
        }
    }
}

/// 从文件名解析会话 id（非事件文件返回 `None`）。
fn session_id_of(path: &Path) -> Option<Uuid> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("events-")?.strip_suffix(".jsonl")?;
    Uuid::parse_str(rest).ok()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// 读取并规范化一个会话文件；返回（状态，是否修复过缺陷）。
fn load_session(path: &Path, session_id: Uuid) -> Result<(SessionState, bool), CoreError> {
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
        let Some(event) = parse_event(&value, session_id) else {
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

fn parse_event(value: &Value, session_id: Uuid) -> Option<Event> {
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

/// 整文件重写（发现缺陷时的修复路径）。
fn rewrite(path: &Path, session_id: Uuid, events: &BTreeMap<u64, Event>) -> Result<(), CoreError> {
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

/// 追加一行（必要时先补齐换行，保证半行不粘连）。
fn append_line(path: &Path, session_id: Uuid, line: &str) -> Result<(), CoreError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
        .map_err(|e| CoreError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    ensure_head(&mut file, session_id, path)?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| CoreError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

/// 新文件首行必须是文件头；已有文件若缺尾换行则补一个（避免粘成半行）。
fn ensure_head(file: &mut File, session_id: Uuid, path: &Path) -> Result<(), CoreError> {
    let size = file.seek(SeekFrom::End(0)).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if size == 0 {
        let head = serde_json::to_string(&HeadLine::new(session_id)).map_err(CoreError::Json)?;
        return file
            .write_all(head.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|e| CoreError::Io {
                path: path.to_path_buf(),
                source: e,
            });
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::End(-1)).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.read_exact(&mut last).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if last[0] != b'\n' {
        file.write_all(b"\n").map_err(|e| CoreError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    }
    Ok(())
}
