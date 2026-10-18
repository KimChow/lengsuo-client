//! 内存索引与 `EventLog` 实现：锁内单临界区的原子 append、分页回放。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::Value;
use uuid::Uuid;

use crate::error::CoreError;
use crate::event_log::append::append_line;
use crate::event_log::format;
use crate::event_log::recovery;
use crate::event_log::{EventLog, DEFAULT_PAGE_LIMIT, MAX_LINE_BYTES};
use crate::schema::Event;

/// 单会话状态。
#[derive(Default)]
pub(crate) struct SessionState {
    pub(crate) events: BTreeMap<u64, Event>,
    pub(crate) next_seq: u64,
    pub(crate) path: PathBuf,
}

/// JSONL 追加实现。
pub struct JsonlEventLog {
    dir: PathBuf,
    inner: Mutex<Index>,
}

pub(crate) struct Index {
    pub(crate) sessions: BTreeMap<Uuid, SessionState>,
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
            let Some(session_id) = format::session_id_of(&path) else {
                continue;
            };
            let (state, repaired) = recovery::load_session(&path, session_id)?;
            if repaired {
                recovery::rewrite(&path, session_id, &state.events)?;
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
        // 也不会把别人的已提交 seq 回退；部分磁盘写入仍由启动恢复处理。
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
            ts_ms: format::now_ms(),
        };
        let line = serde_json::to_string(&event)?;
        if line.len() > MAX_LINE_BYTES {
            if fresh_session {
                guard.sessions.remove(&session_id);
            }
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
