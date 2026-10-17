//! 能力层返回的只读数据结构（serde 可序列化，协议层可直接转 JSON）。

use serde::{Deserialize, Serialize};

/// `file:info` 结果。`modified_ms` 为 Unix 毫秒时间戳。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    pub size: u64,
    pub is_dir: bool,
    pub modified_ms: u64,
}

/// `file:list` 分页条目。`rel_path` 相对工作区，`/` 分隔。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    pub name: String,
    pub rel_path: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified_ms: u64,
}

/// `file:search` 命中项。`rel_path` 相对工作区，`/` 分隔。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub name: String,
    pub rel_path: String,
    pub is_dir: bool,
    pub size: u64,
}

/// `file:writeBatch` 的单个写操作。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteOp {
    pub path: String,
    pub content: String,
}

impl WriteOp {
    pub fn new(path: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
        }
    }
}

/// 从 metadata 取 Unix 毫秒修改时间；取不到（极旧时间戳等）归零。
pub(crate) fn modified_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        })
        .unwrap_or_default()
}
