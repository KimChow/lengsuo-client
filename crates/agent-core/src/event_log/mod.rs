//! EventLog：JSONL 追加实现与启动回放（开工说明 §5）。
//!
//! - 每会话一个文件 `events-<sessionUuid>.jsonl`，首行为文件头（带 `schemaVersion`）。
//! - `seq` 会话内单调递增；启动时扫描目录回放，恢复会话索引与 seq 计数器。
//! - 容错：断行/坏行丢弃、乱序按 seq 排序、重复 seq 只留先出现的；发现缺陷则整文件重写修复。
//! - fjall 实现后置（trait 已隔离，接口不变）。
//!
//! 按职责拆分：`format`（记录格式与行解析）、`jsonl`（内存索引与 `EventLog` 实现）、
//! `recovery`（启动回放与整文件修复）、`append`（追加落盘与文件头补齐）。

mod append;
mod format;
mod jsonl;
mod recovery;

pub use jsonl::JsonlEventLog;

use serde_json::Value;
use uuid::Uuid;

use crate::error::CoreError;
use crate::schema::Event;

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
