//! `agent-tools`：参考客户端 `file:*` 底层能力层的 Rust 实现。
//!
//! 工具（协议层）之下的能力层，把安全闸、回收站删除、组回滚与原子落盘
//! 收在一处：所有路径先过 `guard`，越出工作区即 `Denied`。
//! 同步 IO，不依赖 tokio；不使用 `unsafe`。

mod edit;
mod error;
mod fs_ops;
mod pathguard;
mod read;
mod search;
mod types;

#[cfg(test)]
mod testutil;

pub use error::ToolError;
pub use fs_ops::FsToolbox;
pub use types::{EntryInfo, FileInfo, SearchHit, WriteOp};

/// 单文件读取硬上限：8 MiB。`read` 的有效上限是 `max_bytes` 与本值取小。
pub const MAX_SINGLE_READ_BYTES: u64 = 8 * 1024 * 1024;
