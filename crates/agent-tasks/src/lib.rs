//! agent-tasks：会话内任务看板（对照 参考客户端 task 工具族 TaskCreate/Get/Update/List）。
//!
//! 只包含纯域逻辑（任务模型、状态机、看板与 JSON 契约），不依赖 tokio 或任何 IO 框架；
//! 会话存储与工具接入由上层（agent-core / agent-gateway）负责。
//! 规格源：worktree 根 `TASKS-SPEC.md`（字段名、方法签名与状态机均冻结）。

#![forbid(unsafe_code)]

mod board;
mod error;
mod task;

pub use board::{NowMs, TaskBoard};
pub use error::TaskError;
pub use task::{Task, TaskStatus};
