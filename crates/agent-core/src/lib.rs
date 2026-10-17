//! agent-core：智能体运行时核心域逻辑。
//!
//! 只包含纯域逻辑（会话/事件 schema、事件日志、工具注册表、权限门、脱敏），
//! 不依赖 tokio 或任何 IO 框架；网关层负责运行时与网络。
//! 规格源：worktree 根 `AGENT-KICKOFF.md` §3–§5。

pub mod blobs;
pub mod bus;
pub mod config;
pub mod error;
pub mod event_log;
pub mod permission;
pub mod provider;
pub mod redact;
pub mod runtime;
pub mod schema;
pub mod sensitive;
pub mod tool;
pub mod workspace_read;

pub use error::CoreError;
pub use event_log::{EventLog, JsonlEventLog};
pub use permission::{Decision, PermissionGate};
pub use provider::{Provider, ProviderStep, TurnContext};
pub use redact::Redactor;
pub use runtime::{CreateSession, Runtime, RuntimeBuilder, TurnReceipt};
pub use schema::{Event, Isolation, Message, Mode, PermissionMode, Role, Session, SCHEMA_VERSION};
pub use tool::{ToolRegistry, ToolSpec};
