//! MCP 客户端门面：配置、生命周期与协议面方法。
//!
//! 一次 [`McpClient`] 实例对应一条 stdio 连接与一个会话；[`McpClient::connect`]
//! 完成 `initialize` + `notifications/initialized` 握手，
//! [`McpClient::shutdown`] 完成 `shutdown` 请求 + `exit` 通知并回收子进程。
//!
//! 请求 id 只由 [`crate::session::Session`] 分配（会话内单调递增，取尽后
//! fail-closed）：客户端侧不再自己维护 id 计数，也不再把 id 传进会话层——
//! 一条连接上的并发请求因此不可能被两个调用方分配到同一个 id，迟到响应也
//! 不会被误认成别人的答案。
//!
//! 超时语义（v0 取舍，见 result.md）：每个请求带独立超时，默认取
//! [`ClientConfig::request_timeout`]（30s），握手用
//! [`ClientConfig::handshake_timeout`]；超时后会话被标记 poisoned——本地无法
//! 确定对端是否仍在处理该 id，迟到响应会破坏 id 语义，所以拒绝复用，由调用方
//! 重建客户端。v0 **不**自动重建：重建意味着重新握手与重新订阅通知，静默重试
//! 会让调用方看不清副作用发生在哪一条连接上。

mod command;
mod config;
mod connection;
mod notification;
mod request;
mod status;
mod tools;

pub use command::StdioServerCommand;
pub use config::{ClientConfig, DEFAULT_HANDSHAKE_TIMEOUT};
pub use connection::McpClient;
pub use notification::NotificationReceiver;
