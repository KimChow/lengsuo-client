#![forbid(unsafe_code)]
//! agent-mcp — MCP（Model Context Protocol）客户端 v0。
//!
//! 已有：
//! - JSON-RPC 2.0 帧编解码，两种分帧可选：`Content-Length` 头（LSP 式）与
//!   行分隔 JSON；运行期由 [`codec::Framing`] 参数选择，默认行分隔。
//! - stdio 传输：spawn 子进程，stdin/stdout 双向分帧，请求—响应按 id 关联，
//!   单连接并发复用，服务端主动通知与请求分别分发。
//! - 协议面：`initialize`（协议版本协商 + capability 交换）、`tools/list`
//!   （含 cursor 翻页）、`tools/call`、`ping`、`shutdown`；JSON-RPC error
//!   一律映射为类型化错误 [`error::Error::JsonRpc`]。
//! - 超时：每请求可配超时（默认 30s）；超时后连接标记 poisoned，后续请求
//!   直接 fail-closed，需重建客户端。
//!
//! 尚未实现（v0 范围外，见 result.md 遗留）：HTTP/SSE 传输、resources 与
//! prompts 面、completion、logging 之外的通知语义、progress 取消、
//! 服务端角色（本 crate 只做客户端）、真实第三方 MCP server 互通验收。
//! 本 crate 不能作为完整 MCP 实现发布；兼容性只由测试夹具证明。

pub mod client;
pub mod codec;
pub mod error;
pub mod protocol;
mod session;
mod transport;

pub use client::{ClientConfig, McpClient, NotificationReceiver};
pub use codec::Framing;
pub use error::Error;
pub use protocol::{
    ContentBlock, Implementation, InitializeParams, InitializeResult, JsonRpcErrorObject,
    JsonRpcNotification, ProgressParams, RequestId, Result as ProtocolResult, ServerCapabilities,
    ServerRequest, Tool, ToolCallParams, ToolCallResult, ToolsListResult, LATEST_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};

/// 帧与消息编解码的对外别名，避免与 `std::result::Result` 混淆。
pub type Result<T> = std::result::Result<T, error::Error>;
