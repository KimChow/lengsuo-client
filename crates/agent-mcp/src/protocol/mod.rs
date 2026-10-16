//! MCP v0 协议面类型：JSON-RPC 2.0 消息分类 + initialize / tools / ping。
//!
//! 分两个子模块（单文件 700 行硬上限）：
//! - [`wire`]：与 MCP 无关的 JSON-RPC 2.0 线格式（id、错误对象、请求/通知/
//!   响应分类、写侧信封）。
//! - [`mcp`]：MCP 语义类型（版本协商、能力、工具面、进度通知）。
//!
//! 此处统一 re-export，crate 内其它模块只写 `crate::protocol::X`。

mod mcp;
mod wire;

pub use mcp::{
    ClientCapabilities, ContentBlock, Implementation, InitializeParams, InitializeResult,
    ProgressParams, ServerCapabilities, Tool, ToolCallParams, ToolCallResult, ToolsListResult,
    LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
pub use wire::{
    classify, parse_wire_message, Inbound, JsonRpcErrorObject, JsonRpcNotification, Notification,
    OutNotification, OutRequest, OutResponse, RequestId, Response, ResponsePayload, ServerRequest,
    WireMessage, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND,
};
pub(crate) use wire::{NotificationEnvelope, RequestEnvelope};

/// MCP 结果对象的通用承载（避免与 `std::result::Result` 混淆，线格式一律
/// 用 `serde_json::Value`，由上层解析为具体类型）。
pub type Result = serde_json::Value;
