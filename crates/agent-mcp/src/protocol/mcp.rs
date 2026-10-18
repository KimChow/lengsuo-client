//! MCP 协议面类型：initialize / tools / ping / progress。
//!
//! 只建模 v0 客户端实际用到的字段；未识别的扩展字段由 serde 忽略（不因对端
//! 多写字段而失败），缺失的必需字段则返回带字段名的类型化错误。
//!
//! 分三个子模块，此处统一 re-export，crate 内其它模块只写 `crate::protocol::X`：
//! - [`initialize`]：版本协商、能力声明与 `initialize` 参数/结果；
//! - [`tools`]：工具定义、列表分页与调用结果；
//! - [`progress`]：进度通知参数。

mod initialize;
mod progress;
mod tools;

pub use initialize::{
    ClientCapabilities, Implementation, InitializeParams, InitializeResult, ServerCapabilities,
    LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
pub use progress::ProgressParams;
pub use tools::{ContentBlock, Tool, ToolCallParams, ToolCallResult, ToolsListResult};

#[cfg(test)]
mod tests;
