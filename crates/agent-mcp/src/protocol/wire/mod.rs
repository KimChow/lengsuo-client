//! JSON-RPC 2.0 线格式：消息分类、入站/出站结构与线信封。
//!
//! 分三个子模块（单文件 700 行硬上限、400 行软目标）：
//! - [`types`]：纯类型定义（id、错误对象、消息与信封结构）。
//! - [`classify`]：报文分类与帧解析逻辑。
//! - [`tests`]：线格式测试。
//!
//! 对外路径不变：crate 内其它模块仍写 `crate::protocol::X` 或
//! `super::wire::X`（`shape` 等符号在模块级 re-export）。

mod classify;
mod types;

pub(crate) use classify::shape;
pub use classify::{classify, parse_wire_message};
pub use types::{
    Inbound, JsonRpcErrorObject, JsonRpcNotification, Notification, OutNotification, OutRequest,
    OutResponse, RequestId, Response, ResponsePayload, ServerRequest, WireMessage, INTERNAL_ERROR,
    INVALID_PARAMS, METHOD_NOT_FOUND,
};
pub(crate) use types::{NotificationEnvelope, RequestEnvelope};

#[cfg(test)]
mod tests;
