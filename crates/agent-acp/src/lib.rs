//! agent-acp — ACP（Agent Client Protocol）协议类型层（P1）。
//!
//! 依据 wb 逆向文档（18 册 §2、19 册 §2、27 册 §2）：桌面客户端与 CLI agent
//! 之间走标准 ACP（`@agentclientprotocol/sdk 0.25.0` 形态），**JSON-RPC 2.0 over
//! stdio**，方法名为斜杠族（`session/new`、`session/prompt`、`tasks/list`…），
//! 另有一层厂商私有 `control_request`/`control_notification` 信封
//! （18 册实证 `{type:"control_request", request_id, request:{subtype:...}}`）。
//!
//! 本 crate 是**零 IO 的纯类型层**：
//! - [`message`]：JSON-RPC 三分类（Request / Response / Notification）与 error 对象；
//! - [`methods`]：核心方法的 params/result 类型（initialize、authenticate、
//!   session 生命周期、prompt、cancel、session/update 通知、elicitation、权限）；
//! - [`control`]：`control_request`/`control_notification` 信封（subtype 开放枚举）；
//! - [`codec`]：行分隔 JSON 帧编解码（纯函数 + 增量解码状态机，不碰 socket）；
//! - [`error`]：编解码与类型层错误。
//!
//! 字段命名按 19 册 bundle 实证取 camelCase（`sessionId`/`toolCallId`/
//! `sessionUpdate`），扩展键 `_meta` 按 27 册命名空间保留。
//!
//! P2 预留：真实 stdio 传输接线、请求—响应路由与 id 关联、事件重放协议
//! （19 册 §4）、tasks 四方法与 `B.*` 全方法面的类型补全。见 result.md。

#![forbid(unsafe_code)]

pub mod codec;
pub mod control;
pub mod error;
pub mod message;
pub mod methods;

pub use codec::{
    decode_frame, decode_json, decode_message, encode_frame, LineDecoder, DEFAULT_MAX_LINE_BYTES,
};
pub use control::{
    ControlNotification, ControlRequest, ControlRequestBody, ControlResponse, ControlSubtype,
    TopLevel,
};
pub use error::Error;
pub use message::{
    JsonRpcErrorObject, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, JsonRpcVersion,
    Message, RequestId, JSONRPC_ERROR_INVALID_PARAMS, JSONRPC_ERROR_INVALID_REQUEST,
    JSONRPC_ERROR_METHOD_NOT_FOUND, JSONRPC_ERROR_PARSE,
};
pub use methods::{
    method, AuthenticateParams, CancelNotification, ContentBlock, ElicitationCompleteParams,
    ElicitationCreateParams, Implementation, InitializeParams, InitializeResult, InputContent,
    LoadSessionParams, LoadSessionResult, LogoutParams, NewSessionParams, NewSessionResult,
    PermissionOutcome, PermissionOutcomeKind, PromptParams, PromptResult, RequestPermissionParams,
    ResumeSessionParams, ResumeSessionResult, SessionId, SessionNotification, SessionUpdate,
    SetSessionModeParams, StopReason, TextContent, ToolCallStatus, ToolCallUpdate, ToolKind,
};

/// 编解码与类型层的统一 Result 别名。
pub type Result<T> = std::result::Result<T, error::Error>;
