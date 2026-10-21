//! 错误类型归集：字节层 → 协议层 → 事件流 → 握手。
//!
//! 四个错误枚举原本各栖身于自己的模块（`http` / `rpc` / `events` / `handshake`），
//! 但它们构成的是**同一套失败语义**，下游（桌面壳 / 移动端）需要一次性看清
//! 「哪一层失败、该给用户什么提示」。归到一处后可以 `use lengsuo_ipc::error::*`。
//!
//! **原模块路径保持不变**：各模块仍以 `pub use` 转出本模块的类型
//! （`lengsuo_ipc::rpc::RpcError` / `lengsuo_ipc::http::HttpError` /
//! `lengsuo_ipc::events::EventError` / `lengsuo_ipc::handshake::HandshakeError`），
//! 已有引用方不需要改路径。
//!
//! 错误**文本逐字沿用**原实现，不做任何改写。

use std::io;
use std::path::Path;

/// 字节层错误。全部由调用方归因，本身不含网关语义。
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// 底层 IO 错误。
    #[error("网关连接 IO 错误")]
    Io(#[from] io::Error),
    /// 响应状态行非法（非 HTTP/1.x 或无状态码）。
    #[error("网关响应状态行非法")]
    BadStatusLine,
    /// 响应头无法解析。
    #[error("网关响应头非法")]
    BadHeaders,
    /// 响应体长度与声明不符，或分块编码非法，或未达上限前连接断开。
    #[error("网关响应体不完整或分块编码非法")]
    TruncatedBody,
    /// 响应超出 [`crate::http::MAX_RESPONSE_BYTES`]。
    #[error("网关响应超出上限 {0} 字节")]
    TooLarge(usize),
}

/// RPC 侧错误。鉴权与「动作未注册」分开，壳层据此给出不同 UI 提示。
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// 传输/字节层错误（连接失败、响应不完整、超时以外的 IO）。
    #[error("网关 RPC 传输错误")]
    Transport(#[from] HttpError),
    /// 客户端侧等待超时（默认 30s）。
    #[error("网关 RPC 超时")]
    Timeout,
    /// token 缺失或不匹配（HTTP 403 或信封 code 403）。
    #[error("网关鉴权拒绝：token 无效或缺失")]
    Unauthorized,
    /// 动作未注册（信封 code 404）。
    #[error("网关未注册该动作（{msg}）")]
    ActionNotFound {
        /// 服务端信息，可能为空。
        msg: String,
    },
    /// 其他业务错误码，原样上抛。
    #[error("网关业务错误 code={code}：{msg}")]
    Business {
        /// 业务码。
        code: i64,
        /// 服务端信息。
        msg: String,
    },
    /// 响应不是合法信封。
    #[error("网关信封非法：{0}")]
    MalformedEnvelope(String),
    /// 非 2xx 且无信封的 HTTP 响应。
    #[error("网关返回 HTTP {status}：{body}")]
    Http {
        /// HTTP 状态码。
        status: u16,
        /// 响应体（已截断）。
        body: String,
    },
    /// 客户端侧就把动作名或载荷拒了，不产生网络请求。
    #[error("非法的 v0 动作名或载荷：{0}")]
    InvalidAction(String),
}

impl From<tokio::time::error::Elapsed> for RpcError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        RpcError::Timeout
    }
}

/// 事件流错误。
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// WS 握手或读写传输错误。
    #[error("事件流传输错误")]
    Transport(#[from] tokio_tungstenite::tungstenite::Error),
    /// 连接/握手/单帧等待超时。
    #[error("事件流超时")]
    Timeout,
    /// 帧不是合法 JSON 或缺必填字段。错误文本不含原始帧内容，只含解析器摘要，
    /// 避免把可能带凭据的载荷写进日志（AGENTS.md §3）。
    #[error("事件帧解析失败：{reason}")]
    Malformed {
        /// 解析摘要。
        reason: String,
    },
    /// 非文本帧（binary/ping 之外的控制帧被当作数据交付时）。
    #[error("事件流收到非文本帧")]
    NotText,
    /// 未知事件名：协议缺口，不猜测语义。
    #[error("未知事件类型：{kind}")]
    UnknownKind {
        /// 原始名字。
        kind: String,
    },
    /// 网关关闭了事件流。
    #[error("事件流已被网关关闭")]
    Closed,
}

/// 握手文件读取/校验错误。错误信息只含路径与原因，不含 token。
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// 文件不存在。
    #[error("网关握手文件不存在：{path}")]
    NotFound {
        /// 出错的文件路径。
        path: String,
    },
    /// 其他 IO 错误（权限、磁盘等）。
    #[error("读取网关握手文件失败：{path}")]
    Io {
        /// 出错的文件路径。
        path: String,
        /// 底层 IO 错误。
        source: std::io::Error,
    },
    /// 内容非法：JSON 错误或字段校验失败，一律拒绝。
    #[error("网关握手文件非法：{path}（{reason}）")]
    Invalid {
        /// 出错的文件路径。
        path: String,
        /// 具体原因。
        reason: String,
    },
}

impl HandshakeError {
    /// 按 IO 错误种类分流：不存在与其他 IO 错误分开报。
    pub(crate) fn io(path: &Path, e: std::io::Error) -> Self {
        let path = path.display().to_string();
        if e.kind() == std::io::ErrorKind::NotFound {
            HandshakeError::NotFound { path }
        } else {
            HandshakeError::Io { path, source: e }
        }
    }
}
