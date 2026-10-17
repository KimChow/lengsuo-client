//! 类型化错误。所有解码、协议与传输失败都归一到 [`Error`]，调用方不需要
//! 匹配字符串；错误文本只携带长度、方法名与错误码等元数据，不输出工具
//! 结果内容（工具结果可能含用户数据）。

/// 协议版本协商失败：本地支持列表与对端提议无交集。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("协议版本协商失败：对端返回 {server_offered}，本地支持 {local_supported:?}")]
pub struct VersionMismatch {
    pub server_offered: String,
    pub local_supported: Vec<String>,
}

/// MCP 客户端错误集合。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// JSON-RPC 响应带 `error` 对象（含 method not found、invalid params、
    /// 内部错误与实现自定义码）。fail-closed：不重试、不回退。
    #[error("对端返回 JSON-RPC 错误 code={code} message={message}")]
    JsonRpc {
        code: i64,
        message: String,
        /// `error.data` 原样保留（可能是字符串或对象）；无 data 时为 `None`。
        data: Option<String>,
    },

    /// 握手返回的 `protocolVersion` 不在本地支持列表内。
    #[error(transparent)]
    VersionMismatch(#[from] Box<VersionMismatch>),

    /// `initialize` 响应缺少必需字段。
    #[error("initialize 响应缺少必需字段：{field}")]
    InvalidInitializeResult { field: &'static str },

    /// 帧解码失败：非法 UTF-8、非法头、超长帧或非 JSON 内容。
    /// 一旦发生，该流已无法重新对齐，调用方必须丢弃连接。
    #[error("帧解码失败：{reason}")]
    MalformedFrame { reason: String },

    /// 消息可解码但不是合法 JSON-RPC 2.0 消息（缺 `jsonrpc`、既无
    /// `method` 又无 `result`/`error`、`id` 类型非法等）。
    #[error("不是合法 JSON-RPC 2.0 消息：{reason}")]
    MalformedMessage { reason: String },

    /// 服务端写入的帧超出配置的字节上限。
    #[error("帧长度 {length} 超过上限 {max}，拒绝读取")]
    FrameTooLarge { length: usize, max: usize },

    /// 单请求超时：连接已标记 poisoned，后续请求会以 [`Error::Poisoned`] 拒绝。
    #[error("请求超时（{elapsed_ms}ms 上限），连接已标记为 poisoned")]
    Timeout { elapsed_ms: u64 },

    /// 连接处于 poisoned 状态（超时或帧损坏后），拒绝复用。
    #[error("连接已 poisoned（{reason}），必须重建客户端")]
    Poisoned { reason: String },

    /// 子进程 stdin 写入失败，或对端退出/EOF 导致连接中断。
    #[error("传输中断：{reason}")]
    Transport { reason: String },

    /// 对端（服务端）发起的请求。v0 未实现服务端请求处理策略，显式失败，
    /// 不静默丢弃，以免破坏对端会话状态。
    #[error("收到服务端发起的请求 method={method}，v0 不支持处理")]
    ServerRequestUnsupported { method: String },

    /// 参数或配置非法（例如空协议版本列表、id 取尽）。
    #[error("参数或配置非法：{reason}")]
    InvalidConfig { reason: String },
}

impl Error {
    /// 构造 [`Error::VersionMismatch`]。
    #[must_use]
    pub fn version_mismatch(
        server_offered: impl Into<String>,
        local_supported: Vec<String>,
    ) -> Self {
        Self::VersionMismatch(Box::new(VersionMismatch {
            server_offered: server_offered.into(),
            local_supported,
        }))
    }

    /// 是否为“连接不再可信”类错误（超时、poisoned、帧损坏、传输中断）。
    /// 上层可据此决定丢弃并重建客户端。
    #[must_use]
    pub fn is_connection_fatal(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. }
                | Self::Poisoned { .. }
                | Self::MalformedFrame { .. }
                | Self::FrameTooLarge { .. }
                | Self::Transport { .. }
        )
    }
}
