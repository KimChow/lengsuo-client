//! [`ClientConfig`] 与 [`DEFAULT_HANDSHAKE_TIMEOUT`]：客户端侧的配置面，
//! 包含分帧、超时、帧上限、协议版本候选与握手时上报的 identity/capabilities。

use std::time::Duration;

use crate::codec::Framing;
use crate::error::Error;
use crate::protocol::{ClientCapabilities, Implementation, SUPPORTED_PROTOCOL_VERSIONS};
use crate::session::SessionConfig;

use super::command::StdioServerCommand;

/// `initialize` 握手的默认超时（比请求默认值略紧，握手不该慢）。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 客户端配置。
#[derive(Clone)]
pub struct ClientConfig {
    /// 分帧方式，默认行分隔。
    pub framing: Framing,
    /// 待 spawn 的 server 命令。
    pub command: StdioServerCommand,
    /// 每请求超时（也是会话默认超时），默认 30s
    /// （[`crate::session::SessionConfig::DEFAULT_TIMEOUT`]）。
    pub request_timeout: Duration,
    /// 握手超时，默认 [`DEFAULT_HANDSHAKE_TIMEOUT`]。
    pub handshake_timeout: Duration,
    /// 单帧字节上限，默认 8 MiB（见 [`crate::codec::DEFAULT_MAX_FRAME_BYTES`]）。
    pub max_frame_bytes: usize,
    /// 本地支持的协议版本，按优先级排列，默认规范最新优先。
    pub protocol_versions: Vec<String>,
    /// 客户端实现信息（`clientInfo`）。
    pub client_info: Implementation,
    /// 客户端能力声明（v0 一律为空，表示不响应服务端请求）。
    pub capabilities: ClientCapabilities,
    /// 通知广播通道容量（0 视为 1；订阅端滞后丢最旧，不阻塞读循环）。
    pub notification_capacity: usize,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("framing", &self.framing)
            .field("command", &self.command)
            .field("request_timeout", &self.request_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("protocol_versions", &self.protocol_versions)
            .field("client_info", &self.client_info)
            .field("notification_capacity", &self.notification_capacity)
            .finish_non_exhaustive()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            framing: Framing::default(),
            command: StdioServerCommand::new("mcp-server"),
            request_timeout: SessionConfig::DEFAULT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_frame_bytes: crate::codec::DEFAULT_MAX_FRAME_BYTES,
            protocol_versions: SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            client_info: Implementation {
                name: "lengsuo-agent-mcp".to_string(),
                title: None,
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            capabilities: ClientCapabilities::default(),
            notification_capacity: 256,
        }
    }
}

impl ClientConfig {
    /// 以命令与分帧创建配置。
    #[must_use]
    pub fn stdio(command: StdioServerCommand, framing: Framing) -> Self {
        Self {
            command,
            framing,
            ..Self::default()
        }
    }

    /// 设置每请求超时。
    ///
    /// # Errors
    /// [`Error::InvalidConfig`]：超时为 0。
    pub fn with_request_timeout(mut self, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfig {
                reason: "请求超时不能为 0".to_string(),
            });
        }
        self.request_timeout = timeout;
        Ok(self)
    }

    /// 设置握手超时。
    ///
    /// # Errors
    /// [`Error::InvalidConfig`]：超时为 0。
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfig {
                reason: "握手超时不能为 0".to_string(),
            });
        }
        self.handshake_timeout = timeout;
        Ok(self)
    }

    /// 设置通知广播通道容量（0 视为 1）。
    #[must_use]
    pub fn with_notification_capacity(mut self, capacity: usize) -> Self {
        self.notification_capacity = capacity.max(1);
        self
    }

    /// 覆盖本地支持的协议版本列表（测试与非标对端用）。
    #[must_use]
    pub fn with_protocol_versions<S: Into<String>>(mut self, versions: Vec<S>) -> Self {
        self.protocol_versions = versions.into_iter().map(Into::into).collect();
        self
    }

    /// 会话参数（分帧、帧上限、通知容量与默认超时）。握手与客户端信息留在
    /// 客户端侧：会话只负责一条连接上的报文流转。
    pub(crate) fn session_config(&self) -> SessionConfig {
        SessionConfig::new(
            self.framing,
            self.max_frame_bytes,
            self.notification_capacity,
            self.request_timeout,
        )
    }
}
