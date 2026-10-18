//! 握手结果与连接状态的可观测面：initialize 产物、会话健康度与计数器。

use std::time::Duration;

use crate::codec::Framing;
use crate::protocol::{InitializeResult, ServerCapabilities, ServerRequest};

use super::McpClient;

impl McpClient {
    /// 握手返回的 `protocolVersion` 不在本地支持列表内时的显式拒绝。
    #[must_use]
    pub fn server_capabilities(&self) -> &ServerCapabilities {
        &self.result.capabilities
    }

    /// `initialize` 结果（版本、能力、serverInfo）。
    #[must_use]
    pub fn initialize_result(&self) -> &InitializeResult {
        &self.result
    }

    /// 握手时服务端返回的 `instructions`。
    #[must_use]
    pub fn instructions(&self) -> Option<&str> {
        self.result.instructions.as_deref()
    }

    /// 握手协商出的协议版本。
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.result.protocol_version
    }

    /// 本连接的分帧方式。
    #[must_use]
    pub fn framing(&self) -> Framing {
        self.session.framing()
    }

    /// 当前使用的每请求超时。
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        self.config.request_timeout
    }

    /// 连接是否已被标记 poisoned。
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.session.is_poisoned()
    }

    /// poisoned 原因（若有）。
    #[must_use]
    pub fn poison_reason(&self) -> Option<String> {
        self.session.poison_reason()
    }

    /// 会话是否已结束（对端 EOF 或本地关闭）；结束后不再接受请求。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.session.is_closed()
    }

    /// 无法匹配到在途请求的响应数量（超时后的迟到响应、陌生 id）。
    #[must_use]
    pub fn unmatched_responses(&self) -> u64 {
        self.session.unmatched_responses()
    }

    /// 被忽略的畸形消息数量（分帧仍对齐，不 poison）。
    #[must_use]
    pub fn ignored_messages(&self) -> u64 {
        self.session.ignored_messages()
    }

    /// 通知订阅端滞后导致丢弃的通知条数（会话级累计，跨订阅端共用一条计数）。
    #[must_use]
    pub fn notifications_dropped(&self) -> u64 {
        self.session.notify_dropped()
    }

    /// 是否已安装传输。握手成功的客户端恒为 `true`；该出口供上层在重建会话
    /// 或自定义传输（将来 HTTP/SSE）时做断言用。
    #[must_use]
    pub fn has_transport(&self) -> bool {
        self.session.has_transport()
    }

    /// 取出并清空已记录的服务端请求（v0 只记录并自动拒绝，不处理）。
    pub fn take_server_requests(&self) -> Vec<ServerRequest> {
        self.session.drain_server_requests()
    }
}
