//! 本地网关客户端：握手文件 → `POST /rpc` → `GET /events`（WebSocket）。
//!
//! 模块划分（协议语义统一遵循 AGENT-KICKOFF.md §2）：
//! - [`handshake`]：读 `gateway.json`（`{port, pid, token}`）并校验。
//! - [`http`]：单连接 HTTP/1.1 最小子集。
//! - [`rpc`]：`/rpc` 请求体与 `{code, msg, data}` 信封，含错误映射表。
//! - [`events`]：`/events` 事件流，一行一个 JSON 解析为 typed enum。
//! - 本模块：把上面四层粘成 `GatewayClient`，并给出 v0 动作面的强类型入口。

pub mod events;
pub mod handshake;
pub mod http;
pub mod rpc;

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use tokio::net::TcpStream;

pub use self::events::{EventError, EventKind, EventSubscription, GatewayEvent};
pub use self::handshake::{GatewayHandshake, HandshakeError};
pub use self::rpc::{Envelope, RpcError, DEFAULT_TIMEOUT};

/// 只读地暴露 v0 动作名，避免壳层其他模块散落字符串字面量。
pub mod action {
    /// 会话列表。
    pub const SESSION_LIST: &str = "session:list";
    /// 创建会话。
    pub const SESSION_CREATE: &str = "session:create";
    /// 读取单个会话。
    pub const SESSION_GET: &str = "session:get";
    /// 向会话发送用户输入。
    pub const SESSION_SEND: &str = "session:send";
    /// 停止会话。
    pub const SESSION_STOP: &str = "session:stop";
    /// 审批应答。
    pub const APPROVAL_RESPOND: &str = "approval:respond";
    /// 读取配置。
    pub const CONFIG_GET: &str = "config:get";
    /// 写入配置。
    pub const CONFIG_SET: &str = "config:set";
    /// 工具列表。
    pub const TOOL_LIST: &str = "tool:list";
    /// 健康检查。
    pub const SYS_PING: &str = "sys:ping";
}

/// 网关客户端。token 只驻留内存，`Debug` 已脱敏。
#[derive(Clone)]
pub struct GatewayClient {
    addr: SocketAddr,
    token: String,
    timeout: Duration,
}

impl std::fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayClient")
            .field("addr", &self.addr)
            .field("token", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl GatewayClient {
    /// 由已校验的握手内容构造，地址固定为 `127.0.0.1:port`。
    #[must_use]
    pub fn from_handshake(handshake: GatewayHandshake) -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], handshake.port)),
            token: handshake.token,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// 读握手文件并构造客户端；文件缺失或非法直接失败（不回退任何默认端口）。
    pub async fn connect(path: &Path) -> Result<Self, HandshakeError> {
        let handshake = GatewayHandshake::load(path).await?;
        Ok(Self::from_handshake(handshake))
    }

    /// 覆盖单次操作超时（测试与慢网络场景用；默认 30s 来自协议冻结点）。
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 网关地址。
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// 操作超时。
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 发起一次 RPC。动作名在**联网之前**校验，非法动作不产生任何连接。
    pub async fn rpc(&self, action: &str, payload: Value) -> Result<Value, RpcError> {
        let body = rpc::encode_request(action, &payload)?;
        let timeout = self.timeout;
        let addr = self.addr;
        let token = self.token.as_str();
        tokio::time::timeout(timeout, async move {
            let mut stream = TcpStream::connect(addr)
                .await
                .map_err(|e| RpcError::Transport(http::HttpError::Io(e)))?;
            rpc::roundtrip(&mut stream, token, &body, timeout).await
        })
        .await
        .map_err(|_| RpcError::Timeout)?
    }

    /// 订阅 `GET /events`。握手同样带 `X-Gateway-Token`，缺失/错误由网关拒绝。
    pub async fn subscribe_events(&self) -> Result<EventSubscription, EventError> {
        let timeout = self.timeout;
        tokio::time::timeout(timeout, async {
            let stream = TcpStream::connect(self.addr)
                .await
                .map_err(|e| EventError::Transport(tokio_tungstenite::tungstenite::Error::Io(e)))?;
            EventSubscription::establish(stream, self.addr, &self.token).await
        })
        .await
        .map_err(|_| EventError::Timeout)?
    }

    /// `sys:ping`：健康检查。
    pub async fn sys_ping(&self) -> Result<Value, RpcError> {
        self.rpc(action::SYS_PING, Value::Null).await
    }

    /// `session:list`。
    pub async fn session_list(&self) -> Result<Value, RpcError> {
        self.rpc(action::SESSION_LIST, Value::Null).await
    }

    /// `session:create`：`payload` 由调用方给出（title/workspace_root/mode 等）。
    pub async fn session_create(&self, payload: Value) -> Result<Value, RpcError> {
        self.rpc(action::SESSION_CREATE, payload).await
    }

    /// `session:get`。
    pub async fn session_get(&self, id: &str) -> Result<Value, RpcError> {
        self.rpc(action::SESSION_GET, serde_json::json!({ "id": id }))
            .await
    }

    /// `session:send`。
    pub async fn session_send(&self, id: &str, content: &str) -> Result<Value, RpcError> {
        self.rpc(
            action::SESSION_SEND,
            serde_json::json!({ "id": id, "content": content }),
        )
        .await
    }

    /// `session:stop`。
    pub async fn session_stop(&self, id: &str) -> Result<Value, RpcError> {
        self.rpc(action::SESSION_STOP, serde_json::json!({ "id": id }))
            .await
    }

    /// `approval:respond`：`decision` 为 `allow`/`deny`（三态里的 `ask` 是网关侧策略，
    /// 不是 UI 能提交的回答）。
    pub async fn approval_respond(
        &self,
        session_id: &str,
        approval_id: &str,
        decision: &str,
    ) -> Result<Value, RpcError> {
        self.rpc(
            action::APPROVAL_RESPOND,
            serde_json::json!({
                "session_id": session_id,
                "approval_id": approval_id,
                "decision": decision,
            }),
        )
        .await
    }

    /// `config:get`。
    pub async fn config_get(&self, key: &str) -> Result<Value, RpcError> {
        self.rpc(action::CONFIG_GET, serde_json::json!({ "key": key }))
            .await
    }

    /// `config:set`。
    pub async fn config_set(&self, key: &str, value: Value) -> Result<Value, RpcError> {
        self.rpc(
            action::CONFIG_SET,
            serde_json::json!({ "key": key, "value": value }),
        )
        .await
    }

    /// `tool:list`。
    pub async fn tool_list(&self) -> Result<Value, RpcError> {
        self.rpc(action::TOOL_LIST, Value::Null).await
    }
}

/// IO 错误到 RPC 传输错误的便捷转换（供内部使用）。
impl From<io::Error> for RpcError {
    fn from(e: io::Error) -> Self {
        RpcError::Transport(http::HttpError::Io(e))
    }
}
