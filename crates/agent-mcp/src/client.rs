//! MCP 客户端门面：配置、生命周期与协议面方法。
//!
//! 一次 [`McpClient`] 实例对应一条 stdio 连接与一个会话；[`McpClient::connect`]
//! 完成 `initialize` + `notifications/initialized` 握手，
//! [`McpClient::shutdown`] 完成 `shutdown` 请求 + `exit` 通知并回收子进程。
//!
//! 请求 id 只由 [`crate::session::Session`] 分配（会话内单调递增，取尽后
//! fail-closed）：客户端侧不再自己维护 id 计数，也不再把 id 传进会话层——
//! 一条连接上的并发请求因此不可能被两个调用方分配到同一个 id，迟到响应也
//! 不会被误认成别人的答案。
//!
//! 超时语义（v0 取舍，见 result.md）：每个请求带独立超时，默认取
//! [`ClientConfig::request_timeout`]（30s），握手用
//! [`ClientConfig::handshake_timeout`]；超时后会话被标记 poisoned——本地无法
//! 确定对端是否仍在处理该 id，迟到响应会破坏 id 语义，所以拒绝复用，由调用方
//! 重建客户端。v0 **不**自动重建：重建意味着重新握手与重新订阅通知，静默重试
//! 会让调用方看不清副作用发生在哪一条连接上。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::broadcast;

use crate::codec::Framing;
use crate::error::Error;
use crate::protocol::{
    ClientCapabilities, Implementation, InitializeParams, InitializeResult, JsonRpcNotification,
    ServerCapabilities, ServerRequest, ToolCallResult, ToolsListResult, LATEST_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::session::{Session, SessionConfig};
use crate::transport::StdioTransport;

/// `initialize` 握手的默认超时（比请求默认值略紧，握手不该慢）。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 退出阶段等待子进程的时间上限：到点由会话强杀。
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// 待 spawn 的 MCP server 命令。
#[derive(Debug, Clone)]
pub struct StdioServerCommand {
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

impl StdioServerCommand {
    /// 以可执行程序名创建命令。
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
        }
    }

    /// 追加命令行参数。
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// 追加环境变量（只增不改已有系统环境的其它项）。
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    pub(crate) fn args_slice(&self) -> &[String] {
        &self.args
    }

    pub(crate) fn env_iter(&self) -> &BTreeMap<String, String> {
        &self.env
    }
}

/// 服务端主动通知（`notifications/*` 等）的订阅端。
///
/// 订阅点是「建立订阅的那一刻」：之前的通知不回放（会话只在广播通道里保留
/// 在途消息）。订阅端滞后时丢最旧并累加 [`NotificationReceiver::lagged`]，
/// 绝不反压读循环。
#[derive(Debug)]
pub struct NotificationReceiver {
    rx: broadcast::Receiver<JsonRpcNotification>,
    lagged: u64,
}

impl NotificationReceiver {
    pub(crate) fn new(rx: broadcast::Receiver<JsonRpcNotification>) -> Self {
        Self { rx, lagged: 0 }
    }

    /// 取下一条通知；会话结束（广播通道关闭）时返回 `None`。
    ///
    /// 滞后不视为结束：跳过缺口继续收下一条。
    pub async fn recv(&mut self) -> Option<(String, Value)> {
        loop {
            match self.rx.recv().await {
                Ok(note) => return Some(into_pair(note)),
                Err(broadcast::error::RecvError::Lagged(_skipped)) => self.lagged += 1,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// 非阻塞取一条通知（测试与轮询用）。队列为空、或刚发生滞后跳过时返回
    /// `None`（滞后由 [`Self::lagged`] 计数，下一次调用继续收最新的一条）。
    #[must_use]
    pub fn try_recv(&mut self) -> Option<(String, Value)> {
        match self.rx.try_recv() {
            Ok(note) => Some(into_pair(note)),
            Err(broadcast::error::TryRecvError::Lagged(_skipped)) => {
                self.lagged += 1;
                None
            }
            Err(broadcast::error::TryRecvError::Empty)
            | Err(broadcast::error::TryRecvError::Closed) => None,
        }
    }

    /// 本订阅端因滞后被跳过的通知条数。
    #[must_use]
    pub fn lagged(&self) -> u64 {
        self.lagged
    }
}

fn into_pair(note: JsonRpcNotification) -> (String, Value) {
    (note.method, note.params.unwrap_or(Value::Null))
}

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

/// 一条已握手的 MCP stdio 连接。
pub struct McpClient {
    config: ClientConfig,
    session: Arc<Session>,
    result: InitializeResult,
    shutting_down: AtomicBool,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("framing", &self.config.framing)
            .field("server_info", &self.result.server_name())
            .field("protocol_version", &self.result.protocol_version)
            .field("poisoned", &self.session.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl McpClient {
    /// spawn server 并完成握手。
    ///
    /// # Errors
    /// [`Error::InvalidConfig`]：`protocol_versions` 为空；其余见
    /// [`Self::connect_with_notifications`] 的握手失败路径。
    pub async fn connect(config: ClientConfig) -> Result<Self, Error> {
        Ok(Self::establish(config, false).await?.0)
    }

    /// 握手并同时建立通知订阅端。
    ///
    /// 订阅在 `initialize` 发出之前建立，因此握手之后服务端推送的通知不会漏。
    ///
    /// # Errors
    /// 同 [`Self::connect`]。
    pub async fn connect_with_notifications(
        config: ClientConfig,
    ) -> Result<(Self, NotificationReceiver), Error> {
        let (client, receiver) = Self::establish(config, true).await?;
        // `with_notifications = true` 时订阅端必然随 establish 返回；取不到
        // 只会发生在订阅口已被占用的异常情形，此处以类型化错误收口而非 panic。
        let receiver = receiver.ok_or_else(|| Error::InvalidConfig {
            reason: "通知订阅端已被取走，无法再建立".to_string(),
        })?;
        Ok((client, receiver))
    }

    async fn establish(
        config: ClientConfig,
        with_notifications: bool,
    ) -> Result<(Self, Option<NotificationReceiver>), Error> {
        if config.protocol_versions.is_empty() {
            return Err(Error::InvalidConfig {
                reason: "protocol_versions 不能为空".to_string(),
            });
        }
        let session = Self::open_session(&config).await?;
        let receiver = with_notifications
            .then(|| NotificationReceiver::new(session.subscribe_notifications()));
        let handshake = Self::handshake(&session, &config).await;
        match handshake {
            Ok(result) => Ok((
                Self {
                    config,
                    session,
                    result,
                    shutting_down: AtomicBool::new(false),
                },
                receiver,
            )),
            Err(e) => {
                // 握手失败：丢弃半初始化连接，不留下未握手的会话或子进程。
                session.fail(&format!("握手失败：{e}"));
                session.abort().await;
                Err(e)
            }
        }
    }

    /// spawn 子进程并安装 stdio 传输（未握手）。
    async fn open_session(config: &ClientConfig) -> Result<Arc<Session>, Error> {
        let transport = StdioTransport::spawn(&config.command, &config.session_config()).await?;
        Ok(Arc::clone(transport.session()))
    }

    /// `initialize` + `notifications/initialized`，并做版本协商校验。
    async fn handshake(
        session: &Session,
        config: &ClientConfig,
    ) -> Result<InitializeResult, Error> {
        let params = InitializeParams {
            protocol_version: config
                .protocol_versions
                .first()
                .cloned()
                .unwrap_or_else(|| LATEST_PROTOCOL_VERSION.to_string()),
            capabilities: config.capabilities.clone(),
            client_info: config.client_info.clone(),
        };
        let payload = serde_json::to_value(&params).map_err(|e| Error::MalformedMessage {
            reason: format!("initialize 参数无法序列化：{e}"),
        })?;
        let result = session
            .request("initialize", Some(payload), Some(config.handshake_timeout))
            .await?;
        let initialized = InitializeResult::from_value_strict(&result)?;
        // 版本协商 fail-closed：对端返回的版本不在本地列表内即拒绝。
        initialized.validate_against(&config.protocol_versions)?;
        session.notify("notifications/initialized", None).await?;
        Ok(initialized)
    }

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

    /// 订阅服务端主动通知。可以在任何时候建立，每个订阅端独立；
    /// 建立之前的通知不回放。
    #[must_use]
    pub fn subscribe_notifications(&self) -> NotificationReceiver {
        NotificationReceiver::new(self.session.subscribe_notifications())
    }

    /// 发送任意方法请求（协议面之上的逃生口：扩展方法与测试夹具用）。
    ///
    /// `params` 为 `None` 时按规范省略该字段。id 由会话分配。
    ///
    /// # Errors
    /// 超时、poisoned、传输中断、帧损坏或对端 JSON-RPC error。
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, Error> {
        // 超时取会话默认值（由 ClientConfig::session_config 从 request_timeout 灌入），
        // 客户端不另存一份，避免两条路径上的超时配置分叉。
        self.session
            .request(method, params, Some(self.session.default_timeout()))
            .await
    }

    /// 发送通知（无 id、无响应）。
    ///
    /// # Errors
    /// 写侧失败或连接不可用。
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        self.session.notify(method, params).await
    }

    /// `ping`：空 `params`，成功即 `Ok(())`。
    ///
    /// # Errors
    /// 同 [`Self::request`]。
    pub async fn ping(&self) -> Result<(), Error> {
        self.request("ping", None).await?;
        Ok(())
    }

    /// `tools/list`。
    ///
    /// # Errors
    /// 同 [`Self::request`]，另加结果反序列化失败 → [`Error::MalformedMessage`]。
    pub async fn list_tools(&self) -> Result<ToolsListResult, Error> {
        self.list_tools_with(None).await
    }

    /// 带 cursor 的 `tools/list`（翻页）。
    pub async fn list_tools_with(&self, cursor: Option<&str>) -> Result<ToolsListResult, Error> {
        let params = match cursor {
            Some(c) => serde_json::json!({ "cursor": c }),
            None => serde_json::json!({}),
        };
        let value = self.request("tools/list", Some(params)).await?;
        serde_json::from_value(value).map_err(|e| Error::MalformedMessage {
            reason: format!("tools/list 结果不合法：{e}"),
        })
    }

    /// `tools/call`。工具层面的失败走 `result.isError`（不是 JSON-RPC error），
    /// 因此以 [`ToolCallResult`] 返回，不映射为错误。
    ///
    /// # Errors
    /// 同 [`Self::request`]，另加结果反序列化失败 → [`Error::MalformedMessage`]。
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<ToolCallResult, Error> {
        let params = serde_json::json!({
            "name": name,
            "arguments": arguments.unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        });
        let value = self.request("tools/call", Some(params)).await?;
        serde_json::from_value(value).map_err(|e| Error::MalformedMessage {
            reason: format!("tools/call 结果不合法：{e}"),
        })
    }

    /// `shutdown`：请求对端停止，随后发送 `exit` 通知并回收子进程。
    ///
    /// 幂等：重复调用只回收资源并返回 `Ok(())`。无论对端是否响应 `shutdown`，
    /// 都会尽力发送 `exit` 并终止子进程（fail-closed：不把未清理的进程留在
    /// 系统里），因此返回值只反映第一次调用的对端结果。
    ///
    /// # Errors
    /// 第一次调用时对端返回错误、或连接已 poisoned/中断（此时子进程仍已回收）。
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            let _ = self.session.close(EXIT_GRACE).await;
            return Ok(());
        }
        let outcome = self
            .session
            .request("shutdown", None, Some(self.config.request_timeout))
            .await;
        // 对端可能已在收到 shutdown 时退出：写失败属正常收尾，不覆盖 outcome。
        let _ = self.session.notify("exit", None).await;
        let closed = self.session.close(EXIT_GRACE).await;
        match (outcome, closed) {
            (Ok(_response), Ok(_status)) => Ok(()),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }

    /// 不强求对端配合的直接断开（不发送任何报文，直接强杀子进程）。
    pub async fn disconnect(&mut self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.session.abort().await;
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // 忘记 shutdown 时兜底：停 reader、关写侧（不阻塞当前线程）。子进程由
        // transport 的 `kill_on_drop` 回收，测试通过显式 shutdown/disconnect
        // 验证无残留。
        let _ = self.session.finalize_drop();
    }
}
