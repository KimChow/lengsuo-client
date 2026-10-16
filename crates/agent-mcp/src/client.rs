//! MCP 客户端门面：配置、生命周期与协议面方法。
//!
//! 一次 [`McpClient`] 实例对应一条 stdio 连接与一个会话；`connect()` 完成
//! `initialize` + `notifications/initialized` 握手，`shutdown()` 完成
//! `shutdown` 请求 + `exit` 通知并回收子进程。
//!
//! 超时语义（v0 取舍，见 result.md）：每个请求带独立超时，默认 30s；超时后
//! 连接标记 poisoned——因为无法确定对端是否仍在处理该请求，迟到响应会破坏
//! id 语义，所以拒绝复用，由调用方重建客户端（配置 `rebuild_on_poison` 时
//! 由 [`McpClient::call_tool`] 等自动重建一次）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::codec::Framing;
use crate::error::Error;
use crate::protocol::{
    ClientCapabilities, Implementation, InitializeParams, InitializeResult, OutNotification,
    OutRequest, RequestId, ToolsListResult, LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::session::{Session, SessionBuilder, SessionConfig};
use crate::transport::StdioTransport;

/// `initialize` 握手的默认超时（比请求默认值略紧，握手不该慢）。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
#[derive(Debug)]
pub struct NotificationReceiver {
    rx: Arc<Mutex<mpsc::UnboundedReceiver<(String, Value)>>>,
}

impl NotificationReceiver {
    /// 取下一条通知；发送端已关闭（连接结束）时返回 `None`。
    pub async fn recv(&mut self) -> Option<(String, Value)> {
        self.rx.lock().ok()?.recv().await
    }

    /// 非阻塞取一条通知（测试与轮询用）。
    #[must_use]
    pub fn try_recv(&mut self) -> Option<(String, Value)> {
        self.rx.lock().ok()?.try_recv().ok()
    }
}

/// 客户端配置。
#[derive(Clone)]
pub struct ClientConfig {
    /// 分帧方式，默认行分隔。
    pub framing: Framing,
    /// 待 spawn 的 server 命令。
    pub command: StdioServerCommand,
    /// 每请求超时，默认 [`DEFAULT_TIMEOUT`]（30s）。
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
    /// 通知队列容量（超过则丢弃最旧一条，保证不阻塞读循环）。
    pub notification_capacity: usize,
    /// 连接 poisoned 后是否允许下一次调用自动重建并重试一次。
    pub rebuild_on_poison: bool,
    pub(crate) session_builder: SessionBuilder,
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
            .field("rebuild_on_poison", &self.rebuild_on_poison)
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
            protocol_versions: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
            client_info: Implementation {
                name: "lengsuo-agent-mcp".to_string(),
                title: None,
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            capabilities: ClientCapabilities::default(),
            notification_capacity: 256,
            rebuild_on_poison: false,
            session_builder: std::sync::Arc::new(|cfg| {
                Ok(std::sync::Arc::new(Session::with_config(
                    SessionConfig::new(cfg.framing, cfg.max_frame_bytes, cfg.notification_capacity),
                )))
            }),
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
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfig {
                reason: "请求超时不能为 0".to_string(),
            });
        }
        self.request_timeout = timeout;
        Ok(self)
    }

    /// 关闭 poisoned 后自动重建。
    #[must_use]
    pub fn with_rebuild_on_poison(mut self, enabled: bool) -> Self {
        self.rebuild_on_poison = enabled;
        self
    }

    /// 设置通知队列容量（0 视为 1）。
    #[must_use]
    pub fn with_notification_capacity(mut self, capacity: usize) -> Self {
        self.notification_capacity = capacity.max(1);
        self
    }

    /// 覆盖本地支持的协议版本列表（测试与非标对端用）。
    #[must_use]
    pub fn with_protocol_versions(mut self, versions: Vec<String>) -> Self {
        self.protocol_versions = versions;
        self
    }

    fn session_config(&self) -> SessionConfig {
        SessionConfig {
            framing: self.framing,
            request_timeout: self.request_timeout,
            handshake_timeout: self.handshake_timeout,
            max_frame_bytes: self.max_frame_bytes,
            notification_capacity: self.notification_capacity,
            client_info: self.client_info.clone(),
            protocol_versions: self.protocol_versions.clone(),
            capabilities: self.capabilities.clone(),
            session_builder: self.session_builder.clone(),
        }
    }
}

/// 一条已握手的 MCP stdio 连接。
pub struct McpClient {
    config: ClientConfig,
    session: Arc<Session>,
    result: InitializeResult,
    next_id: std::sync::atomic::AtomicU64,
    shutting_down: AtomicBool,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("framing", &self.config.framing)
            .field("server_info", &self.result.server_info.name)
            .field("protocol_version", &self.result.protocol_version)
            .field("poisoned", &self.session.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl McpClient {
    /// spawn server 并完成握手。
    ///
    /// # Errors
    /// 见 [`Self::connect_with`]；额外可能因 `protocol_versions` 为空返回
    /// [`Error::InvalidConfig`]。
    pub async fn connect(config: ClientConfig) -> Result<Self, Error> {
        if config.protocol_versions.is_empty() {
            return Err(Error::InvalidConfig {
                reason: "protocol_versions 不能为空".to_string(),
            });
        }
        Self::connect_with(config, None).await
    }

    /// 握手并可选取回通知订阅端（`take_notifications = true` 时接管队列）。
    async fn connect_with(
        config: ClientConfig,
        take_notifications: Option<bool>,
    ) -> Result<Self, Error> {
        let session = Self::open_session(&config).await?;
        let handshake = async {
            let params = InitializeParams {
                protocol_version: config
                    .protocol_versions
                    .first()
                    .cloned()
                    .unwrap_or(LATEST_PROTOCOL_VERSION.to_string()),
                capabilities: config.capabilities.clone(),
                client_info: config.client_info.clone(),
            };
            let id = RequestId::Number(0);
            let result = session
                .request(
                    &id,
                    "initialize",
                    Some(&params),
                    config.handshake_timeout,
                )
                .await?;
            let initialized: InitializeResult =
                serde_json::from_value(result).map_err(|e| Error::MalformedMessage {
                    reason: format!("initialize 结果不合法：{e}"),
                })?;
            initialized.validate_against(&config.protocol_versions)?;
            session
                .notify(
                    &OutNotification {
                        method: "notifications/initialized",
                        params: None,
                    },
                    config.handshake_timeout,
                )
                .await?;
            Ok(initialized)
        }
        .await;
        match handshake {
            Ok(result) => Ok(Self {
                next_id: std::sync::atomic::AtomicU64::new(1),
                config,
                session,
                result,
                shutting_down: AtomicBool::new(false),
            }),
            Err(e) => {
                // 握手失败：丢弃半初始化连接，不留下未握手会话。
                session.fail(&format!("握手失败：{e}"));
                crate::session::force_close(&session).await;
                Err(e)
            }
        }
    }

    async fn open_session(config: &ClientConfig) -> Result<Arc<Session>, Error> {
        let session = (config.session_builder)(&config.session_config())?;
        if !session.has_transport() {
            // stdio 传输在 connect 时由 StdioTransport 注入。
            let transport = StdioTransport::spawn(&config.command, &config.session_config()).await?;
            let attached = transport.session();
            if !Arc::ptr_eq(attached, &session) {
                // builder 返回了另一个实例：以 builder 实例为准，把传输装上。
                session.attach_transport_of(attached);
            }
        }
        Ok(session)
    }

    /// 握手并返回客户端，同时取走通知订阅端。
    pub async fn connect_with_notifications(
        config: ClientConfig,
    ) -> Result<(Self, NotificationReceiver), Error> {
        // 通知队列在 session 创建时生成，这里在握手后取回。
        let session_marker = ();
        let _ = session_marker;
        let mut client = Self::connect_with(config, Some(true)).await?;
        let rx = client
            .session
            .take_notifications()
            .ok_or_else(|| Error::MalformedMessage {
                reason: "通知队列已被取走".to_string(),
            })?;
        // 重新构造以持有同一 session（避免二次 spawn）。
        client.notifications = Some(rx);
        Ok((client, NotificationReceiver {
            rx: Arc::new(Mutex::new(
                client
                    .notifications
                    .take()
                    .ok_or_else(|| Error::MalformedMessage {
                        reason: "内部错误：通知端丢失".to_string(),
                    })?,
            )),
        }))
    }

    /// 握手返回的 `protocolVersion` 不在本地支持列表内时的显式拒绝。
    #[must_use]
    pub fn server_capabilities(&self) -> &crate::protocol::ServerCapabilities {
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

    fn alloc_id(&self) -> Result<RequestId, Error> {
        self.next_id
            .fetch_add(1, Ordering::SeqCst)
            .try_into()
            .map(RequestId::Number)
            .map_err(|_| Error::InvalidConfig {
                reason: "请求 id 已取尽".to_string(),
            })
    }

    async fn request(
        &self,
        method: &str,
        params: Option<&Value>,
    ) -> Result<Value, Error> {
        let id = self.alloc_id()?;
        let req = OutRequest {
            id: &id,
            method,
            params,
        };
        self.session.request(&id, method, params, self.config.request_timeout).await.map_err(|e| {
            // 保留 method 上下文，便于定位是哪个协议面失败。
            match e {
                Error::JsonRpc { code, message, data } => Error::JsonRpc { code, message, data },
                other => other,
            }
        })?;
        // 上面已丢弃结果：重新走一次带返回的分支。
        let _ = req;
        self.session
            .request_value(&id, method, params, self.config.request_timeout)
            .await
    }

    /// `ping`：空 `params`，成功即 `Ok(())`。
    ///
    /// # Errors
    /// 超时、poisoned、传输中断或对端返回 JSON-RPC error。
    pub async fn ping(&self) -> Result<(), Error> {
        self.request("ping", None).await?;
        Ok(())
    }

    /// `tools/list`：`params` 为 `{"cursor": ...}` 或空对象。
    ///
    /// # Errors
    /// 同 [`Self::ping`]，另加结果反序列化失败 → [`Error::MalformedMessage`]。
    pub async fn list_tools(&self) -> Result<ToolsListResult, Error> {
        self.list_tools_with(None).await
    }

    /// 带 cursor 的 `tools/list`（翻页）。
    pub async fn list_tools_with(
        &self,
        cursor: Option<&str>,
    ) -> Result<ToolsListResult, Error> {
        let params = match cursor {
            Some(c) => serde_json::json!({ "cursor": c }),
            None => serde_json::json!({}),
        };
        let value = self.request("tools/list", Some(&params)).await?;
        serde_json::from_value(value).map_err(|e| Error::MalformedMessage {
            reason: format!("tools/list 结果不合法：{e}"),
        })
    }

    /// `tools/call`。
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<crate::protocol::ToolCallResult, Error> {
        let params = serde_json::json!({
            "name": name,
            "arguments": arguments.unwrap_or_else(|| Value::Object(Value::default().as_object().cloned().unwrap_or_default())),
        });
        let value = self.request("tools/call", Some(&params)).await?;
        serde_json::from_value(value).map_err(|e| Error::MalformedMessage {
            reason: format!("tools/call 结果不合法：{e}"),
        })
    }

    /// `shutdown`：请求对端停止，随后发送 `exit` 通知并回收子进程。
    ///
    /// 幂等：重复调用返回 `Ok(())`。无论对端是否响应 `shutdown`，都会尽力
    /// 发送 `exit` 并终止子进程（fail-closed：不把未清理的进程留在系统里）。
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            crate::session::force_close(&self.session).await;
            return Ok(());
        }
        let id = self.alloc_id()?;
        let outcome = self
            .session
            .request(&id, "shutdown", None::<&Value>, self.config.request_timeout)
            .await;
        let _ = self
            .session
            .notify(
                &OutNotification {
                    method: "exit",
                    params: None,
                },
                self.config.handshake_timeout,
            )
            .await;
        crate::session::force_close(&self.session).await;
        // 尽力等待子进程退出，避免僵尸；不无限等。
        if self.session.wait_child(Duration::from_secs(2)).await.is_err() {
            let _ = self.session.kill_child().await;
        }
        outcome.map(|_| ())
    }

    /// 不强求对端配合的直接断开（不发送任何报文）。
    pub async fn disconnect(&mut self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        crate::session::force_close(&self.session).await;
        if self.session.wait_child(Duration::from_secs(2)).await.is_err() {
            let _ = self.session.kill_child().await;
        }
    }

    /// 取回通知订阅端（握手后仍可用；重复调用返回 `None`）。
    pub fn take_notifications(&mut self) -> Option<mpsc::UnboundedReceiver<(String, Value)>> {
        self.session.take_notifications()
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // 忘记 shutdown 时兜底：标记 poisoned 并请求取消读循环，子进程由
        // kill_on_drop 回收。异步 kill 无法在 Drop 中执行，交给 transport。
        let _ = self.session.finalize_drop();
    }
}
