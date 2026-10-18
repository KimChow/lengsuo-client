//! [`McpClient`] 的连接生命周期：spawn、握手、关闭与 Drop 兜底。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::protocol::{InitializeParams, InitializeResult, LATEST_PROTOCOL_VERSION};
use crate::session::Session;
use crate::transport::StdioTransport;

use super::config::ClientConfig;
use super::notification::NotificationReceiver;

/// 退出阶段等待子进程的时间上限：到点由会话强杀。
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// 一条已握手的 MCP stdio 连接。
pub struct McpClient {
    // 字段对 `client` 模块树内可见（拆分后各子模块的 impl 块需访问），对外仍私有。
    pub(super) config: ClientConfig,
    pub(super) session: Arc<Session>,
    pub(super) result: InitializeResult,
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
