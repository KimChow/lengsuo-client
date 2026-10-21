//! `GET /events` WebSocket 订阅：一行一个 JSON，解析为 typed 事件。
//!
//! 冻结语义（AGENT-KICKOFF.md §2/§3）：
//! - 事件名与 `agent-core::schema::EventKind` **逐项一致**（含 `user` 与
//!   `approval_resolved`、`error`）：`user / thinking / text / tool_use / tool_result /
//!   approval_request / approval_resolved / files / done / error / session_update`。
//!   由 `contracts-check` 的穷举断言守住两侧不漂移。
//! - 帧形态 `{seq, session_id, kind, payload, ts_ms}`，`seq` 会话内单调递增，
//!   是将来分页回溯的锚点。
//! - 鉴权同样走 `X-Gateway-Token` 头；token 不进事件、不进错误信息。
//!
//! 顺序保证：本模块只做「一条 WS 文本帧 = 一个事件」的严格解析，未知 `kind`
//! 不静默丢弃而是返回 [`EventError::UnknownKind`]（协议缺口由上层记录，
//! 壳层不擅自扩展动作面/事件面）。
//!
//! ⚠️ **载荷键名是 camelCase**（`argsRef` / `resultRef` / `tsMs` / `chars` /
//! `preview` / `name` / `args`）——这是**线上真实形态**，由服务端发射端决定。
//! 本模块只透传 `payload`（`Value`），不重命名、不改写任何键名。

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async, WebSocketStream};

pub use crate::error::EventError;

/// 事件类型。覆盖协议已定型的名字，`rename_all = "snake_case"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// 用户输入（durable 事件；读侧据此重建消息序列）。
    User,
    /// 模型思考增量。
    Thinking,
    /// 助手正文增量。
    Text,
    /// 工具调用开始。
    ToolUse,
    /// 工具结果（大结果只带 `result_ref`，不进 content）。
    ToolResult,
    /// 审批请求，UI 需挂起并等待 `approval:respond`。
    ApprovalRequest,
    /// 审批已裁决（`approval:respond` 的结果回声；与 `agent-core::schema::EventKind`
    /// 的 `ApprovalResolved` 逐项对齐，此前壳侧缺此变体导致该事件被拒）。
    ApprovalResolved,
    /// 文件产出/变更。
    Files,
    /// 本轮结束。
    Done,
    /// 错误事件（与 `agent-core::schema::EventKind` 的 `Error` 逐项对齐）。
    Error,
    /// 会话元信息变化（状态、模式、环境绑定等）。
    SessionUpdate,
}

impl EventKind {
    /// 线上事件名（与 `agent-core::schema::EventKind::as_str` 逐项一致）。
    ///
    /// serde 的 `rename_all = "snake_case"` 已保证**反序列化**方向的名字一致；
    /// 这里补上**正序列化**方向的显式名字，避免调用方靠 `format!("{kind:?}")`
    /// 之类的方式猜线上键名。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::User => "user",
            EventKind::Thinking => "thinking",
            EventKind::Text => "text",
            EventKind::ToolUse => "tool_use",
            EventKind::ToolResult => "tool_result",
            EventKind::ApprovalRequest => "approval_request",
            EventKind::ApprovalResolved => "approval_resolved",
            EventKind::Files => "files",
            EventKind::Done => "done",
            EventKind::Error => "error",
            EventKind::SessionUpdate => "session_update",
        }
    }
}

/// 一条网关事件。`payload` 保持 [`Value`]，由各视图按需取用（避免为 v0 未定型的
/// 子结构硬编码 schema，见 PROTOCOL-NOTES.md）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayEvent {
    /// 会话内单调递增序号。
    pub seq: u64,
    /// 归属会话。
    pub session_id: String,
    /// 事件类型。
    pub kind: EventKind,
    /// 事件载荷（**键名原样透传**，线上为 camelCase）。
    #[serde(default)]
    pub payload: Value,
    /// 毫秒时间戳。
    pub ts_ms: u64,
}

/// 已建立的事件订阅。持有 WS 半边，按需拉取下一条事件。
pub struct EventSubscription {
    stream: WebSocketStream<TcpStream>,
    timeout: Duration,
}

impl std::fmt::Debug for EventSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSubscription")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// `EventError` 的错误变体直接内嵌 `tungstenite::Error`。
///
/// 本仓对齐 workspace 的 `tokio-tungstenite 0.24`，该版本的 `Error` 内联整个
/// `Message`（136 字节）；0.28 把它装箱后才降到 32 字节。错误**类型**是协议契约
/// 的一部分（下游按变体匹配），故不改形状，只在此处放行体积 lint。
#[allow(clippy::result_large_err)]
impl EventSubscription {
    /// 在已连接的 TCP 流上完成 `/events` 握手。`token` 只进请求头。
    pub(crate) async fn establish(
        tcp: TcpStream,
        addr: std::net::SocketAddr,
        token: &str,
    ) -> Result<Self, EventError> {
        let url = format!("ws://{addr}/events");
        let mut request = url.as_str().into_client_request()?;
        request.headers_mut().insert(
            "X-Gateway-Token",
            token.parse().map_err(|_| EventError::Malformed {
                reason: "token 含非法字符，无法作为 HTTP 头".to_string(),
            })?,
        );
        let (stream, _response) = client_async(request, tcp).await?;
        Ok(Self {
            stream,
            timeout: Duration::from_secs(5),
        })
    }

    /// 覆盖单帧等待超时（默认 5s：事件是推送流，不应借用 RPC 的 30s）。
    #[must_use]
    pub fn with_frame_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 取下一条事件。
    pub async fn next(&mut self) -> Result<GatewayEvent, EventError> {
        let timeout = self.timeout;
        let message = tokio::time::timeout(timeout, self.stream.next())
            .await
            .map_err(|_| EventError::Timeout)?
            .ok_or(EventError::Closed)??;
        match message {
            Message::Text(text) => Self::parse(text.as_str()),
            Message::Close(_) => Err(EventError::Closed),
            Message::Binary(_) | Message::Frame(_) => Err(EventError::NotText),
            // ping/pong 由 tungstenite 自动应答，正常不会交付到这里。
            Message::Pong(_) => Err(EventError::NotText),
            Message::Ping(_) => Err(EventError::NotText),
        }
    }

    /// 解析一帧（一行一个 JSON）。
    fn parse(text: &str) -> Result<GatewayEvent, EventError> {
        // 先取 kind 原文，未知事件名要报出来而不是归入 serde 的 enum 错误。
        let value: Value = serde_json::from_str(text).map_err(|e| EventError::Malformed {
            reason: summarize(&e),
        })?;
        let kind =
            value
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| EventError::Malformed {
                    reason: "缺少 kind 字段".to_string(),
                })?;
        if serde_json::from_value::<EventKind>(Value::String(kind.to_string())).is_err() {
            return Err(EventError::UnknownKind {
                kind: kind.to_string(),
            });
        }
        serde_json::from_value::<GatewayEvent>(value).map_err(|e| EventError::Malformed {
            reason: summarize(&e),
        })
    }

    /// 主动关闭订阅。
    pub async fn close(mut self) -> Result<(), EventError> {
        let _ = self.stream.send(Message::Close(None)).await;
        Ok(())
    }
}

/// 把 serde 错误压成一行、不带原始内容的摘要。
fn summarize(e: &serde_json::Error) -> String {
    format!("{e}")
        .lines()
        .next()
        .unwrap_or("parse error")
        .to_string()
}
