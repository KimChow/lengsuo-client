//! `GET /events` WebSocket 订阅：一行一个 JSON，解析为 typed 事件。
//!
//! 冻结语义（AGENT-KICKOFF.md §2/§3）：
//! - 事件名固定 8 类：`thinking / text / tool_use / tool_result / approval_request /
//!   files / done` 加 `session_update`。
//! - 帧形态 `{seq, session_id, kind, payload, ts_ms}`，`seq` 会话内单调递增，
//!   是将来分页回溯的锚点。
//! - 鉴权同样走 `X-Gateway-Token` 头；token 不进事件、不进错误信息。
//!
//! 顺序保证：本模块只做「一条 WS 文本帧 = 一个事件」的严格解析，未知 `kind`
//! 不静默丢弃而是返回 [`EventError::UnknownKind`]（协议缺口由上层记录，
//! 壳层不擅自扩展动作面/事件面）。

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async, WebSocketStream};

/// 事件类型。与协议冻结的 8 个名字一一对应，`rename_all = "snake_case"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
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
    /// 文件产出/变更。
    Files,
    /// 本轮结束。
    Done,
    /// 会话元信息变化（状态、模式、环境绑定等）。
    SessionUpdate,
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
    /// 事件载荷。
    #[serde(default)]
    pub payload: Value,
    /// 毫秒时间戳。
    pub ts_ms: u64,
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
