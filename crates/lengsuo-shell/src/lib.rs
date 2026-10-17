//! `lengsuo-shell`：GPUI 桌面壳的**网关客户端 + 视图状态**层（阶段一，纯逻辑）。
//!
//! 职责边界：
//! - 只作为本地网关的**客户端**：读握手文件、`POST /rpc`、`GET /events` WebSocket 订阅。
//! - 不引入 gpui（阶段二用 feature `ui` 隔离）；不 import 也不修改 `ss-*`；
//!   不实现网关服务端（服务端归轨道 D）。
//! - 视图状态是纯 Rust 结构体（无渲染、无 IO），为将来 GPUI 渲染供数。
//!
//! 协议遵循 [AGENT-KICKOFF.md](../../AGENT-KICKOFF.md) §2 网关协议 v0：
//! - 握手文件 `gateway.json`，内容 `{port, pid, token}`；token 只驻留内存。
//! - 单入口 `POST /rpc`，请求体 `{action: "<域>:<动作>", payload}`，
//!   信封 `{code, msg, data}`；`code == 0` 成功；404 未注册动作、403 鉴权拒绝、
//!   408 超时；默认超时 30s。所有请求带头 `X-Gateway-Token`。
//! - `GET /events`（WebSocket）：一行一个 JSON；事件名 `thinking / text / tool_use /
//!   tool_result / approval_request / files / done` 加 `session_update`。
//!
//! 发现协议缺口时**不改协议**，记录到 `PROTOCOL-NOTES.md`（轨道 E 分工卡约束）。

#![forbid(unsafe_code)]

pub mod gateway;
pub mod state;
pub mod ui;

pub use gateway::{
    action, Envelope, EventError, EventKind, EventSubscription, GatewayClient, GatewayEvent,
    GatewayHandshake, HandshakeError, RpcError, DEFAULT_TIMEOUT,
};
pub use state::{
    ApprovalDecision, ApprovalState, EnvEntry, EnvListViewState, EnvStatus, MessageRole,
    PendingApproval, SessionListItem, SessionListState, SessionMessage, SessionMode, SessionStatus,
    SessionStreamState, StateError, StreamPhase, ToolRef,
};
