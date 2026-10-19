//! Trojan 外层传输（client 侧）：在已完成认证 TLS 的字节流之上再套一层
//! WebSocket / HTTPUpgrade，与 Xray `streamSettings.network` 对应。
//!
//! 参考路径（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//!
//! - `transport/internet/websocket/{dialer,connection}.go`：客户端在 TLS 流上
//!   发起 HTTP/1.1 Upgrade（`Sec-WebSocket-Key`/`Version`），服务端回
//!   `101 Switching Protocols`；其后是 RFC 6455 二进制帧，trojan 头部与载荷
//!   全部落在帧的载荷里。
//! - `transport/internet/httpupgrade/{dialer,connection}.go`：同样是 HTTP/1.1
//!   Upgrade，但握手完成后**不是** WebSocket 帧，而是裸字节流——升级点之后的
//!   每个字节直接就是 trojan 流量（`ConnRF.Read` 只在首读时消费 101 响应头，
//!   此后透传）。
//!
//! 两个传输都先说 HTTP 升级，区别只在“升级之后线上是什么”：
//! `ws` 是帧（本模块 `ws.rs`），`httpupgrade` 是裸流（`httpupgrade.rs`）。
//!
//! ## 与参考的差异（本卡范围内的直接依赖约束）
//!
//! 参考客户端用 gorilla/websocket；本仓**不引入新依赖**（新增普通依赖会改写根
//! `Cargo.lock`，超出本卡边界）。因此这里按 RFC 6455 与参考 dialer 的实际线上
//! 字节手写客户端握手与帧编解码：客户端只发二进制帧、掩码恒置、不协商扩展，
//! 与参考 `connection.Write`（`BinaryMessage`）及 `dialer.DialContext` 的请求头
//! 集合逐字节对齐。TLS 仍由上层（`lengsuo-tls`）负责，本模块只接收/产出已认证
//! 流上的字节。

pub mod http;
pub mod httpupgrade;
pub mod server;
pub mod sha1;
pub mod ws;

use std::time::Duration;

/// 外层传输错误。握手失败、帧非法、超时与 IO 失败分区上报；Display/Debug
/// 不含凭据或载荷明文。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("截止时间必须大于零")]
    InvalidDeadline,

    #[error("传输握手超时")]
    Timeout,

    #[error("HTTP 升级请求被拒绝：{0}")]
    UpgradeRejected(String),

    #[error("HTTP 响应头非法或超长")]
    BadResponse,

    #[error("WebSocket 帧非法：{0}")]
    BadFrame(&'static str),

    #[error("服务端不应掩码 WebSocket 帧")]
    ServerMasked,

    #[error("传输层 IO 失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 零时长会被 `tokio::time::timeout` 立刻判定过期，显式拒绝以便调用方区分。
pub(crate) fn check_deadline(wait: Duration) -> Result<(), Error> {
    if wait.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    Ok(())
}
