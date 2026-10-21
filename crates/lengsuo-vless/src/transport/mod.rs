//! VLESS 外层传输（client + server）：WebSocket / HTTPUpgrade，对应 Xray
//! `streamSettings.network = "ws" | "httpupgrade"`。
//!
//! 参考路径（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//!
//! - `transport/internet/websocket/{dialer,connection,hub}.go`：客户端在已建立
//!   的 TLS/TCP 流上发起 HTTP/1.1 Upgrade（`Sec-WebSocket-Key`/`Version`），
//!   服务端回 `101 Switching Protocols`；其后是 RFC 6455 帧，VLESS 头部与载荷
//!   全部落在帧的载荷里。
//! - `transport/internet/httpupgrade/{dialer,hub}.go`：同样是 HTTP/1.1 Upgrade，
//!   但升级点之后**不是** WebSocket 帧，而是裸字节流——升级点之后的每个字节
//!   直接就是 VLESS 流量（`ConnRF.Read` 只在首读时消费 101 响应头，此后透传）。
//! - `infra/conf/transport_internet.go:1009`：`network` 取值映射
//!   `case "ws", "websocket":`；`:173` 构造 `websocket.Config`。
//!
//! ## 与 `lengsuo-trojan::transport` 的同源关系
//!
//! 本目录的 `http.rs` / `sha1.rs` / `ws/` / `httpupgrade.rs` / `server.rs`
//! **与 `crates/lengsuo-trojan/src/transport/` 同源**（逐字复制，仅模块文档
//! 标注 VLESS）。后续应收敛到共享 crate：当前 `lengsuo-vless` 不能依赖
//! `lengsuo-trojan`（需要新增 path 依赖 ⇒ 改 `Cargo.toml`，属共享区，本卡
//! 无权改动），故先以复制方式落地，待基建卡统一。
//!
//! 本模块只提供「已建立的字节流 → 升级后的字节流」这一层，**不**处理 TLS、
//! REALITY、VLESS 头部与认证；调用方先完成安全传输，再把流交给这里升级。
//!
//! ## 与参考的差异
//!
//! 参考客户端用 gorilla/websocket；本仓**不引入新依赖**（47 上 crates.io 不可达，
//! 新增普通依赖还会改写根 `Cargo.lock`）。因此按 RFC 6455 与参考 dialer 的实际
//! 线上字节手写客户端握手与帧编解码：客户端只发二进制帧、掩码恒置、不协商扩展，
//! 与参考 `connection.Write`（`BinaryMessage`）及 `dialer.DialContext` 的请求头
//! 集合逐字节对齐。`Ed`（early data）与 `HeartbeatPeriod` 未实现，见
//! `ws/mod.rs` / `server.rs` 注释。

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
