//! 最薄接口：把「按节点配置建一条可转发的出站会话」暴露给 `lengsuo-tun`。
//!
//! `lengsuo-tun` 的出口选择层（`egress::OutboundRuntime`）需要的是**真实协议
//! 出口**：给定节点配置与**真实目标地址**，建一条「应用字节流 ⇄ 协议流」的会话。
//! 该能力本来就存在于 `crate::forward::session`，但那个模块是 `forward` 的私有实现。
//!
//! 本模块**只做转出**：不复制任何协议分帧、不另写一套 AEAD、不重做握手。
//! 协议细节仍由各协议 crate 承担（见 `forward/session/*`）。
//!
//! ## 依赖方向
//!
//! `lengsuo-tun → lengsuo-node`（单向）。本模块**不依赖** `lengsuo-tun`，
//! 因此不存在 cargo 依赖环。
//!
//! ## fail-closed
//!
//! 失败一律返回 `Err`（[`SessionError`]），调用方**不得**回落到直连。

use std::time::Duration;

use ss_core::target::TargetAddr;

use crate::config::NodeConfig;
use crate::forward::session::{self, LiveSession, Opened, SessionError};

/// 建立一条可转发的出站会话：返回即代表**握手已完成**且会话可承载业务载荷。
///
/// - 目标地址写进协议请求头（trojan / shadowsocks / vless / vmess / ss2022 /
///   anytls / hysteria 的**真实目标**，不是 dry-run 的探测目标）。
/// - wireguard 明确不支持（L3 隧道，转发层没有字节流）⇒
///   [`SessionError::Unsupported`]。
/// - 失败一律 `Err`（fail-closed）：调用方**不得**回落到直连。
///
/// `observe` 是 trojan 的负向排除观察窗（参考 trojan 服务端认证失败表现为关闭连接，
/// 没有正向确认）；其余协议的判据在协议 crate 内自洽。
pub async fn open_relay(
    config: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
    observe: Duration,
) -> Result<LiveSession, SessionError> {
    // `Opened` 目前只有一个变体；将来新增变体时这里会编译失败，强制显式处理。
    let Opened::Relay(session) = session::open(config, target, wait, observe).await?;
    Ok(*session)
}
