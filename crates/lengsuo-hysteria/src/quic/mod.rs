//! QUIC 传输层（对齐 `transport/internet/hysteria/dialer.go`）。
//!
//! 职责：构建 quinn 客户端端点（ALPN=h3、rustls ring、证书验证默认开启），
//! 完成 H3 认证（见 `crate::h3_auth`），随后向调用方提供两类通道：
//! - TCP：`open_bi()` 双向流，首写前置 `FrameTypeTCPRequest` varint
//!   （对齐 conn.go `interConn.Write` 的 client 分支）；
//! - UDP：QUIC datagram，前 4 字节为会话 ID（对齐 conn.go `InterUdpConn`），
//!   由后台任务按会话 ID 分发（对齐 dialer.go `udpSessionManagerClient`）。
//!
//! # 拥塞控制参数面
//! `CongestionConfig`（见 `crate::congestion`）作为 QUIC 配置构造参数被
//! 承载与校验，用于在握手后读写 `Hysteria-CC-RX` / `Hysteria-CC-TX` 头
//! 并推导参考会选取的目标发送速率。
//!
//! **本层只做参数面：实际拥塞器仍为 quinn 默认（CUBIC）。** 本仓未 fork
//! quinn，无法调用参考的 `congestion.UseBrutal/UseBBR`；`CongestionConfig`
//! 不传递给 `quinn::TransportConfig` 之外的任何拥塞器替换入口，也不改变
//! QUIC 的发送节奏。

pub mod client;
pub mod early;
pub mod server;

/// 拥塞参数配置（参数面；**不**替换 quinn 拥塞器，见模块级说明）。
pub use crate::congestion::CongestionConfig;

pub use client::{ClientConfig, ConnectError, HysteriaClient, UdpSendError, UdpSession};
pub use early::{
    configure_tls, run_early, EarlyBudget, EarlyBudgetExceeded, EarlyDataConfig, EarlyDataError,
    EarlyError, MemorySessionCache, OperationKind, SessionCache, ZeroRttOutcome, ZeroRttRejected,
    ZeroRttStatus,
};
pub use server::{HysteriaServer, ServerConfig, ServerError, ServerSessionCtx, UdpInboundSession};
