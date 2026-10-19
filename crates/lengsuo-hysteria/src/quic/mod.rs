//! QUIC 传输层（对齐 `transport/internet/hysteria/dialer.go`）。
//!
//! 职责：构建 quinn 客户端端点（ALPN=h3、rustls ring、证书验证默认开启），
//! 完成 H3 认证（见 `crate::h3_auth`），随后向调用方提供两类通道：
//! - TCP：`open_bi()` 双向流，首写前置 `FrameTypeTCPRequest` varint
//!   （对齐 conn.go `interConn.Write` 的 client 分支）；
//! - UDP：QUIC datagram，前 4 字节为会话 ID（对齐 conn.go `InterUdpConn`），
//!   由后台任务按会话 ID 分发（对齐 dialer.go `udpSessionManagerClient`）。

pub mod client;
pub mod server;

pub use client::{ClientConfig, ConnectError, HysteriaClient, UdpSendError, UdpSession};
pub use server::{HysteriaServer, ServerConfig, ServerError, ServerSessionCtx, UdpInboundSession};
