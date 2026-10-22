//! quinn 客户端端点与 QUIC 连接（对齐 `transport/internet/hysteria/dialer.go`
//! 的 `client.dial`/`client.tcp`/`client.udp` 与 `conn.go`）。
//!
//! 建连流程与参考一致：绑定本机 UDP 端口 → rustls（ALPN=h3，证书验证
//! 默认开启，自签 CA 通过 `roots` 注入仍走完整验证链）→ QUIC 握手 →
//! HTTP/3 认证 → 按需提供 TCP 双向流 / UDP datagram 会话。
//!
//! 与参考的实现性差异（详见 docs 偏离清单）：
//! - 拥塞控制用 quinn 默认（BBR/Brutal 不移植），`Hysteria-CC-RX`
//!   请求头仍按参考发送、响应头仍解析保存；
//! - UDP 发送经 `h3_auth::SeedFiller` 桥（依赖冻结拿不到 `bytes` crate，
//!   `send_datagram` 只接受 `Bytes`；复用接收路径返回的独占缓冲，见
//!   `h3_auth` 模块文档），接收侧分发完整实现。
//!
//! ## 子模块
//!
//! | 子模块 | 职责 |
//! |--------|------|
//! | [`endpoint`] | `HysteriaClient`：建连、H3 认证、TCP/UDP 通道开放 |
//! | [`config`] | `ClientConfig` / `ConnectError` |
//! | [`constants`] | 会话 ID 长度、通道容量、首个会话 ID |
//! | [`udp`] | `UdpManager` / `UdpSession` / `UdpSendError` |

mod config;
mod constants;
mod endpoint;
mod udp;

pub use config::{ClientConfig, ConnectError, ObfsHopConfig};
pub use constants::{FIRST_UDP_SESSION_ID, UDP_MESSAGE_CHAN_SIZE, UDP_SESSION_ID_LEN};
pub use endpoint::HysteriaClient;
pub use udp::{UdpSendError, UdpSession};
