//! quinn 服务端端点与 QUIC 连接（对齐 `transport/internet/hysteria/hub.go`
//! 的 `Listener`/`handleClient`/`udpSessionManagerServer`）。
//!
//! 建连流程与参考一致：`Endpoint::new` 绑定 UDP → rustls（ALPN=h3，
//! 无客户端证书验证 `with_no_client_auth`，对齐 `tlsConfig.GetTLSConfig()`
//! 未启用 `VerifyPeerCertificate` 的服务端路径）→ QUIC 握手 →
//! 每连接一个 HTTP/3 服务例程（见 `h3_auth::serve_connection`）。
//!
//! 与参考的实现性差异（详见 docs 偏离清单）：
//! - 拥塞控制：`congestion` 非空时经 `lengsuo-congestion` 注入 Brutal，
//!   否则沿用 quinn 默认 CUBIC（BBR 不移植）；
//! - UDP 发送经 `h3_auth::SeedFiller` 桥（依赖冻结拿不到 `bytes` crate，
//!   `send_datagram` 只接受 `Bytes`；复用接收路径返回的独占缓冲，见
//!   `h3_auth` 模块文档）；
//! - masquerade 只实现参考的缺省分支（404），`file`/`proxy`/`string`
//!   需要 Xray 的配置/HTTP 栈，不在本卡范围。
//!
//! ## 子模块
//!
//! | 子模块 | 职责 |
//! |--------|------|
//! | [`endpoint`] | `HysteriaServer` / `ServerSessionCtx` / quinn 服务端配置构造 |
//! | [`config`] | `ServerConfig` / `ServerError` |
//! | [`constants`] | 会话 ID 长度、通道容量、UDP 空闲回收与 QUIC 缺省值 |
//! | [`udp`] | `UdpManager` / `UdpInboundSession` / `UdpSendHandle` / 分发循环 |

mod config;
mod constants;
mod endpoint;
mod udp;

pub use config::{ServerConfig, ServerError};
pub use constants::{
    DEFAULT_MAX_IDLE_TIMEOUT_MS, DEFAULT_MAX_INCOMING_STREAMS, DEFAULT_UDP_IDLE_TIMEOUT_SECS,
    UDP_IDLE_CLEANUP_INTERVAL_SECS, UDP_MESSAGE_CHAN_SIZE, UDP_SESSION_ID_LEN,
};
pub use endpoint::{HysteriaServer, ServerSessionCtx};
pub use udp::{UdpInboundSession, UdpSendError, UdpSendHandle};

pub(crate) use udp::{run_udp_manager, UdpManager};
