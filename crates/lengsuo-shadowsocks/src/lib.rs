//! lengsuo-shadowsocks — 传统 Shadowsocks AEAD 的 UDP 数据报编解码与 TCP 字节 chunk 层。
//!
//! 已有：`UdpCodec` 的单包密封与打开，`TcpWriter` / `TcpReader` 的异步 TCP 字节
//! chunk 收发，两者都覆盖 ss-core 支持的四类 AEAD 套件（aes-128-gcm、aes-256-gcm、
//! chacha20-ietf-poly1305、xchacha20-ietf-poly1305）。密钥派生、AEAD 原语、chunk
//! 帧与 SOCKS 目标地址全部复用 `ss-core`，本 crate 不复制核心实现。
//!
//! `TcpWriter` / `TcpReader` 是**字节 chunk 层，不是完整代理会话**：首段明文就是
//! 上层编码好的目标地址（`TargetAddr::encode_checked`），本层不解析地址、不实现
//! 中继服务，也不做 UDP 关联。
//!
//! 尚未实现：UDP 中继服务、密钥轮换、分块 padding 与参考实现的读端行为缓解。
//! 入站 salt 防重放已由 `replay` 模块提供（[`ReplayFilter`]，经
//! [`TcpReader::recv_guarded`] / [`UdpCodec::open_guarded`] 接入）。状态见
//! `docs/shadowsocks-status.md`。

mod key;
mod replay;
pub mod tcp;
pub mod udp;

pub use replay::{Error as ReplayError, ReplayFilter};
pub use ss_core::crypto::CipherSuite;
pub use ss_core::target::TargetAddr;
pub use tcp::Error as TcpError;
pub use tcp::Reader as TcpReader;
pub use tcp::Writer as TcpWriter;
pub use tcp::MAX_SEGMENT_PAYLOAD;
pub use udp::Error as UdpError;
pub use udp::UdpCodec;
pub use udp::MAX_PACKET_LEN;
