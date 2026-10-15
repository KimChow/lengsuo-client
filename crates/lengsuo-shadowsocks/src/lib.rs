#![forbid(unsafe_code)]
//! lengsuo-shadowsocks — 传统 Shadowsocks AEAD 的 UDP 数据报编解码。
//!
//! 已有：`UdpCodec` 的单包密封与打开，覆盖 ss-core 支持的四类 AEAD 套件
//! （aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、xchacha20-ietf-poly1305）。
//! 密钥派生、AEAD 原语与 SOCKS 目标地址全部复用 `ss-core`，本 crate 不复制核心实现。
//!
//! 尚未实现：UDP 中继服务与异步收发流水线、入站防重放（盐唯一性检查）与
//! 密钥轮换、以及参考实现的真实互通验收。状态见 `docs/shadowsocks-status.md`。

pub mod udp;

pub use ss_core::crypto::CipherSuite;
pub use ss_core::target::TargetAddr;
pub use udp::Error as UdpError;
pub use udp::UdpCodec;
pub use udp::MAX_PACKET_LEN;
