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
//! 尚未实现：UDP 中继服务、分块 padding 与参考实现的读端行为缓解。
//! 入站 salt 防重放已由 `replay` 模块提供（[`ReplayFilter`]，经
//! [`TcpReader::recv_guarded`] / [`UdpCodec::open_guarded`] 接入）。重放状态文件的
//! 完整性校验由 `persist` 模块的 [`MacKey`]（HMAC-SHA256）提供：`ReplayFilter` 的
//! 内存重放判定逻辑不变，`save_with_key` / `load_with_keys` 接受调用方注入的密钥，
//! 校验失败 fail-closed；加载时同时接受上一代密钥并支持升级重写（密钥轮换）。
//! **`salt_store` 模块把持久化接进入站运行时**（[`SaltStore`]）：启动加载 → 运行时
//! 记录 → 收尾/停止回写；中继侧用 [`SaltStateConfig`] 挂上状态文件路径，
//! **不配置路径则行为与现状一致**。
//! 状态见 `docs/shadowsocks-status.md`。

pub mod address;
pub mod drain;
mod key;
pub mod padding;
mod persist;
mod relay;
mod replay;
pub mod salt_store;
pub mod tcp;
mod tcp_drain;
pub mod udp;

pub use address::AddressReader;
pub use drain::{
    response_behavior_seed, BehaviorSeedLimitedDrainer, BehaviorSeedSource, DrainError,
    HandshakeError, DRAIN_FOUNDATION, SALT_LEN,
};
pub use padding::{
    dechunk_padded, decode_flags, encode_padded, PaddedChunk, PaddingError, PaddingPolicy,
    MAX_PADDING_LEN,
};
pub use persist::MacKey;
pub use relay::{RelayConfig, RelayConfigParts, RelayHandle, RelayService};
pub use replay::{Error as ReplayError, LoadedState, ReplayFilter};
pub use salt_store::{FlushPolicy, SaltStateConfig, SaltStore, SaltStoreConfig, SaltStoreError};
pub use ss_core::crypto::CipherSuite;
pub use ss_core::target::TargetAddr;
pub use tcp::Error as TcpError;
pub use tcp::Reader as TcpReader;
pub use tcp::Writer as TcpWriter;
pub use tcp::MAX_SEGMENT_PAYLOAD;
pub use udp::Error as UdpError;
pub use udp::UdpCodec;
pub use udp::MAX_PACKET_LEN;
