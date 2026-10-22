//! 装配层：把「握手 + 密钥落地 + UDP + 漫游 + keepalive」拼成一条能跑的链路。
//!
//! # 这一层补的是什么
//!
//! 三个孤岛拼起来才有链路：
//!
//! | 孤岛 | 提供什么 | 缺什么 |
//! |---|---|---|
//! | [`crate::udp`] | UDP socket、收发循环、keepalive 发包能力 | 不知道 peer 是谁、**不做握手**、不驱动 keepalive |
//! | `lengsuo_wireguard` | `Device` / `Handshake` / `Responder` / `PeerSet` | **全是纯逻辑**（无 socket） |
//! | `lengsuo_link_core` | 密文帧编解码 | **不碰网络** |
//!
//! ⇒ 本模块就是**接线的那一层**：一个 peer 的完整链路生命周期。
//!
//! # 分层位置
//!
//! **L1 传输 × L2 密钥 × L3 帧** 的装配处。本 crate **不重写**任何密码学：
//! 握手状态机来自 `lengsuo_wireguard::handshake`，AEAD 来自
//! `lengsuo_wireguard::transport`，帧编解码来自 `lengsuo_link_core::frame`。
//!
//! # 线上格式
//!
//! **一个 UDP 数据报 = 一个 L3 帧**；帧的**载荷**是 WireGuard 报文
//! （握手 initiation/response/cookie，或运输数据消息）。
//!
//! # 四件事
//!
//! 1. **握手编排**（[`handshake`]）：把 `Handshake` / `Responder` 接到 UDP 上，
//!    MAC 失败 ⇒ 走 cookie reply 路径（⛔ 不得直接丢弃），
//!    握手失败 ⇒ **明确报错**（⛔ 不回退明文、⛔ 不静默重试到底）。
//! 2. **密钥落地**（[`session`]）：把派生出的 `TransportKeys` / `ResponderKeys`
//!    装进 `Device` 的 keypair 三元组，之后数据面走 `Device::receive`。
//! 3. **endpoint 漫游**（[`session`]）：收包时用
//!    `lengsuo_wireguard::device::endpoint_after_receive` 判定是否更新 endpoint
//!    ⇒ 认证失败的包**绝不**更新（该语义已内建，本层**不**另写判定）。
//! 4. **keepalive 驱动**（[`keepalive`]）：会话未就绪时**不发**，
//!    就绪后按上层给的间隔发**合法零长载荷帧**。
//!
//! # 依赖边界
//!
//! 本 crate **有 IO**（tokio + 平台 socket）⇒ **只在 PC 端使用，移动端不依赖它**。
//! 移动端只用 `lengsuo-link-core`（无 IO）。

pub mod config;
pub mod error;
pub mod handshake;
pub mod keepalive;
pub mod reason;
pub mod session;

pub use self::config::{AssemblyConfig, Role};
pub use self::error::AssemblyError;
pub use self::handshake::{
    HandshakeCodec, InitiatorHandshake, ResponderHandshake, SessionKeys, HANDSHAKE_FRAME_TYPE,
};
pub use self::keepalive::{keepalive_frame, KeepaliveDriver};
pub use self::session::{Assembly, AssemblyEvent};
