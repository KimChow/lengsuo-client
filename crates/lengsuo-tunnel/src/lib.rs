#![forbid(unsafe_code)]
//! `lengsuo-tunnel` — 跨端链路隧道运行时（**有 IO，只在 PC 端使用**）。
//!
//! 职责边界：
//! - **有**：UDP socket 封装、收发循环、peer endpoint 漫游更新入口、
//!   persistent keepalive 驱动，以及把三者**装配**成一条完整链路的会话层。
//! - **没有**：协议语义。帧编解码、密钥派生、通道协商全在
//!   `lengsuo-link-core`（无 IO）里，本 crate 只负责搬运字节与驱动状态机。
//!
//! ⚠️ **移动端不依赖本 crate**：它引入 tokio 与平台 socket，
//! 会把移动端构建链拖垮。移动端只用 `lengsuo-link-core`。
//!
//! # 依赖边界
//!
//! 本 crate **依赖**（且只依赖）这两个下游 crate，**方向单向**：
//!
//! | 依赖 | 用途 | 边界 |
//! |---|---|---|
//! | `lengsuo-link-core` | L3 密文帧的边界格式与编解码 | **无 IO**，可编进移动端静态库 |
//! | `lengsuo-wireguard` | L2 握手状态机、AEAD 传输密钥、peer 路由 | **纯逻辑**，不建 socket |
//!
//! ⛔ 本 crate **不**依赖任何 lengsuo 业务仓（`lengsuo-agent` 等），
//! ⛔ 也**不**被 `lengsuo-link-core` 依赖（否则移动端会被拖进 tokio）。
//!
//! # 分层
//!
//! | 层 | 内容 | 归属 |
//! |---|---|---|
//! | **L1 传输** | UDP socket、收发循环、endpoint 漫游入口、keepalive 驱动 | **本 crate** |
//! | **L1 装配** | 握手编排、密钥落地、漫游接线、keepalive 接线 | **本 crate** |
//! | L2 密钥 | 握手、密钥落地、世代号 | `lengsuo-wireguard`（握手 / AEAD 来源）＋ **本 crate** 编排；世代号语义见 `lengsuo-link-core::session` |
//! | L3 密文帧 | 帧边界格式与编解码 | `lengsuo-link-core::frame` |
//! | L4 通道协商 | 通道模式、能力集、世代号核对 | `lengsuo-link-core::negotiate`（协议真相）＋ **本 crate** [`negotiate`]（装配接线） |
//! | L5 ACP 语义 | — | 不动 |
//!
//! ⚠️ **`lengsuo-link-core::transport` 现在已接到生产路径**：[`link`] 把
//! 本 crate 的 UDP 端点适配成 `Transport`，PC 端可用 `link_core::transport::Link::send_frame` /
//! `recv_frame` 与移动端跑**同一套 L2**。旧的 [`assembly`] 路径（自己调
//! `Keypair::seal`）保留不动。
//!
//! # 模块
//!
//! - [`udp`]：**L1 传输**。socket 封装、收发循环、两级错误、keepalive 驱动。
//! - [`link`]：**L1×L2 接线**。把 UDP 端点适配成 `link-core` 的 `Transport`，
//!   用 [`Link`]（会话 + 搬运）收发。
//! - [`assembly`]：**L1 装配**。握手编排、密钥落地、endpoint 漫游接线、
//!   keepalive 接线——把上面三块拼成「一个 peer 的完整链路生命周期」。
//! - [`negotiate`]：**L4 装配接线**。把 `lengsuo-link-core::negotiate`
//!   的协议真相挂进 [`assembly`]：控制帧 ⇄ 协商驱动器、世代号核对。

pub mod assembly;
pub mod link;
pub mod negotiate;
pub mod udp;

pub use crate::assembly::{
    Assembly, AssemblyConfig, AssemblyError, AssemblyEvent, HandshakeCodec, InitiatorHandshake,
    KeepaliveDriver, ResponderHandshake, Role, SessionKeys,
};
pub use crate::negotiate::{
    NegotiateConfig, NegotiateDriver, NegotiateError, NegotiationResult, NegotiationStep,
};
pub use crate::udp::{
    Cancel, Datagram, DatagramError, ErrorSeverity, HandshakeKind, KeepaliveConfig,
    KeepaliveOutcome, LoopOutcome, UdpEndpoint, UdpError, UdpEvent,
};
