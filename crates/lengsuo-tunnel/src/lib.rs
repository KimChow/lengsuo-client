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
//! | L2 密钥 | 握手、密钥协商 | `lengsuo-link-core`（后续卡） |
//! | L3 密文帧 | 帧边界格式与编解码 | `lengsuo-link-core`（已交付） |
//! | L4 通道协商 | 通道、世代号、能力集 | 后续卡 |
//! | L5 ACP 语义 | — | 不动 |
//!
//! # 模块
//!
//! - [`udp`]：**L1 传输**。socket 封装、收发循环、两级错误、keepalive 驱动。
//! - [`assembly`]：**L1 装配**。握手编排、密钥落地、endpoint 漫游接线、
//!   keepalive 接线——把上面三块拼成「一个 peer 的完整链路生命周期」。

pub mod assembly;
pub mod udp;

pub use crate::assembly::{
    Assembly, AssemblyConfig, AssemblyError, AssemblyEvent, HandshakeCodec, InitiatorHandshake,
    KeepaliveDriver, ResponderHandshake, Role, SessionKeys,
};
pub use crate::udp::{
    Cancel, Datagram, DatagramError, ErrorSeverity, HandshakeKind, KeepaliveConfig,
    KeepaliveOutcome, LoopOutcome, UdpEndpoint, UdpError, UdpEvent,
};
