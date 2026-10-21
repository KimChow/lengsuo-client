#![forbid(unsafe_code)]
//! `lengsuo-tunnel` — 跨端链路隧道运行时（**有 IO，只在 PC 端使用**）。
//!
//! 职责边界：
//! - **有**：UDP socket 封装、收发循环、peer endpoint 漫游更新入口、
//!   persistent keepalive 驱动。
//! - **没有**：协议语义。帧编解码、密钥派生、通道协商全在
//!   `lengsuo-link-core`（无 IO）里，本 crate 只负责搬运字节与驱动状态机。
//!
//! ⚠️ **移动端不依赖本 crate**：它引入 tokio 与平台 socket，
//! 会把移动端构建链拖垮。移动端只用 `lengsuo-link-core`。
//!
//! # 分层
//!
//! | 层 | 内容 | 归属 |
//! |---|---|---|
//! | **L1 传输** | UDP socket、收发循环、endpoint 漫游入口、keepalive 驱动 | **本 crate** |
//! | L2 密钥 | 握手、密钥协商 | `lengsuo-link-core`（后续卡） |
//! | L3 密文帧 | 帧边界格式与编解码 | `lengsuo-link-core`（已交付） |
//! | L4 通道协商 | 通道、世代号、能力集 | 后续卡 |
//! | L5 ACP 语义 | — | 不动 |
//!
//! # 模块
//!
//! - [`udp`]：**L1 传输**。socket 封装、收发循环、两级错误、keepalive 驱动。

pub mod udp;

pub use crate::udp::{
    Cancel, ErrorSeverity, KeepaliveConfig, KeepaliveOutcome, LoopOutcome, UdpEndpoint, UdpError,
    UdpEvent,
};
