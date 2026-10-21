#![forbid(unsafe_code)]
//! `lengsuo-link-core` — 跨端链路协议核心（**无 IO**）。
//!
//! 职责边界（**刻意收窄，避免它长成第二个网络栈**）：
//! - **有**：会话密钥派生、密文帧编解码、通道协商（`p2p` / `relay`）、
//!   连接世代号、能力集协商。
//! - **没有**：任何 socket、任何文件、任何计时器驱动、任何线程。
//!   时间的推进由调用方通过显式传入的时间戳决定。
//!
//! 为什么要「无 IO」：本 crate 是**唯一会被编成移动端静态库的 Rust 代码**
//! （iOS / Android 通过 FFI 调用）。一旦它引入 tokio 或平台相关依赖，
//! 移动端构建链就会被拖垮。
//!
//! 依赖方向：本 crate 只依赖 `lengsuo-wireguard`（Noise IK 握手与
//! ChaCha20Poly1305 传输密钥的来源），**不依赖任何 lengsuo 业务仓**。
//!
//! ⚠️ **本 crate 不是标准 WireGuard 协议**：它复用 wireguard-go 的握手与
//! AEAD 算法（开源参照，保留署名），但**不复用其 IP/TUN 封装**——
//! 我方直接在 UDP 之上承载 ACP 帧。详见仓内 `docs/spec/`。
//!
//! # 模块
//!
//! - [`frame`]：L3 密文帧的边界格式与编解码。
//!   帧格式规范见仓内 `docs/link-frame-spec.md`。
//! - [`session`]：L2 会话状态机（握手封装、传输密钥落地、连接世代号）。
//!   会话规范见仓内 `docs/link-session-spec.md`。
//! - [`negotiate`]：L4 通道协商（`p2p` / `relay` 选择、能力集交集、
//!   世代号确认、稳定错误码）。
//!   协商规范见仓内 `docs/link-negotiate-spec.md`。
//! - [`transport`]：L1 传输抽象（**字节搬运**的 trait）+ L1↔L2 接线层。
//!   搬运层**只认字节**（⛔ 不提供明文语义），接线层负责把 L2 会话
//!   （`seal_frame` / `open_frame`）接到搬运层上。
//!   ⛔ **不含** UDP / socket / 打洞（那是 `crates/lengsuo-tunnel` 的活）。
//!   传输规范见仓内 `docs/link-transport-spec.md`。
//!
//! 后续模块由后续卡在各自子目录里补齐；
//! 顶层模块声明统一由本文件维护。

pub mod frame;
pub mod negotiate;
pub mod session;
pub mod transport;
