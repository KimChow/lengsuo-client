//! 出口隧道：按配置连到出口服务器并封装/解封载荷。
//!
//! 复用 `lengsuo_shadowsocks::{TcpReader, TcpWriter}`（同仓协议实现，⛔ 不复制第二套），
//! 目标地址编码复用 `ss_core::target::TargetAddr`。
//!
//! 语义参考（只读）：`crates/lengsuo-node/src/outbound_ss.rs`。
//! fail-closed：认证失败即断开，绝不回退明文。
