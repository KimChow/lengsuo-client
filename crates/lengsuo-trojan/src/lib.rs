#![forbid(unsafe_code)]
//! lengsuo-trojan — Trojan 协议基础请求编解码（部分实现，未完成 Xray 互通验收）。
//!
//! 已有：密码 SHA224 十六进制凭据、TCP/UDP 命令、复用 `ss-core` SOCKS 地址的
//! 请求头编码与带常量时间认证的解码。头部之后的字节保留给应用载荷。
//!
//! 尚未实现：异步 TCP/UDP 服务与客户端流水线、UDP 数据报分帧、
//! 与 Xray 的真实互通验收。TLS 属于上层（`lengsuo-tls`），本 crate 无明文回退。
//! 状态与验证记录见 `docs/trojan-status.md`。

pub mod codec;
pub mod credential;

pub use codec::{decode, encode, Command, Request};
pub use credential::Credential;
pub use ss_core::target::TargetAddr;
