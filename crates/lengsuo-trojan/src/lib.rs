#![forbid(unsafe_code)]
//! lengsuo-trojan — Trojan 基础请求与数据帧（已验证限定范围的 Xray 双向互通）。
//!
//! 已有：密码 SHA224 十六进制凭据、TCP/UDP 命令、复用 `ss-core` SOCKS 地址的
//! 请求头同步编解码，以及异步请求头握手与 UDP 数据报分帧（`stream` 模块），
//! 每次操作带单一正数截止时间，失败一律 fail-closed。
//!
//! 尚未实现：产品代理运行时与客户端入口、所有传输及异常范围的完整验收。Trojan 没有成功响应头，握手成功由调用方继续传输表达。TLS 属于
//! 上层（`lengsuo-tls`），调用方必须先完成认证 TLS，本 crate 无明文回退。
//! 状态与验证记录见 `docs/trojan-status.md`。

pub mod codec;
pub mod credential;
pub mod stream;

pub use codec::{decode, encode, Command, Request};
pub use credential::Credential;
pub use ss_core::target::TargetAddr;
