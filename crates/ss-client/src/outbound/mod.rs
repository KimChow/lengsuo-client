//! 出口隧道：按配置连到出口服务器并封装/解封载荷。
//!
//! 复用 `lengsuo_shadowsocks::{TcpReader, TcpWriter}`（同仓协议实现，⛔ 不复制第二套），
//! 目标地址编码复用 `ss_core::target::TargetAddr`。
//!
//! 语义参考（只读）：`crates/lengsuo-node/src/outbound_ss.rs`。
//! fail-closed：认证失败即断开，绝不回退明文。
//!
//! 分文件：
//! - [`dialer`]：`ss://` 解析、套件选择、建连与首个认证 chunk 判定；
//! - [`tunnel`]：已建连的双向隧道，`AsyncRead` / `AsyncWrite`。
//!
//! **凭据纪律**：[`Dialer`] / [`Tunnel`] 故意不实现 `Debug`，口令与主密钥
//! 不进入日志；错误消息也不回显口令。

mod dialer;
mod tunnel;

pub use dialer::{DialError, Dialer};
pub use tunnel::Tunnel;
