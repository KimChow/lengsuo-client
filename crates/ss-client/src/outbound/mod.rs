//! 出口隧道：按配置连到出口服务器并封装/解封载荷。
//!
//! 复用 `lengsuo_shadowsocks::{TcpReader, TcpWriter}`（同仓协议实现，⛔ 不复制第二套），
//! 目标地址编码复用 `ss_core::target::TargetAddr`。
//!
//! 语义参考（只读）：`crates/lengsuo-node/src/outbound_ss.rs`。
//! fail-closed：认证失败即断开，绝不回退明文。
//!
//! 分文件：
//! - [`dialer`]：八协议**一处分发**；`ss://` 的解析、套件选择、建连与首个
//!   认证 chunk 判定；其余七协议如实报 [`DialError::NotWiredYet`]；
//! - [`endpoint`]：其余七协议（vless / vmess / trojan / hysteria2 / anytls /
//!   wireguard / ss2022）的端点形状解析，映射到 `lengsuo-egress` 的
//!   `NodeConfig` 并复用其 `validate()`；
//! - [`tunnel`]：已建连的双向隧道，`AsyncRead` / `AsyncWrite`。
//!
//! **凭据纪律**：[`Dialer`] / [`Tunnel`] 故意不实现 `Debug`，口令与主密钥
//! 不进入日志；错误消息也不回显口令。
//!
//! [`endpoint`] 声明为 `pub(crate)`：`config::load` 在**加载期**用同一份解析
//! 规则校验非 `ss://` 的出口 URL（fail-closed 越早越好）。

mod dialer;
pub(crate) mod endpoint;
mod tunnel;

pub use dialer::{DialError, Dialer};
pub use tunnel::Tunnel;
