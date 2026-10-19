#![forbid(unsafe_code)]
//! lengsuo-trojan — Trojan 基础请求、数据帧与空闲/关闭语义（已验证限定范围的 Xray 双向互通）。
//!
//! 已有：密码 SHA224 十六进制凭据、TCP/UDP 命令、复用 `ss-core` SOCKS 地址的
//! 请求头同步编解码，异步请求头握手与 UDP 数据报分帧（`stream` 模块），
//! 关闭前残留丢弃（`drain` 模块，对齐参考 `common/drain/drainer.go`），以及
//! “未通过握手即无法转发载荷”的类型级会话门（`session` 模块），
//! 每次操作带单一正数截止时间，失败一律 fail-closed（永久 poison）。
//!
//! 命令分支核对：参考 `proxy/trojan/protocol.go` 只有 `commandTCP = 1` 与
//! `commandUDP = 3`，**没有**第三种命令、应答/心跳分支，也**没有**响应首字节
//! 状态码（`client.go` 不读状态字节，`server.go` 不写状态码；空闲靠
//! `CancelAfterInactivity` 直接断连）。因此本 crate 不发明这些语义，fail-closed
//! 由“握手顺序 + Session 类型 + 永久 poison”表达（见 `session` 模块注释）。
//!
//! 已实现服务端运行时（`server` 模块）：TLS 接入（tokio-rustls `TlsAcceptor`）、
//! 请求头多用户常量时间校验、CONNECT 目标解析与拨号、双向中继（半关闭传递），
//! 以及 UDP ASSOCIATE 转发（`udp` 报文 codec + `udp_relay` 中继）。
//! TLS 属于上层（`lengsuo-tls`），产品路径调用方必须先完成认证 TLS，本 crate 无明文回退。
//! 状态与验证记录见 `docs/trojan-status.md`。

pub mod codec;
pub mod credential;
pub mod drain;
pub mod server;
pub mod session;
pub mod stream;
pub mod udp;
pub mod udp_relay;

pub use codec::{decode, encode, Command, Request};
pub use credential::Credential;
pub use drain::{BehaviorSeedLimitedDrainer, DrainOutcome, Drainer, NopDrainer};
pub use session::Session;
pub use ss_core::target::TargetAddr;
