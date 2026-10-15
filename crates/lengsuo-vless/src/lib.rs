#![forbid(unsafe_code)]
//! VLESS v0 基础握手与数据帧；TCP 已通过固定基线双向回环互通。
//! 支持基础 XUDP 单会话；Vision、通用 TCP Mux、反向代理和非空附加字段尚未实现。

pub mod header;
pub mod stream;
pub mod xudp;
