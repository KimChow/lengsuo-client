#![forbid(unsafe_code)]
//! VLESS v0 基础握手与数据帧；TCP 已通过固定基线双向回环互通。
//! Vision、Mux、反向代理和非空附加字段目前明确拒绝。

pub mod header;
pub mod stream;
