#![forbid(unsafe_code)]
//! VLESS v0 基础握手与数据帧；TCP 已通过固定基线双向回环互通。
//! 支持基础 XUDP 单会话；Vision、通用 TCP Mux、反向代理和非空附加字段尚未实现。
//! XEL（Xray Encryption Layer）记录层见 [`xel`]：密钥由调用方注入，
//! 密钥协商（KEM）不在本 crate 范围。VLESS Vision（xtls-rprx-vision）
//! 客户端流量层见 [`vision`]；REALITY 客户端接入主链路见 [`reality_link`]。

pub mod header;
pub mod mux;
pub mod mux_wire;
pub mod reality;
pub mod reality_config;
pub mod reality_link;
pub mod stream;
pub mod vision;
pub mod vision_wire;
pub mod xel;
pub mod xel_wire;
pub mod xudp;
