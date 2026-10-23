//! ss-client — Shadowsocks 客户端（数据面拨号侧）。
//!
//! 职责：
//! - 本地入站（SOCKS5，仅监听回环）——见 [`inbound`]
//! - 与服务端的加密隧道（复用同仓协议实现，不复制第二套）——见 [`outbound`]
//! - fail-closed：握手失败即断开，不带病重试
//!
//! 注意：棱梭产品语境下，本 crate 是 engine 数据面的底层拨号组件之一，
//! 不做协议外的任何产品逻辑（节点选择/健康探测归 net-egress，后续迁入）。
pub mod config;
pub mod error;
pub mod inbound;
pub mod outbound;
pub mod runtime;
pub use error::Error;
pub use error::Result;
