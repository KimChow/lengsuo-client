//! 本地入站：SOCKS5（**仅回环**）。
//!
//! 本模块只做**协议面**：完成 SOCKS5 握手并解析出目标地址，把已握手的
//! 客户端连接交给上层拼接数据面。**不在此处拨号**（拨号见 [`crate::outbound`]）。
//!
//! 子模块按协议阶段切开，便于 UDP ASSOCIATE 独立落地：
//! - `greeting`：方法协商（VER/NMETHODS/METHODS，RFC 1928 §3）
//! - `auth`：用户名/口令子协商（RFC 1929）
//! - `request`：CONNECT 请求与应答（RFC 1928 §4-§6）
//!
//! ⛔ 仅允许绑定回环地址：非回环绑定必须 fail-closed 拒绝。
