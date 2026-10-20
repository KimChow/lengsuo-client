//! TLS 1.3 记录层与握手消息（REALITY 的承载层）。
//!
//! # 为什么自研
//!
//! REALITY 的认证载荷密钥是
//! `HKDF-SHA256(ikm = X25519(客户端临时私钥, 服务端公钥), ...)`，
//! 其中**客户端临时私钥必须在客户端本地生成**。但 TLS 1.3 的 ECDHE 密钥由
//! TLS 库内部持有，`rustls` / `tokio-rustls` **不暴露**该私钥
//! （本仓的 `lengsuo-tls` 只有 `TlsClient` / `TlsServer` 薄封装）。
//! 因此无法用现成 TLS 库拼出 REALITY——必须自己实现 TLS 1.3 的
//! 记录层与密钥调度，才能同时拿到 X25519 共享密钥与 TLS 会话。
//!
//! # 参考实现
//!
//! * 记录层：`xtls/reality` `conn.go`（`readRecord` / `writeRecord`）、
//!   `cipher_suites.go`。
//! * 密钥调度：`xtls/reality` `key_schedule.go` + `tls13` 包（`ExpandLabel`）。
//! * 握手消息：`xtls/reality` `handshake_messages.go`。
//! * Ed25519：RFC 8032。
//!
//! # 范围
//!
//! 只覆盖 `TLS_AES_128_GCM_SHA256` + X25519 + Ed25519 这一条路径，
//! 即 REALITY 实际使用的那条。**不实现** PSK、0-RTT、ECH、ML-KEM、
//! HelloRetryRequest、证书压缩、ALPN 协商结果回传。
//!
//! 参考的 REALITY 服务端还会做「回落」：认证不通过就把连接镜像到 `dest`。
//! 本模块**不做回落**（回落属于服务端策略，见
//! [`crate::reality::server`]）。

pub mod certificate;
pub mod ed25519;
pub mod handshake;
pub mod io;
pub mod messages;
pub mod record;
pub mod schedule;
pub mod server;
