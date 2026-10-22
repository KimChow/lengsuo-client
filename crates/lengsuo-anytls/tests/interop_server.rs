//! AnyTLS 服务端方向真实互通（TLS 承载）：spawn anytls-go v0.0.13 的 anytls-client
//! （socks5 入口，出站**无条件** TLS），本端用 tokio-rustls 的 TlsAcceptor 包住
//! TcpStream 后交给 interop_server::session::serve 组装服务端，经隧道回程核对逐字节一致。
//!
//! 安全边界（必须如实记录）：官方参考客户端是示例客户端，`InsecureSkipVerify=true`，
//! **不校验**服务端证书（cmd/client/main.go）。本用例因此只证明
//! 「Rust rustls TLS 服务端 ↔ 官方客户端真实握手 + 认证 + 单流载荷往返」，
//! 不得据此声称产品侧 TLS 信任链/证书校验已验收。
//! 证书为本测试临时 openssl 自签（回环、1 天有效、用后即删），不是任何生产凭据。
//! 默认 #[ignore]，LENGSUO_ANYTLS 指向参考二进制目录。
#[path = "interop_server/harness.rs"]
mod harness;
#[path = "interop_server/pumps.rs"]
mod pumps;
#[path = "interop_server/report.rs"]
mod report;
#[path = "interop_server/session.rs"]
mod session;
#[path = "interop/support.rs"]
mod support;
#[path = "interop_server/tls.rs"]
mod tls;

use std::time::Duration;
use tokio::time::timeout;

/// 回程核对用的载荷长度（与上面写出的常量保持一致）。
fn payload_len() -> usize {
    b"real-tls-server-direction-echo-check".len()
}

/// Rust↔Rust 单流往返载荷：出站字节计数与回程比对都用它（7 字节
/// 目标地址前缀被服务端解析消耗，不计入转发）。
const RUST_RUST_PAYLOAD: &[u8] = b"rust-to-rust-real-tls-roundtrip";

// 用例按主题拆到 `tests/interop_server/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
// 上面的 `#[path]` 子模块装配（harness / pumps / report / session / support / tls）
// 保持不动。
//
// - `e2e.rs`：真实互通 2 条（官方客户端经 Rust TLS 服务端 / Rust 客户端校验证书往返）。
// - `rejections.rs`：4 条拒绝类（明文连接 / 错误口令 / 缺 Settings / 错误 SNI）。

include!("interop_server/e2e.rs");
include!("interop_server/rejections.rs");
