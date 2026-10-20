//! REALITY 端到端与 TLS 1.3 记录层的**确定性**测试（不依赖 Xray 二进制）。
//!
//! 覆盖四层（按子模块拆分，每个子模块一个文件）：
//!
//! 1. [`vectors`] —— **确定性向量**：HMAC / HKDF / SHA / X25519 / Ed25519 /
//!    TLS 1.3 密钥调度 / REALITY `auth_key` / 证书标签 / 记录层字节，
//!    期望值全部**硬编码**且来自 RFC 或独立实现（见 `support/vectors.rs`
//!    顶部的来源表），**不是**本仓实现自证。
//! 2. [`framing`] —— **握手消息与记录层分帧**（结构级）。
//! 3. [`negative`] —— **负例**：错口令 / 错短 ID / 错 SNI / 重放认证载荷 /
//!    篡改握手消息 / 截断记录，每条都有断言且必须 fail-closed
//!    （返回错误，**不 panic**）。
//! 4. [`handshake`] —— **Rust↔Rust 端到端**（回环 TCP）与 REALITY 准入负例。
//!
//! **硬约束**：本测试**不得**出现 `#[ignore]`；只用回环地址、临时端口、
//! 假凭据；日志不得输出密钥/明文/口令。

mod framing;
mod handshake;
mod negative;
mod vectors;

pub mod support;

pub use support::{hex, ClientIdentity, ServerIdentity};
