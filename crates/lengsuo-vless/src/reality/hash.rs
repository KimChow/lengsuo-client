//! REALITY 握手层所需的哈希原语**内置实现**。
//!
//! # 为什么内置
//!
//! 参考用 Go 标准库 `crypto/sha256`、`crypto/sha512`、`crypto/hmac` 与
//! `golang.org/x/crypto/hkdf`。本 crate 的 `[dependencies]` 里没有
//! `sha2` / `hmac` / `hkdf`；工作区 `Cargo.toml` 虽已声明这些 workspace
//! 依赖，但要 `use` 就得改 `crates/lengsuo-vless/Cargo.toml`，而本卡硬约束
//! 明令不得自行改 `Cargo.toml`。为在范围内交付**可编译、可测**的实现，
//! 这里按 FIPS 180-4 / RFC 2104 / RFC 5869 逐条转写，并用权威测试向量
//! 自证正确性。
//!
//! **这是既定偏离**：由主理人开基建卡引入 `sha2` + `hmac` + `hkdf` 后，
//! 本目录可整体删除、`auth.rs` 改回依赖实现（字节语义不变）。
//!
//! 全部为纯 Rust、无 `unsafe`、无堆分配。

pub mod hmac;
pub mod sha;

pub use self::hmac::{hkdf_sha256, hmac_sha512};
pub use sha::{sha256, sha512, Sha256, Sha512};
