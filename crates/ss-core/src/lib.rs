//! ss-core — 双端共享 Shadowsocks 协议原语（部分实现，未完成 Xray 互通验收）。
//!
//! 已有目标地址模型、EVP_BytesToKey、HKDF-SHA1、四类 AEAD 与 TCP chunk。
//! nonce 为小端递增；UDP codec、完整流收尾与真实服务互通尚未完成。
//! 核心不得依赖客户端/服务端业务；异步 chunk 使用 tokio I/O trait。
//! Python fixtures 是辅助样本，不是 Xray 实跑黄金样本或兼容性证明。

pub mod chunk;
pub mod crypto;
pub mod error;
pub mod kdf;
pub mod target;

pub use error::Error;
pub use error::Result;
