//! 凭据体系的密码学层（纯函数、无 IO、可单测）。
//!
//! 字节布局的唯一真相是浏览器仓的 `docs/credential-wire-contract.md`；
//! 本 crate 每个模块对应契约的一节，测试逐字节断言。
//!
//! | 模块 | 契约节 | 内容 |
//! |---|---|---|
//! | [`flags`] | §2.1 | 标志位常量（UP/UV/BE/BS/AT/ED） |
//! | [`keypair`] | §1.2.1 | ES256 密钥对 + 标准 PKCS#8 导出 |
//! | [`cose`] | §2.2 | COSE_Key（恰好 77 字节） |
//! | [`authdata`] | §2 | authData 逐字节 |
//! | [`attestation`] | §3 | attestationObject（fmt=none / attStmt={}） |
//! | [`envelope`] | §1 | 信封格式（Envelope v1） |
//! | [`kdf`] | §4 | 恢复码 KDF（Argon2id）+ base32 编码 |
//! | [`cbor`] | §3 | 手写最小 CBOR 编码器 |
//!
//! # 许可
//!
//! 只用 `ring`（Apache-2.0 + ISC + MIT）、`aes-gcm`/`sha2`/`argon2`（MIT/Apache-2.0）
//! ⇒ **可商用闭源**。⛔ 不含任何 GPL-3.0 实现的代码。
//!
//! # 依赖面
//!
//! ⛔ **不引入通用 CBOR 库**（契约 §3 明确要求手写最小编码器）：
//! 缩小依赖面 + 避免 canonicalization 分歧。
//!
//! # 确定性
//!
//! 固定测试向量要求可复现 ⇒ 所有随机字节都经 [`entropy::Entropy`] 注入；
//! 唯一例外是 ES256 密钥生成（`ring` 的 `SecureRandom` 是 sealed trait），
//! 确定性向量改用**固定 PKCS#8 夹具**。

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod attestation;
pub mod authdata;
pub mod cbor;
pub mod cose;
pub mod entropy;
pub mod envelope;
pub mod error;
pub mod flags;
pub mod kdf;
pub mod keypair;

pub use error::Error;
