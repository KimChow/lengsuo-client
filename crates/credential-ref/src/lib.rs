#![forbid(unsafe_code)]
//! 凭据引用化与本地加密存储 v0。
//!
//! ## 目标
//! - [`CredentialRef`]：只承载元数据（引用 id、作用域、过期时刻），永不携带明文；
//!   `Debug`/`Display` 对 id 与作用域目标恒输出掩码，可安全写入诊断输出。
//! - [`SecretStore`]：`put/get/delete/list` 抽象；提供 [`MemoryStore`]（测试与开发用，
//!   明文常驻内存）与 [`FileStore`]（口令派生密钥、AES-256-GCM 逐条加密落盘）。
//! - [`Plaintext`]：明文只以此形式短暂存在，内部 `Zeroizing`，离开作用域清零。
//!
//! ## 隔离与过期
//! - `get`/`delete` 要求引用作用域与记录作用域完全一致，跨作用域返回
//!   [`StoreError::ScopeMismatch`]，不返回明文；`list` 只返回同作用域且未过期的引用。
//! - 达到 `expires_at_ms` 即视为过期（不宽限），读取返回 [`StoreError::Expired`]。
//! - 时钟通过 [`StoreClock`] 注入，测试可用 [`fixed_clock`] 获得确定性结果。
//!
//! ## fail-closed
//! - schema 版本不识别 → 拒绝读取，不尝试解密（[`StoreError::UnsupportedVersion`]）。
//! - magic 不符、截断、长度不自洽、尾部多余字节 → [`StoreError::MalformedContainer`]。
//! - 口令错误 → [`StoreError::WrongPassphrase`]；密文/元数据被篡改 →
//!   [`StoreError::RecordAuthentication`]。文件不存在才视为空库，其余错误一律上抛。
//! - 任何错误值、`Debug`、`Display` 都不含明文、口令、派生密钥、salt 或密文字节。
//! - 不落盘明文（`FileStore` 只存密文）；`MemoryStore` 不落盘，仅用于测试与开发路径。
//!
//! KDF/加密参数见 [`KdfParams`] 与 `crypto` 模块文档；文件布局见 `container` 模块文档。

pub mod container;
pub mod crypto;
pub mod error;
pub mod file;
pub mod memory;
pub mod plaintext;
pub mod reference;
pub mod store;

pub use crypto::KdfParams;
pub use error::StoreError;
pub use file::FileStore;
pub use memory::MemoryStore;
pub use plaintext::Plaintext;
pub use reference::{CredentialRef, RefId, Scope, ScopeKind};
pub use store::{fixed_clock, system_clock, SecretStore, StoreClock};
