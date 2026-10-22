//! XEL 记录层 AEAD 后端（对齐 `common.go` 的 `NewAEAD` + `AEAD` 包装）。
//!
//! 为什么不直接复用 `ss_core::crypto::SessionAead`：XEL 记录把 5 字节头部作为
//! **附加认证数据**，nonce 是 **大端** 递增（`common.go` `IncreaseNonce` 从
//! `nonce[11]` 起加、向低位进位），且接收侧必须按**指定序号**取 nonce 而不是内部
//! 计数器。`SessionAead` 无 AAD、nonce 为 byte[0] 先行的小端进位、nonce 由内部
//! 顺序消耗，三点都不符。因此这里只调用与 `ss-core` 相同版本、相同许可
//! （MIT / Apache-2.0）的 RustCrypto `aes-gcm` / `chacha20poly1305`，不复制实现。
//!
//! **目录结构**（拆分自原单文件 `aead.rs`，行为逐字节等价）：
//! - `cipher`：套件选择（`XelCipher`）与加密后端分发；
//! - `nonce`：序号 → nonce 字节的映射（`nonce_for_sequence`）；
//! - `direction`：单方向 AEAD 上下文 [`AeadDirection`]（序号 + poison 位）；
//! - `tests`：单元测试。

mod cipher;
mod direction;
mod nonce;

#[cfg(test)]
mod tests;

pub use cipher::XelCipher;
pub use direction::AeadDirection;
pub use nonce::nonce_for_sequence;

/// nonce 长度（两套 AEAD 都是 12 字节，与 `common.go` 的 `[12]byte` 一致）。
pub const NONCE_LEN: usize = 12;
/// tag 长度；等于 `ss_core::crypto::TAG_LEN`（同一 RustCrypto 后端）。
pub const TAG_LEN: usize = ss_core::crypto::TAG_LEN;
/// 序号上限：本实现把 nonce 计数器限制在 64 位。
///
/// `common.go` 在 96 位 nonce 计满后用记录字节重派生密钥（`MaxNonce` 分支）；
/// 密钥重派生属握手范围，因此这里用尽即 fail-closed，要求调用方重新握手。
pub const MAX_SEQUENCE: u64 = u64::MAX;
