//! VLESS Vision AEAD 记录层：对齐 `common.go` 的 `NewAEAD` / `AEAD` /
//! `IncreaseNonce` / `EncodeLength` / `DecodeLength` / `EncodeHeader` /
//! `DecodeHeader`，并按 `CommonConn.Write/Read` 的记录路径封装/解封。
//!
//! 与 [`crate::xel`] 的差异在密钥派生（见 [`crate::vision`] 模块文档）：本模块的
//! [`Aead::new`] 按参考 `NewAEAD(ctx, key, useAES)` 用 `blake3::derive_key(ctx, key)`
//! 从原始握手材料派生 32 字节密钥，ctx 是握手上下文而非已派生密钥。
//!
//! **与参考的有意偏离（取更严格，全部不可达/在报告偏离清单说明）**：
//! - 参考 nonce 计满 `MaxNonce` 后改用刚产出的记录字节重派生密钥；本实现把
//!   96 位 nonce 用尽视为 fail-closed（[`Error::NonceExhausted`]）。96 位 nonce
//!   在单个连接生命周期内不可达，且参考的二进制 ctx 重派生与 Rust blake3
//!   仅接受 `&str` context 的差异同源，故不重派生。
//! - `DecodeHeader` 参考在魔数不符时把长度清 0 后仍返回 `(0, err)`；本实现直接
//!   返回 [`Error::InvalidHeader`]，语义等价（长度 0 本就落入越界分支）。
//!
//! **目录结构**（拆分自原单文件 `record.rs`，行为逐字节等价）：
//! - `codec`：记录头 / 长度的编解码（`EncodeLength` / `DecodeHeader` 等）；
//! - `cipher`：AEAD 后端与 96 位 nonce 计数器（`Aead` / `IncreaseNonce`）；
//! - `stream`：记录流的发送 / 接收方向（`RecordWriter` / `RecordReader`）；
//! - `tests`：单元测试。
//!
//! 本模块不含 `unsafe`。

mod cipher;
mod codec;
mod stream;

#[cfg(test)]
mod tests;

pub use cipher::{increase_nonce, Aead, MAX_NONCE};
pub use codec::{
    decode_header, decode_length, encode_header, encode_length, HEADER_LEN, MAGIC, MAX_BODY_LEN,
    MIN_BODY_LEN,
};
pub use stream::{RecordReader, RecordWriter};

/// `CommonConn.Write` 的单次明文分块上限（8192）。
pub const RECORD_CHUNK: usize = 8192;
/// 两套 AEAD 的 nonce 长度（`common.go` 的 `[12]byte`）。
pub const NONCE_LEN: usize = 12;
/// 两套 AEAD 的 tag 长度。
pub const TAG_LEN: usize = 16;

/// AEAD 套件（`common.go` 的 `useAES` 二选一）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-256-GCM。
    Aes256Gcm,
    /// ChaCha20-Poly1305。
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("记录头非法")]
    InvalidHeader,
    #[error("记录体长度越界：{got} 字节，允许 {min}..={max}")]
    InvalidRecordLength { got: usize, min: usize, max: usize },
    #[error("记录认证失败")]
    AuthFailed,
    #[error("nonce 已用尽，必须重新握手")]
    NonceExhausted,
    #[error("记录截断：需要 {need} 字节，只有 {got} 字节")]
    Truncated { need: usize, got: usize },
    #[error("状态已 poison，必须弃用整条流")]
    Poisoned,
}
