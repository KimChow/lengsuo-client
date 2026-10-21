//! VMess 数据段分帧（对齐 `proxy/vmess/encoding/auth.go` 的 `ShakeSizeParser`
//! 与 `common/crypto/io.go` 的 chunk 语义、`GenerateChunkNonce`）。
//!
//! 线格式（每个数据 chunk）：
//! ```text
//! BE16(声明长度 ^ Shake128(iv).next()) || AEAD(载荷)   （chunkMasking 开启）
//! BE16(载荷明文长度) || AEAD(载荷)                     （无掩码；AEAD 依安全选项）
//! ```
//! - nonce：把 16 字节 requestBodyIV 的**前 2 字节**用作 BE16 计数器
//!   （`GenerateChunkNonce`：`binary.BigEndian.PutUint16(c, count); count++`，
//!   即每个 chunk 消耗一个 nonce，计数器大端递增，其余字节保持 IV 原值）。
//! - 安全选项 AES-128-GCM：key = requestBodyKey(16B)，nonce 12 字节
//!   （计数器 2B + IV[2..12]）；ChaCha20-Poly1305：key = MD5×2 扩展 32B，
//!   nonce 12 字节同构；none：无 AEAD（明文）。
//! - size 掩码：SHA3-Shake128(iv) 流式读 2 字节作 BE16 与声明长度异或，
//!   掩码流跨 chunk 连续（每 chunk 消耗 2 字节掩码）。
//! - 终止：写端以"声明长度为 0 的 chunk"表达 EOF（参考 `io.Copy` 收尾写入
//!   一个空 chunk），读取端遇到解出的 0 长度即正常收尾。
//!
//! fail-closed：认证失败/长度越界/掩码流错位后调用方必须弃用连接。
//!
//! 拆分：长度段掩码流在 [`size`]，数据段 AEAD 上下文与密钥派生在 [`cipher`]，
//! 无 padding 的分帧读写在 [`frame`]，带 GlobalPadding 的分帧读写在
//! [`padded`]，异步读写在 [`async_io`]。

mod async_io;
mod cipher;
mod frame;
mod padded;
mod size;

pub use async_io::{read_data_chunk, read_data_chunk_into, write_data_chunk, write_eof};
pub use cipher::{generate_chacha20_poly1305_key, md5_digest, new_data_aead, DataCipher};
pub use frame::{open_data_chunk, seal_data_chunk, write_data_eof};
pub use padded::{open_padded_chunk, read_padded_size, seal_padded_chunk};
pub use size::{plain_size_encode, shake_mask, DataSizeParser};

/// 单个 chunk 载荷明文上限。参考 `buf.Size` 为 8192（Size = 16384/2，含掩码
/// 开销与 tag 后由调用方保证 ≤ u16），本实现锁定 16384 上限并允许调用方
/// 用更小的分段写出。
pub const MAX_CHUNK_PAYLOAD: usize = 16384;

#[cfg(test)]
mod tests;
