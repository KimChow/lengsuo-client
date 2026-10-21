//! 请求头尾部的 FNV-1a 校验与 `CipherSpec` 兼容占位。

use super::model::SecurityOption;
use super::KEY_LEN;

/// FNV-1a 32 位（`hash/fnv` New32a，与参考 `Authenticate` 一致）。
#[must_use]
pub fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    for &byte in bytes {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// `CipherSpec` 兼容占位：安全选项 + 数据段密钥派生结果。
/// （保留导出名以满足 lib.rs 的公开面；具体派生在 `chunkframe::DataCipher`。）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSpec {
    /// 安全选项。
    pub security: SecurityOption,
}

impl CipherSpec {
    /// 数据段 AEAD 密钥长度（none 为 0）。
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self.security {
            SecurityOption::Aes128Gcm => KEY_LEN,
            SecurityOption::ChaCha20Poly1305 => 32,
            _ => 0,
        }
    }
}
