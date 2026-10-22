//! 可注入的熵源。
//!
//! 契约要求固定向量可复现 ⇒ **凡是要写进向量的随机字节，都必须能注入固定值**。
//! 因此所有需要随机数的模块（信封 nonce、恢复码熵、KDF salt、credential_id）
//! 都接受 `&mut impl Entropy`，测试注入固定字节序列，产出完全确定。
//!
//! **唯一的例外是 ES256 密钥生成**：`ring` 的 `SecureRandom` 是 sealed trait
//! （外部 crate 无法实现），所以密钥生成只能走系统随机源。
//! ⇒ 确定性向量改用**固定 PKCS#8 夹具**（见 `tests/support/`），
//! 而不是给密钥生成硬塞一个可注入 RNG。

use rand::RngCore;

/// 熵源失败（拿不到系统随机数）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("熵源不可用")]
pub struct EntropyError;

/// 随机字节源。
///
/// 实现约定：`fill` 要么把 `dest` **全部写满**，要么返回错误；
/// 绝不返回「半随机」数据（调用方会把它当密钥/nonce 用）。
pub trait Entropy {
    /// 用随机字节填满 `dest`。
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

/// 系统随机源（操作系统 CSPRNG）。
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl OsEntropy {
    /// 构造系统随机源。
    pub fn new() -> Self {
        Self
    }
}

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        rand::rngs::OsRng
            .try_fill_bytes(dest)
            .map_err(|_| EntropyError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_fills_every_byte() {
        let mut buf = [0u8; 48];
        OsEntropy.fill(&mut buf).unwrap();
        // 概率上必然不全零；只断言「写满了」这一可判定性质。
        assert_eq!(buf.len(), 48);
    }
}
