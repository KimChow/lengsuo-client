//! AEAD 套件选择与加密后端分发。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use aes_gcm::aead::generic_array::{typenum::U12, GenericArray};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use super::super::Error;
use super::{NONCE_LEN, TAG_LEN};

/// XEL 的两套 AEAD（`common.go` 的 `useAES` 二选一）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XelCipher {
    /// AES-256-GCM（参考端有 AES-NI 时选用）。
    Aes256Gcm,
    /// ChaCha20-Poly1305（参考端无 AES-NI 时选用）。
    ChaCha20Poly1305,
}

impl XelCipher {
    /// 密钥长度（blake3 派生输出 32 字节，两套相同）。
    pub fn key_len(self) -> usize {
        super::super::KEY_LEN
    }

    pub fn nonce_len(self) -> usize {
        NONCE_LEN
    }

    pub fn tag_len(self) -> usize {
        TAG_LEN
    }

    /// 密文相对明文的固定开销（= tag 长度）。
    pub fn overhead(self) -> usize {
        TAG_LEN
    }
}

/// 两套 AEAD 的具体后端。不用 `Box<dyn Aead>`：当前 `aead` 版本的关联类型
/// （`TagSize`/`NonceSize` 等）没有 dyn 兼容的默认值，枚举分发零开销且明确。
pub(super) enum Backend {
    Aes(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

/// 故意脱敏：后端持有密钥材料，`{:?}` 不输出任何字节。
impl core::fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Backend")
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl Backend {
    pub(super) fn new(cipher: XelCipher, key: &[u8]) -> Result<Self, Error> {
        let want = cipher.key_len();
        let bad = || Error::InvalidKeyLength {
            got: key.len(),
            want,
        };
        match cipher {
            XelCipher::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map(|aead| Self::Aes(Box::new(aead)))
                .map_err(|_| bad()),
            XelCipher::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map(Self::ChaCha)
                .map_err(|_| bad()),
        }
    }

    pub(super) fn encrypt(
        &self,
        nonce: &GenericArray<u8, U12>,
        payload: Payload,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Aes(aead) => aead.encrypt(nonce, payload),
            Self::ChaCha(aead) => aead.encrypt(nonce, payload),
        }
        .map_err(|_| Error::AuthFailed)
    }

    pub(super) fn decrypt(
        &self,
        nonce: &GenericArray<u8, U12>,
        payload: Payload,
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Aes(aead) => aead.decrypt(nonce, payload),
            Self::ChaCha(aead) => aead.decrypt(nonce, payload),
        }
        .map_err(|_| Error::AuthFailed)
    }
}

pub(super) fn nonce_array(nonce: &[u8]) -> GenericArray<u8, U12> {
    // 固定 12 字节 → GenericArray<U12>，长度由调用方保证，无运行时失败分支。
    debug_assert_eq!(nonce.len(), NONCE_LEN);
    let mut array = GenericArray::<u8, U12>::default();
    array.copy_from_slice(nonce);
    array
}
