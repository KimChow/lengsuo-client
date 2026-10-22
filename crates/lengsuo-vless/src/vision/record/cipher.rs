//! AEAD 后端与 96 位 nonce 计数器：对齐 `common.go` 的 `NewAEAD` / `AEAD` /
//! `IncreaseNonce`。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead as _;
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use super::{Cipher, Error, NONCE_LEN};

/// 参考 `MaxNonce`（96 位全 1）。
pub const MAX_NONCE: [u8; NONCE_LEN] = [0xFF; NONCE_LEN];

/// 参考 `IncreaseNonce`：96 位大端自增（从 `nonce[11]` 起向低位进位）。
pub fn increase_nonce(nonce: &mut [u8; NONCE_LEN]) -> &mut [u8; NONCE_LEN] {
    for index in (0..NONCE_LEN).rev() {
        nonce[index] = nonce[index].wrapping_add(1);
        if nonce[index] != 0 {
            break;
        }
    }
    nonce
}

fn nonce_array(nonce: &[u8]) -> GenericArray<u8, U12> {
    debug_assert_eq!(nonce.len(), NONCE_LEN);
    let mut array = GenericArray::<u8, U12>::default();
    array.copy_from_slice(nonce);
    array
}

/// 两套 AEAD 的具体后端。
enum Backend {
    Aes(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

impl core::fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Backend([REDACTED])")
    }
}

/// 参考 `common.go` 的 `AEAD`：内部 96 位 nonce + AEAD 后端。
pub struct Aead {
    backend: Backend,
    nonce: [u8; NONCE_LEN],
}

impl core::fmt::Debug for Aead {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Aead")
            .field("nonce", &self.nonce)
            .field("backend", &"[REDACTED]")
            .finish()
    }
}

impl Aead {
    /// 参考 `NewAEAD(ctx, key, useAES)`：`blake3::derive_key(ctx, key)` 派生 32 字节密钥。
    ///
    /// `key` 为握手材料（`nfsKey` / `UnitedKey` 等，长度不拘，参考先 blake3 派生）；
    /// `ctx` 为派生上下文。Rust blake3 仅接受 `&str` context，非 UTF-8 的握手上下文
    /// 见模块文档偏离说明（本卡不做二进制定长 context，取 fail-closed/报告）。
    pub fn new(ctx: &str, key: &[u8], cipher: Cipher) -> Self {
        let derived: [u8; 32] = blake3::derive_key(ctx, key);
        let backend = match cipher {
            Cipher::Aes256Gcm => Backend::Aes(Box::new(
                Aes256Gcm::new_from_slice(&derived).expect("32 字节密钥"),
            )),
            Cipher::ChaCha20Poly1305 => {
                Backend::ChaCha(ChaCha20Poly1305::new_from_slice(&derived).expect("32 字节密钥"))
            }
        };
        Self {
            backend,
            nonce: [0u8; NONCE_LEN],
        }
    }

    /// 当前 nonce（下一次自动取用前的值；参考先加后用）。
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// 参考 `AEAD.Seal`：`nonce == None` 时先 [`increase_nonce`] 再使用。
    pub fn seal(
        &mut self,
        nonce: Option<&[u8]>,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce: &[u8] = match nonce {
            Some(explicit) => explicit,
            None => {
                if self.nonce == MAX_NONCE {
                    return Err(Error::NonceExhausted);
                }
                increase_nonce(&mut self.nonce)
            }
        };
        debug_assert_eq!(nonce.len(), NONCE_LEN);
        let payload = Payload {
            msg: plaintext,
            aad: additional_data,
        };
        match &self.backend {
            Backend::Aes(aead) => aead.encrypt(&nonce_array(nonce), payload),
            Backend::ChaCha(aead) => aead.encrypt(&nonce_array(nonce), payload),
        }
        .map_err(|_| Error::AuthFailed)
    }

    /// 参考 `AEAD.Open`：`nonce == None` 时先 [`increase_nonce`] 再使用。
    pub fn open(
        &mut self,
        nonce: Option<&[u8]>,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce: &[u8] = match nonce {
            Some(explicit) => explicit,
            None => {
                if self.nonce == MAX_NONCE {
                    return Err(Error::NonceExhausted);
                }
                increase_nonce(&mut self.nonce)
            }
        };
        debug_assert_eq!(nonce.len(), NONCE_LEN);
        let payload = Payload {
            msg: ciphertext,
            aad: additional_data,
        };
        match &self.backend {
            Backend::Aes(aead) => aead.decrypt(&nonce_array(nonce), payload),
            Backend::ChaCha(aead) => aead.decrypt(&nonce_array(nonce), payload),
        }
        .map_err(|_| Error::AuthFailed)
    }
}
