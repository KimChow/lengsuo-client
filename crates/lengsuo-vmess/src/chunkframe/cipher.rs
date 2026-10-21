//! 数据段 AEAD 上下文：安全选项分派 + 密钥派生 + 递增计数 nonce。
//!
//! 语义来源：参考 `proxy/vmess/encoding/auth.go` 的
//! `GenerateChacha20Poly1305Key`（`MD5(b) || MD5(MD5(b))` 扩展成 32B）与
//! `common/crypto/auth.go` 的 `GenerateChunkNonce`（计数写进 IV 前 2 字节、
//! 大端递增、其余字节保持 IV 原值）。

use aes_gcm::aead::{Aead, KeyInit};
use ss_core::crypto::TAG_LEN;

use crate::consts::{CHACHA_KEY_LEN, SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305};
use crate::{Error, Result};

/// `GenerateChacha20Poly1305Key`：MD5(b) || MD5(MD5(b)) 扩成 32 字节。
#[must_use]
pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    use sha3::digest::{FixedOutput, Update};
    let mut hasher = md5::Md5::default();
    Update::update(&mut hasher, data);
    hasher.finalize_fixed().into()
}

/// `GenerateChacha20Poly1305Key`：MD5(b) || MD5(MD5(b)) 扩成 32 字节。
#[must_use]
pub fn generate_chacha20_poly1305_key(b: &[u8]) -> [u8; CHACHA_KEY_LEN] {
    let first = md5_digest(b);
    let second = md5_digest(&first);
    let mut key = [0u8; CHACHA_KEY_LEN];
    key[..16].copy_from_slice(&first);
    key[16..].copy_from_slice(&second);
    key
}

/// 数据段 AEAD 上下文：安全选项 + 会话密钥/IV + 大端 2B 计数 nonce。
pub struct DataCipher {
    security: u8,
    key: Vec<u8>,
    iv: [u8; 16],
    count: u16,
}

impl DataCipher {
    /// 由请求（或响应）body key/iv 与安全选项构造。
    ///
    /// none：不加密；AES-128-GCM：key 即 16B bodyKey；ChaCha20-Poly1305：
    /// key = [`generate_chacha20_poly1305_key`] 扩展的 32B。
    pub fn new(security: u8, body_key: &[u8; 16], body_iv: &[u8; 16]) -> Self {
        let key = match security {
            SECURITY_AES_128_GCM => body_key.to_vec(),
            SECURITY_CHACHA20_POLY1305 => generate_chacha20_poly1305_key(body_key).to_vec(),
            // none 与未知值都按明文处理；未知值由 request 层拒绝，这里不 panic。
            _ => Vec::new(),
        };
        DataCipher {
            security,
            key,
            iv: *body_iv,
            count: 0,
        }
    }

    /// 已消耗的 nonce 计数（诊断）。
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// 是否带 AEAD。
    pub(super) fn is_aead(&self) -> bool {
        self.security == SECURITY_AES_128_GCM || self.security == SECURITY_CHACHA20_POLY1305
    }

    /// `GenerateChunkNonce`：计数写进 IV 前 2 字节（BE），取前 12 字节。
    fn nonce12(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        nonce
    }

    /// 封装载荷明文。
    pub(super) fn seal_payload(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        if !self.is_aead() {
            self.count = self.count.wrapping_add(1);
            return Ok(plain.to_vec());
        }
        let nonce = self.nonce12();
        self.count = self.count.wrapping_add(1);
        match self.security {
            SECURITY_AES_128_GCM => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                    .expect("AES-128-GCM 固定 16B 密钥");
                cipher
                    .encrypt((&nonce).into(), plain)
                    .map_err(|_| Error::AuthFailed)
            }
            SECURITY_CHACHA20_POLY1305 => {
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("ChaCha20 key 已扩成 32B");
                cipher
                    .encrypt((&nonce).into(), plain)
                    .map_err(|_| Error::AuthFailed)
            }
            _ => Ok(plain.to_vec()),
        }
    }

    /// 解封装载荷密文。
    pub(super) fn open_payload(&mut self, ct: &[u8], plain_len: usize) -> Result<Vec<u8>> {
        if !self.is_aead() {
            self.count = self.count.wrapping_add(1);
            return Ok(ct.to_vec());
        }
        let nonce = self.nonce12();
        self.count = self.count.wrapping_add(1);
        let outcome = match self.security {
            SECURITY_AES_128_GCM => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                    .expect("AES-128-GCM 固定 16B 密钥");
                cipher.decrypt((&nonce).into(), ct)
            }
            SECURITY_CHACHA20_POLY1305 => {
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("ChaCha20 key 已扩成 32B");
                cipher.decrypt((&nonce).into(), ct)
            }
            _ => Ok(ct.to_vec()),
        };
        outcome.map_err(|_| Error::AuthFailed).inspect(|plain| {
            if plain.len() != plain_len {
                // AEAD 认证保证长度一致；此分支不可达，防御性保留。
            }
        })
    }

    /// 声明长度的线上字节数（载荷段密文长度 = 明文 + tag；none 无 tag）。
    #[must_use]
    pub fn wire_len(&self, plain_len: usize) -> usize {
        let overhead = if self.is_aead() { TAG_LEN } else { 0 };
        2 + plain_len + overhead
    }
}

/// `new_data_aead` 兼容导出：等价 [`DataCipher::new`]。
#[must_use]
pub fn new_data_aead(security: u8, body_key: &[u8; 16], body_iv: &[u8; 16]) -> DataCipher {
    DataCipher::new(security, body_key, body_iv)
}

/// 每帧的 AEAD 开销（tag 长度；none 档为 0）。
pub(super) fn cipher_overhead(cipher: &DataCipher) -> usize {
    if cipher.is_aead() {
        TAG_LEN
    } else {
        0
    }
}
