//! AEAD 原语层（与 Xray common/crypto 的 AEADAuthenticator + GenerateAEADNonceWithSize 行为对齐）。
//!
//! 关键语义（不可偏离）：
//! - nonce 从全 0xFF 起始，每次取用**先递增后使用**（首次取用 = 全 0，第二次 = ...01）
//! - 同一会话内 size 块与 payload 块共用同一递增序列（每块消耗 2 个 nonce：先 size 后 payload）
//! - AEAD 无 additional data

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

use crate::{Error, Result};

pub const TAG_LEN: usize = 16;

/// Xray Shadowsocks 支持的 AEAD 套件（config.go getCipher 的 Rust 对应物）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
    XChaCha20IetfPoly1305,
}

impl CipherSuite {
    /// 解析套件名（SIP00x 命名，与 Xray CipherType 对应）。
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Some(Self::ChaCha20IetfPoly1305),
            "xchacha20-ietf-poly1305" => Some(Self::XChaCha20IetfPoly1305),
            _ => None,
        }
    }

    /// 主密钥长度（KeyBytes）。
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            _ => 32,
        }
    }

    /// 会话 salt/IV 长度（IVBytes，Xray 表：AES-128-GCM=16，其余=32）。
    pub fn salt_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            _ => 32,
        }
    }

    /// nonce 长度（XChaCha 为 24，其余 12）。
    pub fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20IetfPoly1305 => 24,
            _ => 12,
        }
    }

    fn seal_raw(self, key: &[u8], nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let ct = match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
            Self::ChaCha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
            Self::XChaCha20IetfPoly1305 => XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
        };
        ct.map_err(|_| Error::SealFailed)
    }

    fn open_raw(self, key: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let pt = match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
            Self::ChaCha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
            Self::XChaCha20IetfPoly1305 => XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
        };
        pt.map_err(|_| Error::AuthFailed)
    }
}

/// 小端递增计数器 nonce：全 0xFF 起始，先增后用（首次输出全 0）。
/// 复刻 Xray GenerateIncreasingNonce 的进位方向：byte[0] 先加，进位向高位。
pub struct NonceCounter {
    counter: Vec<u8>,
}

impl NonceCounter {
    pub fn new(nonce_len: usize) -> Self {
        Self {
            counter: vec![0xFF; nonce_len],
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> &[u8] {
        for bytes in self.counter.iter_mut() {
            let (v, overflow) = bytes.overflowing_add(1);
            *bytes = v;
            if !overflow {
                break;
            }
        }
        &self.counter
    }
}

/// 一个会话方向的 AEAD 上下文（对应 Xray AEADAuthenticator + AEADChunkSizeParser 组合）。
pub struct SessionAead {
    suite: CipherSuite,
    subkey: Vec<u8>,
    nonce: NonceCounter,
}

impl SessionAead {
    /// 由 subkey 构造（subkey 由调用方经 kdf::hkdf_sha1_subkey 派生）。
    pub fn new(suite: CipherSuite, subkey: Vec<u8>) -> Self {
        debug_assert_eq!(subkey.len(), suite.key_len());
        Self {
            suite,
            subkey,
            nonce: NonceCounter::new(suite.nonce_len()),
        }
    }

    /// 加密任意明文块，消耗一个 nonce，返回 ct = pt || tag。
    pub fn seal(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.next().to_vec();
        self.suite.seal_raw(&self.subkey, &nonce, pt)
    }

    /// 解密任意密文块（pt||tag 形态），消耗一个 nonce。
    pub fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.next().to_vec();
        self.suite.open_raw(&self.subkey, &nonce, ct)
    }

    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_starts_at_zero_then_increments() {
        // Xray GenerateIncreasingNonce: c[i]++; if c[i]!=0 break —— FF+1=00 继续进位
        // 全 FF 起始 → 首次调用回绕为全 0，第二次为 [01,00×11]（little-endian 递增）
        let mut n = NonceCounter::new(12);
        assert_eq!(n.next(), &[0u8; 12]);
        assert_eq!(n.next(), &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut n2 = NonceCounter::new(1);
        assert_eq!(n2.next(), &[0]);
        assert_eq!(n2.next(), &[1]);
        // byte0 从 FF 走满一轮后进位到 byte1
        let mut n3 = NonceCounter::new(2);
        n3.next(); // 全 0
        for _ in 0..255 {
            n3.next(); // [1,0] ... [FF,0]
        }
        assert_eq!(n3.next(), &[0, 1]); // byte0 FF→00 进位，byte1 00→01
        assert_eq!(n3.next(), &[1, 1]);
    }

    #[test]
    fn suite_params_match_xray_table() {
        assert_eq!(CipherSuite::Aes128Gcm.key_len(), 16);
        assert_eq!(CipherSuite::Aes128Gcm.salt_len(), 16);
        assert_eq!(CipherSuite::Aes256Gcm.salt_len(), 32);
        assert_eq!(CipherSuite::ChaCha20IetfPoly1305.nonce_len(), 12);
        assert_eq!(CipherSuite::XChaCha20IetfPoly1305.nonce_len(), 24);
    }

    #[test]
    fn seal_open_roundtrip_all_suites() {
        for suite in [
            CipherSuite::Aes128Gcm,
            CipherSuite::Aes256Gcm,
            CipherSuite::ChaCha20IetfPoly1305,
            CipherSuite::XChaCha20IetfPoly1305,
        ] {
            let subkey = vec![7u8; suite.key_len()];
            let mut a = SessionAead::new(suite, subkey.clone());
            let mut b = SessionAead::new(suite, subkey);
            let pt = b"hello shadowsocks";
            let ct = a.seal(pt).unwrap();
            assert_eq!(ct.len(), pt.len() + 16);
            assert_eq!(b.open(&ct).unwrap(), pt);
        }
    }

    #[test]
    fn tampered_ct_fails_closed() {
        let subkey = vec![9u8; 16];
        let mut a = SessionAead::new(CipherSuite::Aes128Gcm, subkey.clone());
        let mut b = SessionAead::new(CipherSuite::Aes128Gcm, subkey);
        let mut ct = a.seal(b"data").unwrap();
        ct[0] ^= 0xFF;
        assert!(b.open(&ct).is_err());
    }
}
