//! SIP022 基线 20b4952e8a54e696ebcabc5f91b5dad7f322f2da；不使用口令派生。
//!
//! AES 系列与 ChaCha 系列的 UDP 头部布局不同，见 [`Key::header`] / [`Key::body`]：
//! - `2022-blake3-aes-128/256-gcm`：16 字节 separate header 由 AES 块加密承载，
//!   AEAD 用 12 字节 nonce（取自 header[4..16]），subkey 由 psk+salt 派生。
//! - `2022-blake3-chacha20-poly1305`：24 字节随机 nonce 明文置于包首，
//!   AEAD 直接用 PSK（无 subkey 派生），nonce 为完整 24 字节。
use crate::Error;
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt},
    Aes128, Aes256,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128,
    Aes256,
    /// SIP022 `2022-blake3-chacha20-poly1305`：TCP 用 32 字节 salt 派生 subkey；
    /// UDP 走 XChaCha20-Poly1305（24 字节 nonce），见 [`Key::udp_seal`]。
    ChaCha20,
}
impl Method {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::ChaCha20 => 32,
        }
    }
    /// UDP 明文包首的 nonce 前缀长度；AES 系列用 AES 块（16），ChaCha 用 XChaCha nonce（24）。
    pub fn udp_nonce_len(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes256 => 16,
            Self::ChaCha20 => 24,
        }
    }
}
/// 不派生 Debug，PSK 只能由可信配置注入。
#[derive(Clone)]
pub struct Key {
    method: Method,
    psk: Vec<u8>,
}
impl Key {
    pub fn new(method: Method, psk: &[u8]) -> Result<Self, Error> {
        if psk.len() != method.key_len() {
            return Err(Error::KeyLength);
        }
        Ok(Self {
            method,
            psk: psk.to_vec(),
        })
    }
    pub fn method(&self) -> Method {
        self.method
    }
    pub(crate) fn subkey(&self, salt: &[u8]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
        hasher.update(&self.psk);
        hasher.update(salt);
        let mut result = vec![0; self.method.key_len()];
        hasher.finalize_xof().fill(&mut result);
        result
    }
    /// AES 系列 UDP separate header（16 字节，块加密）；ChaCha 无此原语。
    pub(crate) fn header(&self, bytes: [u8; 16], encrypt: bool) -> Result<[u8; 16], Error> {
        let mut block = bytes.into();
        match self.method {
            Method::Aes128 => {
                let cipher = Aes128::new_from_slice(&self.psk).expect("构造时已校验长度");
                if encrypt {
                    cipher.encrypt_block(&mut block)
                } else {
                    cipher.decrypt_block(&mut block)
                }
            }
            Method::Aes256 => {
                let cipher = Aes256::new_from_slice(&self.psk).expect("构造时已校验长度");
                if encrypt {
                    cipher.encrypt_block(&mut block)
                } else {
                    cipher.decrypt_block(&mut block)
                }
            }
            Method::ChaCha20 => return Err(Error::Unsupported),
        }
        Ok(block.into())
    }
}

/// ChaCha20-Poly1305 UDP 载荷：XChaCha20（24 字节 nonce），直接使用 PSK。
/// 参考 `sing-shadowsocks/shadowaead_2022`：`chacha20poly1305.NewX(psk)`，
/// `Seal(nonce[0:24], plaintext, nil)`，AEAD 覆盖 nonce 之后的全部字节。
mod xchacha {
    use chacha20poly1305::{
        aead::{Aead as _, KeyInit as _},
        XChaCha20Poly1305, XNonce,
    };

    pub(super) fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        let nonce: &[u8; 24] = nonce.try_into().ok()?;
        XChaCha20Poly1305::new_from_slice(key)
            .ok()?
            .encrypt(XNonce::from_slice(nonce), plaintext)
            .ok()
    }

    pub(super) fn open(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let nonce: &[u8; 24] = nonce.try_into().ok()?;
        XChaCha20Poly1305::new_from_slice(key)
            .ok()?
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .ok()
    }
}

impl Key {
    pub(crate) fn body(
        &self,
        subkey: &[u8],
        nonce: &[u8],
        bytes: &[u8],
        encrypt: bool,
    ) -> Result<Vec<u8>, Error> {
        let result = match self.method {
            Method::Aes128 => {
                let cipher = Aes128Gcm::new_from_slice(subkey).map_err(|_| Error::KeyLength)?;
                if encrypt {
                    cipher.encrypt(nonce.into(), bytes)
                } else {
                    cipher.decrypt(nonce.into(), bytes)
                }
            }
            Method::Aes256 => {
                let cipher = Aes256Gcm::new_from_slice(subkey).map_err(|_| Error::KeyLength)?;
                if encrypt {
                    cipher.encrypt(nonce.into(), bytes)
                } else {
                    cipher.decrypt(nonce.into(), bytes)
                }
            }
            Method::ChaCha20 => {
                return if encrypt {
                    xchacha::seal(&self.psk, nonce, bytes)
                } else {
                    xchacha::open(&self.psk, nonce, bytes)
                }
                .ok_or(Error::Authentication);
            }
        };
        result.map_err(|_| Error::Authentication)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_constructs_and_derives_full_subkey() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        assert_eq!(key.method().key_len(), 32);
        assert_eq!(key.subkey(&[0x22; 32]).len(), 32);
    }

    #[test]
    fn chacha_has_no_aes_separate_header() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        assert!(matches!(key.header([0; 16], true), Err(Error::Unsupported)));
    }

    #[test]
    fn chacha_udp_nonce_is_24_bytes() {
        assert_eq!(Method::ChaCha20.udp_nonce_len(), 24);
        assert_eq!(Method::Aes128.udp_nonce_len(), 16);
        assert_eq!(Method::Aes256.udp_nonce_len(), 16);
    }

    #[test]
    fn chacha_body_roundtrips_with_psk_not_subkey() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        let nonce = [0x33; 24];
        let sealed = key.body(&[], &nonce, b"payload", true).unwrap();
        assert_eq!(sealed.len(), b"payload".len() + 16);
        let opened = key.body(&[], &nonce, &sealed, false).unwrap();
        assert_eq!(opened, b"payload");
    }

    #[test]
    fn chacha_body_rejects_tampered_tag() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        let nonce = [0x33; 24];
        let mut sealed = key.body(&[], &nonce, b"payload", true).unwrap();
        sealed[0] ^= 1;
        assert!(matches!(
            key.body(&[], &nonce, &sealed, false),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn method_key_lengths_include_chacha_32() {
        assert_eq!(Method::Aes128.key_len(), 16);
        assert_eq!(Method::Aes256.key_len(), 32);
        assert_eq!(Method::ChaCha20.key_len(), 32);
        assert!(Key::new(Method::Aes128, &[0; 32]).is_err());
        assert!(Key::new(Method::ChaCha20, &[0; 16]).is_err());
        assert!(Key::new(Method::ChaCha20, &[0; 32]).is_ok());
    }
}
