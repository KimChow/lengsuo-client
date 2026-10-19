//! SIP022 基线 20b4952e8a54e696ebcabc5f91b5dad7f322f2da；不使用口令派生。
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
    /// SIP022 `2022-blake3-chacha20-poly1305`：仅 TCP 会话走此套件；
    /// UDP separate header 是 AES 专有原语，见 [`Key::header`]。
    ChaCha20,
}
impl Method {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::ChaCha20 => 32,
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
            // UDP separate header 由 AES 块加密承载；ChaCha 方法的 UDP 采用
            // XChaCha20 24 字节 nonce 的另一种头部布局，不是本原语。
            Method::ChaCha20 => return Err(Error::Unsupported),
        }
        Ok(block.into())
    }
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
            // UDP body 是 AES-GCM 12 字节 nonce；ChaCha 的 UDP 布局不使用此原语。
            Method::ChaCha20 => return Err(Error::Unsupported),
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
    fn chacha_rejects_aes_only_udp_primitives() {
        let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
        assert!(matches!(key.header([0; 16], true), Err(Error::Unsupported)));
        assert!(matches!(
            key.body(&[0; 32], &[0; 12], b"x", true),
            Err(Error::Unsupported)
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
