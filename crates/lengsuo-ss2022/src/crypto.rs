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
}
impl Method {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
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
    pub(crate) fn header(&self, bytes: [u8; 16], encrypt: bool) -> [u8; 16] {
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
        }
        block.into()
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
        };
        result.map_err(|_| Error::Authentication)
    }
}
