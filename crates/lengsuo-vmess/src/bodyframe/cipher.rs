//! 数据段 AEAD 上下文（安全档分派 + 认证长度段）。
//!
//! 语义来源（只读参考，固定 commit `d2758a02`）：
//! - `proxy/vmess/encoding/client.go` `EncodeRequestBody` / `DecodeResponseBody`：
//!   按 `request.Security` 分派数据段 AEAD。
//! - `proxy/vmess/encoding/server.go` `DecodeRequestBody` / `EncodeResponseBody`：
//!   服务端同构。
//! - `proxy/vmess/encoding/auth.go` `GenerateChacha20Poly1305Key`：
//!   `MD5(b) || MD5(MD5(b))` 扩展成 32B。
//! - `common/crypto/auth.go` `AEADAuthenticator`：nonce 由 `GenerateChunkNonce`
//!   产生，**载荷段与认证长度段是两个独立闭包**（计数器各自从 0 起）。
//! - `common/crypto/chunk.go` `AEADChunkSizeParser`：长度段线上是
//!   `Seal(BE16(总长 - tag))`，解密端加回 tag。

use aes_gcm::aead::{Aead as _, KeyInit as _};

use crate::aead_chacha;
use crate::bodyframe::{BodySuite, KDF_PATH_AUTH_LEN, TAG_LEN};
use crate::kdf::kdf16;
use crate::{Error, Result};

/// 数据段 AEAD 上下文：套件 + 密钥 + 大端 2B 计数 nonce。
///
/// 不实现 `Debug`（内含密钥材料）。
///
/// 载荷段与认证长度段各持**独立**的计数 nonce（参考里是两个独立的
/// `GenerateChunkNonce` 闭包，计数器都从 0 起）。
pub struct BodyCipher {
    suite: BodySuite,
    payload_key: Vec<u8>,
    len_key: Option<Vec<u8>>,
    payload_iv: [u8; 16],
    len_iv: [u8; 16],
    payload_count: u16,
    len_count: u16,
}

impl BodyCipher {
    /// 由安全档与本方向 body key/iv 构造（不含认证长度段）。
    ///
    /// `security` 是线上安全档字节；未知/哨兵档位 fail-closed。
    pub fn new(security: u8, body_key: &[u8; 16], body_iv: &[u8; 16]) -> Result<Self> {
        let suite = BodySuite::from_security_byte(security)?;
        Ok(Self {
            payload_key: suite.derive_key(body_key),
            suite,
            len_key: None,
            payload_iv: *body_iv,
            len_iv: *body_iv,
            payload_count: 0,
            len_count: 0,
        })
    }

    /// 由套件构造（调用方已解析安全档）。
    pub fn from_suite(suite: BodySuite, body_key: &[u8; 16], body_iv: &[u8; 16]) -> Self {
        Self {
            suite,
            payload_key: suite.derive_key(body_key),
            len_key: None,
            payload_iv: *body_iv,
            len_iv: *body_iv,
            payload_count: 0,
            len_count: 0,
        }
    }

    /// 启用认证长度段。
    ///
    /// 密钥 = `KDF16(request_body_key, "auth_len")` 再按套件派生（AES 直接用
    /// 16B；ChaCha 走 MD5 链扩展成 32B）。nonce 基值恒为**请求方向**的
    /// `request_body_iv`（响应方向也一样，对齐参考 `server.go`）。
    pub fn enable_authenticated_length(
        &mut self,
        request_body_key: &[u8; 16],
        request_body_iv: &[u8; 16],
    ) -> Result<()> {
        if self.suite == BodySuite::None {
            // 参考的 NONE 分支根本不看 AuthenticatedLength 选项。
            return Err(Error::Unsupported {
                feature: "authenticated length with none security",
            });
        }
        let base = kdf16(request_body_key, &[KDF_PATH_AUTH_LEN]);
        self.len_key = Some(self.suite.derive_key(&base));
        self.len_iv = *request_body_iv;
        Ok(())
    }

    /// 当前套件。
    #[must_use]
    pub const fn suite(&self) -> BodySuite {
        self.suite
    }

    /// 已消耗的载荷 nonce 计数（诊断）。
    #[must_use]
    pub const fn payload_count(&self) -> u16 {
        self.payload_count
    }

    /// `GenerateChunkNonce`：计数写进 IV 前 2 字节（大端），nonce 取前 12 字节。
    fn nonce12(count: u16, iv: &[u8; 16]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&count.to_be_bytes());
        nonce[2..].copy_from_slice(&iv[2..12]);
        nonce
    }

    fn payload_nonce(&self) -> [u8; 12] {
        Self::nonce12(self.payload_count, &self.payload_iv)
    }

    fn len_nonce(&self) -> [u8; 12] {
        Self::nonce12(self.len_count, &self.len_iv)
    }

    /// 封装载荷段（不含长度段）。
    pub fn seal_payload(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.payload_nonce();
        self.payload_count = self.payload_count.wrapping_add(1);
        match self.suite {
            BodySuite::None => Ok(plain.to_vec()),
            BodySuite::Aes128Gcm => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&self.payload_key)
                    .expect("AES-128-GCM 固定 16B 密钥");
                cipher
                    .encrypt((&nonce).into(), plain)
                    .map_err(|_| Error::AuthFailed)
            }
            BodySuite::ChaCha20Poly1305 => {
                let key: [u8; 32] = self
                    .payload_key
                    .as_slice()
                    .try_into()
                    .expect("ChaCha20 key 已扩成 32B");
                Ok(aead_chacha::seal(&key, &nonce, plain, &[]))
            }
        }
    }

    /// 解封装载荷段（不含长度段）；tag 校验失败即 [`Error::AuthFailed`]。
    pub fn open_payload(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.payload_nonce();
        self.payload_count = self.payload_count.wrapping_add(1);
        match self.suite {
            BodySuite::None => Ok(ct.to_vec()),
            BodySuite::Aes128Gcm => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&self.payload_key)
                    .expect("AES-128-GCM 固定 16B 密钥");
                cipher
                    .decrypt((&nonce).into(), ct)
                    .map_err(|_| Error::AuthFailed)
            }
            BodySuite::ChaCha20Poly1305 => {
                let key: [u8; 32] = self
                    .payload_key
                    .as_slice()
                    .try_into()
                    .expect("ChaCha20 key 已扩成 32B");
                aead_chacha::open(&key, &nonce, ct, &[])
            }
        }
    }

    /// 封认证长度段（18 字节 = `Seal(BE16(总长 - 16))`）。
    ///
    /// `total` 是长度段之后应当跟随的字节数（密文 + tag + 明文 padding）。
    pub fn seal_len_segment(&mut self, total: u16) -> Result<Vec<u8>> {
        let key = self.len_key.as_ref().ok_or(Error::Unsupported {
            feature: "authenticated length segment not enabled",
        })?;
        let overhead = u16::try_from(self.suite.overhead()).map_err(|_| Error::BadLength {
            declared: self.suite.overhead(),
            got: u16::MAX as usize,
        })?;
        // 参考对 uint16 下溢是静默回绕；此处 fail-closed（帧本身已非法）。
        let plain_len = total.checked_sub(overhead).ok_or(Error::BadLength {
            declared: 0,
            got: total as usize,
        })?;
        let nonce = self.len_nonce();
        self.len_count = self.len_count.wrapping_add(1);
        match self.suite {
            BodySuite::Aes128Gcm => {
                let cipher =
                    aes_gcm::Aes128Gcm::new_from_slice(key).expect("AES-128-GCM 固定 16B 密钥");
                cipher
                    .encrypt((&nonce).into(), plain_len.to_be_bytes().as_slice())
                    .map_err(|_| Error::AuthFailed)
            }
            BodySuite::ChaCha20Poly1305 => {
                let key: [u8; 32] = key.as_slice().try_into().expect("ChaCha20 key 已扩成 32B");
                Ok(aead_chacha::seal(
                    &key,
                    &nonce,
                    &plain_len.to_be_bytes(),
                    &[],
                ))
            }
            BodySuite::None => Err(Error::Unsupported {
                feature: "authenticated length segment with none security",
            }),
        }
    }

    /// 解认证长度段（18 字节 → 长度段之后应当跟随的字节数）。
    pub fn open_len_segment(&mut self, wire: &[u8]) -> Result<u16> {
        let key = self.len_key.as_ref().ok_or(Error::Unsupported {
            feature: "authenticated length segment not enabled",
        })?;
        if wire.len() != 2 + TAG_LEN {
            return Err(Error::Truncated {
                need: 2 + TAG_LEN,
                got: wire.len(),
            });
        }
        let nonce = self.len_nonce();
        self.len_count = self.len_count.wrapping_add(1);
        let plain = match self.suite {
            BodySuite::Aes128Gcm => {
                let cipher =
                    aes_gcm::Aes128Gcm::new_from_slice(key).expect("AES-128-GCM 固定 16B 密钥");
                cipher
                    .decrypt((&nonce).into(), wire)
                    .map_err(|_| Error::AuthFailed)?
            }
            BodySuite::ChaCha20Poly1305 => {
                let key: [u8; 32] = key.as_slice().try_into().expect("ChaCha20 key 已扩成 32B");
                aead_chacha::open(&key, &nonce, wire, &[])?
            }
            BodySuite::None => {
                return Err(Error::Unsupported {
                    feature: "authenticated length segment with none security",
                })
            }
        };
        if plain.len() != 2 {
            return Err(Error::BadLength {
                declared: plain.len(),
                got: 2,
            });
        }
        let total = u16::from_be_bytes([plain[0], plain[1]]);
        let overhead = u16::try_from(self.suite.overhead()).map_err(|_| Error::BadLength {
            declared: self.suite.overhead(),
            got: u16::MAX as usize,
        })?;
        total.checked_add(overhead).ok_or(Error::BadLength {
            declared: total as usize,
            got: u16::MAX as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"request-body-key";
    const IV: [u8; 16] = *b"request-body-iv!";

    /// `Result::expect_err` 需要 `T: Debug`，而 `BodyCipher` 刻意不实现
    /// `Debug`（内含密钥）。这里显式取错误变体。
    fn expect_err<T>(result: Result<T>) -> Error {
        match result {
            Ok(_) => panic!("预期失败但成功了"),
            Err(error) => error,
        }
    }

    #[test]
    fn unknown_and_sentinel_security_bytes_fail_closed() {
        for security in [0u8, 1, 2, 6, 7, 0x0F] {
            let err = expect_err(BodyCipher::new(security, &KEY, &IV));
            assert!(
                matches!(err, Error::Unsupported { .. }),
                "security={security} 实际 {err:?}"
            );
        }
    }

    #[test]
    fn payload_and_length_counters_are_independent() {
        let mut cipher = BodyCipher::from_suite(BodySuite::Aes128Gcm, &KEY, &IV);
        cipher
            .enable_authenticated_length(&KEY, &IV)
            .expect("可启用");
        cipher.seal_payload(b"a").expect("可封");
        cipher.seal_len_segment(16).expect("可封");
        assert_eq!(cipher.payload_count(), 1);
        // 长度段有自己的计数器（不与载荷段共享）。
        assert_eq!(cipher.suite().overhead(), 16);
    }

    #[test]
    fn authenticated_length_requires_enable_and_rejects_none() {
        let mut cipher = BodyCipher::from_suite(BodySuite::Aes128Gcm, &KEY, &IV);
        let err = expect_err(cipher.seal_len_segment(16));
        assert!(matches!(err, Error::Unsupported { .. }));
        let mut none = BodyCipher::from_suite(BodySuite::None, &KEY, &IV);
        let err = expect_err(none.enable_authenticated_length(&KEY, &IV));
        assert!(matches!(err, Error::Unsupported { .. }));
    }
}
