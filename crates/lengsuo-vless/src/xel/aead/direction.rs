//! 单方向 AEAD 上下文：密钥 + 严格递增序号 + poison 位。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use aes_gcm::aead::Payload;

use super::super::Error;
use super::cipher::{nonce_array, Backend, XelCipher};
use super::nonce::nonce_for_sequence;
use super::{NONCE_LEN, TAG_LEN};

/// 单方向 AEAD 上下文：密钥 + 严格递增序号 + poison 位。
///
/// `Debug` 只输出套件、序号与 poison 状态，不输出密钥字节。
#[derive(Debug)]
pub struct AeadDirection {
    cipher: XelCipher,
    backend: Backend,
    sequence: u64,
    poisoned: bool,
}

impl AeadDirection {
    /// 由注入密钥建立方向状态；序号从 0 起（首次使用取 1）。
    /// 后端在构造期建立一次：密钥长度不符在这里 fail-closed，而不是每次加解密。
    /// 注入的 [`XelKey`](super::super::XelKey) 在构造结束时清零丢弃，方向内只保留
    /// 已展开的后端。
    pub fn new(cipher: XelCipher, key: super::super::XelKey) -> Self {
        let backend = Backend::new(cipher, key.as_slice())
            .expect("构造期密钥长度由 XelKey 强制为 32 字节，不会失败");
        Self {
            cipher,
            backend,
            sequence: 0,
            poisoned: false,
        }
    }

    pub fn cipher(&self) -> XelCipher {
        self.cipher
    }

    /// 最后成功使用的序号（0 = 尚未使用）。
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// 下一次发送将使用的 nonce（不消耗计数器），便于诊断递增趋势。
    pub fn next_nonce_preview(&self) -> [u8; NONCE_LEN] {
        nonce_for_sequence(self.sequence.saturating_add(1))
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 密文长度 = 明文长度 + tag；明文长度越出单记录范围时 fail-closed。
    pub fn body_len(&self, plaintext_len: usize) -> Result<usize, Error> {
        let body = plaintext_len
            .checked_add(TAG_LEN)
            .ok_or(Error::RecordTooLarge {
                got: plaintext_len,
                max: super::super::MAX_RECORD_BODY_LEN,
            })?;
        if body > super::super::MAX_RECORD_BODY_LEN {
            return Err(Error::RecordTooLarge {
                got: plaintext_len,
                max: super::super::MAX_RECORD_BODY_LEN - TAG_LEN,
            });
        }
        Ok(body)
    }

    /// 加密一条记录体：先取序号再加密（失败同样推进状态 ⇒ poison，禁止复用）。
    ///
    /// 返回 `(序号, 密文 || tag)`；序号由调用方写进头部长度之外不可见的位置，
    /// 线上不携带（与参考一致，接收方靠本地计数器对齐）。
    pub(crate) fn seal_at_next(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let next = match self.sequence.checked_add(1) {
            Some(next) => next,
            None => {
                self.poisoned = true;
                return Err(Error::SequenceExhausted);
            }
        };
        let outcome = self.seal_raw(next, aad, plaintext);
        match outcome {
            Ok(ct) => {
                self.sequence = next;
                Ok((next, ct))
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    /// 按**指定序号**解密（接收侧锁定步由 [`super::super::record`] 校验后传入）。
    pub(crate) fn open_at(
        &mut self,
        sequence: u64,
        aad: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        match self.open_raw(sequence, aad, body) {
            Ok(plaintext) => {
                self.sequence = sequence;
                Ok(plaintext)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn seal_raw(&self, sequence: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = nonce_array(&nonce_for_sequence(sequence));
        // GCM/ChaCha20Poly1305 的加密只在长度异常时失败；统一映射为认证失败，
        // 不给调用方任何可区分信号（也不回显明文）。
        self.backend.encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
    }

    fn open_raw(&self, sequence: u64, aad: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() < TAG_LEN {
            return Err(Error::InvalidRecordLength {
                got: body.len(),
                min: super::super::MIN_RECORD_BODY_LEN,
                max: super::super::MAX_RECORD_BODY_LEN,
            });
        }
        let nonce = nonce_array(&nonce_for_sequence(sequence));
        // 错误密钥、篡改与 nonce 失步在 AEAD 层不可区分 → 同一认证失败。
        self.backend.decrypt(&nonce, Payload { msg: body, aad })
    }
}
