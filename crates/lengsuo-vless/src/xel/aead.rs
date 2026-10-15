//! XEL 记录层 AEAD 后端（对齐 `common.go` 的 `NewAEAD` + `AEAD` 包装）。
//!
//! 为什么不直接复用 `ss_core::crypto::SessionAead`：XEL 记录把 5 字节头部作为
//! **附加认证数据**，nonce 是 **大端** 递增（`common.go` `IncreaseNonce` 从
//! `nonce[11]` 起加、向低位进位），且接收侧必须按**指定序号**取 nonce 而不是内部
//! 计数器。`SessionAead` 无 AAD、nonce 为 byte[0] 先行的小端进位、nonce 由内部
//! 顺序消耗，三点都不符。因此这里只调用与 `ss-core` 相同版本、相同许可
//! （MIT / Apache-2.0）的 RustCrypto `aes-gcm` / `chacha20poly1305`，不复制实现。

use aes_gcm::aead::generic_array::{typenum::U12, GenericArray};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use super::{Error, XelKey};

/// nonce 长度（两套 AEAD 都是 12 字节，与 `common.go` 的 `[12]byte` 一致）。
pub const NONCE_LEN: usize = 12;
/// tag 长度；等于 `ss_core::crypto::TAG_LEN`（同一 RustCrypto 后端）。
pub const TAG_LEN: usize = ss_core::crypto::TAG_LEN;
/// 序号上限：本实现把 nonce 计数器限制在 64 位。
///
/// `common.go` 在 96 位 nonce 计满后用记录字节重派生密钥（`MaxNonce` 分支）；
/// 密钥重派生属握手范围，因此这里用尽即 fail-closed，要求调用方重新握手。
pub const MAX_SEQUENCE: u64 = u64::MAX;

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
        super::KEY_LEN
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
enum Backend {
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
    fn new(cipher: XelCipher, key: &[u8]) -> Result<Self, Error> {
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

    fn encrypt(&self, nonce: &GenericArray<u8, U12>, payload: Payload) -> Result<Vec<u8>, Error> {
        match self {
            Self::Aes(aead) => aead.encrypt(nonce, payload),
            Self::ChaCha(aead) => aead.encrypt(nonce, payload),
        }
        .map_err(|_| Error::AuthFailed)
    }

    fn decrypt(&self, nonce: &GenericArray<u8, U12>, payload: Payload) -> Result<Vec<u8>, Error> {
        match self {
            Self::Aes(aead) => aead.decrypt(nonce, payload),
            Self::ChaCha(aead) => aead.decrypt(nonce, payload),
        }
        .map_err(|_| Error::AuthFailed)
    }
}

fn nonce_array(nonce: &[u8]) -> GenericArray<u8, U12> {
    // 固定 12 字节 → GenericArray<U12>，长度由调用方保证，无运行时失败分支。
    debug_assert_eq!(nonce.len(), NONCE_LEN);
    let mut array = GenericArray::<u8, U12>::default();
    array.copy_from_slice(nonce);
    array
}

/// 序号 → nonce 字节（大端；高 4 字节恒零）。
///
/// `common.go` 起始 nonce 全 0 且**先加后用**，故首个使用的 nonce 是
/// `00…0001`（序号 1），第二个是 `00…0002`。本函数固化该映射，使线上 nonce 与
/// 序号一一对应、可观测。
pub fn nonce_for_sequence(sequence: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

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
    /// 注入的 [`XelKey`] 在构造结束时清零丢弃，方向内只保留已展开的后端。
    pub fn new(cipher: XelCipher, key: XelKey) -> Self {
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
                max: super::MAX_RECORD_BODY_LEN,
            })?;
        if body > super::MAX_RECORD_BODY_LEN {
            return Err(Error::RecordTooLarge {
                got: plaintext_len,
                max: super::MAX_RECORD_BODY_LEN - TAG_LEN,
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

    /// 按**指定序号**解密（接收侧锁定步由 [`super::record`] 校验后传入）。
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
                min: super::MIN_RECORD_BODY_LEN,
                max: super::MAX_RECORD_BODY_LEN,
            });
        }
        let nonce = nonce_array(&nonce_for_sequence(sequence));
        // 错误密钥、篡改与 nonce 失步在 AEAD 层不可区分 → 同一认证失败。
        self.backend.decrypt(&nonce, Payload { msg: body, aad })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> XelKey {
        XelKey::new(&[byte; TAG_LEN * 2]).unwrap()
    }

    const CIPHERS: [XelCipher; 2] = [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305];

    #[test]
    fn nonce_is_big_endian_and_starts_at_one() {
        assert_eq!(
            nonce_for_sequence(1),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "先加后用：首次取用必须以 1 结尾"
        );
        assert_eq!(nonce_for_sequence(2)[11], 2);
        assert_eq!(
            nonce_for_sequence(256),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
        );
        let wide = nonce_for_sequence(u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(&wide[..4], &[0, 0, 0, 0]);
        assert_eq!(&wide[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(nonce_for_sequence(1).len(), NONCE_LEN);
    }

    #[test]
    fn seal_open_roundtrip_keeps_record_boundary() {
        for cipher in CIPHERS {
            let mut sender = AeadDirection::new(cipher, key(0x11));
            let mut receiver = AeadDirection::new(cipher, key(0x11));
            let (sequence, body) = sender.seal_at_next(b"hdr", b"record one").unwrap();
            assert_eq!(sequence, 1);
            assert_eq!(body.len(), 10 + TAG_LEN);
            assert_eq!(
                receiver.open_at(1, b"hdr", &body).unwrap(),
                b"record one",
                "{cipher:?} 记录边界必须逐字节保持"
            );
            assert_eq!(sender.sequence(), 1);
        }
    }

    #[test]
    fn sequence_increments_are_observable() {
        let mut sender = AeadDirection::new(XelCipher::Aes256Gcm, key(0x22));
        assert_eq!(sender.sequence(), 0);
        assert_eq!(sender.next_nonce_preview()[11], 1);
        let first = sender.seal_at_next(b"", b"a").unwrap();
        let second = sender.seal_at_next(b"", b"a").unwrap();
        assert_eq!((first.0, second.0), (1, 2), "序号必须严格递增且可观测");
        assert_eq!(first.1[11] % 2, second.1[11] % 2, "仅为可读性检查");
        assert_eq!(sender.next_nonce_preview()[11], 3);
        assert_eq!(sender.sequence(), 2);
    }

    #[test]
    fn aad_changes_break_authentication() {
        for cipher in CIPHERS {
            let mut sender = AeadDirection::new(cipher, key(0x33));
            let mut receiver = AeadDirection::new(cipher, key(0x33));
            let (_, body) = sender.seal_at_next(b"headA", b"same").unwrap();
            assert_eq!(
                receiver.open_at(1, b"headB", &body),
                Err(Error::AuthFailed),
                "{cipher:?} 头部（AAD）改动必须认证失败"
            );
            assert!(receiver.is_poisoned(), "认证失败后必须永久 poison");
            assert_eq!(receiver.open_at(2, b"headA", &body), Err(Error::Poisoned));
        }
    }

    #[test]
    fn tampered_tag_and_body_are_auth_failed() {
        for cipher in CIPHERS {
            for tweak in ["tag", "body"] {
                let mut sender = AeadDirection::new(cipher, key(0x44));
                let mut receiver = AeadDirection::new(cipher, key(0x44));
                let (_, mut body) = sender.seal_at_next(b"", b"payload!").unwrap();
                let index = match tweak {
                    "tag" => body.len() - 1,
                    _ => body.len() / 2,
                };
                body[index] ^= 0x01;
                assert_eq!(receiver.open_at(1, b"", &body), Err(Error::AuthFailed));
                assert!(receiver.is_poisoned());
            }
        }
    }

    #[test]
    fn wrong_key_fails_closed_without_panic() {
        for cipher in CIPHERS {
            let mut sender = AeadDirection::new(cipher, key(0x55));
            let mut victim = AeadDirection::new(cipher, key(0x99));
            let (_, body) = sender.seal_at_next(b"aad", b"secret text").unwrap();
            assert_eq!(victim.open_at(1, b"aad", &body), Err(Error::AuthFailed));
            assert!(victim.is_poisoned());
            // poison 后不得再解密任何记录（哪怕序号正确）。
            assert_eq!(victim.open_at(2, b"aad", &body), Err(Error::Poisoned));
        }
    }

    #[test]
    fn short_body_is_rejected_before_crypto() {
        let mut receiver = AeadDirection::new(XelCipher::Aes256Gcm, key(0x66));
        assert!(matches!(
            receiver.open_at(1, b"", &[0u8; TAG_LEN - 1]),
            Err(Error::InvalidRecordLength { .. })
        ));
        assert!(receiver.is_poisoned());
    }

    #[test]
    fn direction_debug_hides_key_bytes() {
        let state = AeadDirection::new(XelCipher::Aes256Gcm, key(0xA5));
        let printed = format!("{state:?}");
        assert!(!printed.contains("165"), "Debug 泄露密钥字节：{printed}");
        assert!(printed.contains("REDACTED"), "Debug 未标脱敏：{printed}");
    }

    #[test]
    fn body_len_accounts_for_tag_and_limit() {
        let state = AeadDirection::new(XelCipher::Aes256Gcm, key(0x77));
        assert_eq!(state.body_len(0).unwrap(), TAG_LEN);
        assert_eq!(
            state
                .body_len(super::super::MAX_RECORD_BODY_LEN - TAG_LEN)
                .unwrap(),
            super::super::MAX_RECORD_BODY_LEN
        );
        assert_eq!(
            state.body_len(super::super::MAX_RECORD_BODY_LEN - TAG_LEN + 1),
            Err(Error::RecordTooLarge {
                got: super::super::MAX_RECORD_BODY_LEN - TAG_LEN + 1,
                max: super::super::MAX_RECORD_BODY_LEN - TAG_LEN,
            })
        );
    }
}
