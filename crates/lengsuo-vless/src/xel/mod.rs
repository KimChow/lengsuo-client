//! VLESS XEL（Xray Encryption Layer）记录层原语。
//!
//! 参考基线与 `header`/`xudp` 相同：Xray v26.3.27
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，对应
//! `proxy/vless/encryption/common.go`（AEAD 记录）与 `xor.go`（轻量 XOR 记录）。
//!
//! **范围**：本模块只做记录层——分帧、严格递增 nonce、序号锁定、可选 XOR 头部掩蔽。
//! XEL 的密钥协商（ML-KEM-768 × X25519、服务端公钥交换、票据与 0-RTT）明确不在范围内：
//! 会话密钥由调用方作为 [`XelKey`] 注入，本模块不参与生成、交换或握手派生。
//!
//! **fail-closed 纪律**：任何记录认证失败、序号失步、头部非法或长度截断之后，
//! 该方向状态立即永久 poison，之后的调用一律返回 [`Error::Poisoned`]。
//! 调用方必须弃用整条流——不重试、不回退明文、不换密钥继续读同一条流。
//!
//! **与参考实现的有意偏离**（一律取更严格，不做静默兼容）：
//! - `common.go` 在 96 位 nonce 计满后用记录字节重派生密钥；本实现把计数器限制在
//!   64 位，用尽即 poison 并要求重新握手（密钥重派生属握手范围）。
//! - `common.go` 的 `DecodeHeader` 在魔数不符时把长度置 0 后继续；本实现视为
//!   [`Error::InvalidHeader`] 并 poison。
//! - `xor.go` 同样忽略 `DecodeHeader` 错误继续运行；本实现 poison。
//! - 序号检查用**锁定步**（收到序号必须等于期望值），比
//!   [`ss_core::replay::Window`] 的 8192 位乱序窗口更严格；XEL 线上不携带序号，
//!   任何乱序都意味着 nonce 失步，因此窗口语义在此没有意义，取更严格者。
//!
//! 加密后端复用 `ss-core` 同一套 RustCrypto crate 与版本（`aes-gcm`、
//! `chacha20poly1305`、`aes`、`ctr`、`blake3`、`zeroize`，均为 MIT / Apache-2.0
//! 双许可；许可情况见 `docs/vless-status.md`）。本模块不含 `unsafe`
//! （crate 根 `lib.rs` 已 `#![forbid(unsafe_code)]`）。

pub mod aead;
pub mod frame;
pub mod record;
pub mod xor;

use zeroize::Zeroize as _;

/// 记录头魔数（`common.go` `EncodeHeader`：`h[0]=23, h[1]=3, h[2]=3`）。
pub const RECORD_MAGIC: [u8; 3] = [23, 3, 3];
/// 记录头长度：3 字节魔数 + BE16 记录体长度前缀。
pub const RECORD_HEADER_LEN: usize = 5;
/// 记录体最小长度（`common.go` `DecodeHeader` 的 `l < 17` 判据，即 1 字节明文 + tag）。
pub const MIN_RECORD_BODY_LEN: usize = 17;
/// 记录体最大长度（`common.go`：TLS 1.3 16384 + 256，RFC 8446 §5.2）。
pub const MAX_RECORD_BODY_LEN: usize = 16640;

/// XEL 会话密钥（单方向 AEAD 主密钥，或 XOR 层 CTR 主密钥材料）。
///
/// 不透明 newtype：**不派生 `Debug`**（只有脱敏实现），不派生 `PartialEq`/`Hash`/
/// `Serialize`，Drop 时清零。密钥来自调用方（握手/KEM 在范围外），因此这里不存在
/// 任何由本模块生成密钥的路径。
pub struct XelKey {
    bytes: Vec<u8>,
}

/// XEL 两套 AEAD 的密钥长度（blake3 派生输出 32 字节；AES-256-GCM 与
/// ChaCha20-Poly1305 都用 32 字节密钥）。
pub const KEY_LEN: usize = 32;

impl XelKey {
    /// 注入会话密钥；长度必须等于 [`KEY_LEN`]，否则 fail-closed 拒绝。
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != KEY_LEN {
            // 只报长度，绝不回显任何密钥字节。
            return Err(Error::InvalidKeyLength {
                got: bytes.len(),
                want: KEY_LEN,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// 密钥长度（诊断用，不暴露内容）。
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// newtype 长度由构造强制为 [`KEY_LEN`]；保留本方法以符合 Rust 惯例。
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for XelKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// 故意脱敏：`{:?}` 只输出类型名与长度，绝不输出密钥字节。
impl core::fmt::Debug for XelKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XelKey")
            .field("len", &self.bytes.len())
            .field("material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// XEL 记录层统一错误。所有 Display 只含长度／序号，不含密钥、明文或密文字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 注入密钥长度不符（只报长度）。
    #[error("会话密钥长度非法：{got} 字节，需要 {want} 字节")]
    InvalidKeyLength { got: usize, want: usize },

    /// 记录头魔数（`23 03 03`）不符：对端协议错误或主动攻击。
    #[error("记录头非法：魔数不符")]
    InvalidHeader,

    /// 记录体长度越界（参考常量 17..=16640）。
    #[error("记录体长度越界：{got} 字节，允许 {min}..={max}")]
    InvalidRecordLength {
        got: usize,
        min: usize,
        max: usize,
    },

    /// 明文超出单记录上限。
    #[error("明文超出单记录上限：{got} 字节，上限 {max} 字节")]
    RecordTooLarge { got: usize, max: usize },

    /// AEAD 认证失败（错误密钥、篡改或 nonce 失步，三者不可区分）。
    #[error("记录认证失败")]
    AuthFailed,

    /// 序号不是期望的下一个值（重放、超前或乱序）。
    #[error("记录序号失步：期望 {expected}，收到 {received}")]
    SequenceOutOfSync { expected: u64, received: u64 },

    /// 序号计数器用尽（64 位上限），必须重新握手。
    #[error("发送序号已用尽，必须重新握手")]
    SequenceExhausted,

    /// 流被截断（头部或记录体不完整）。
    #[error("记录截断：需要 {need} 字节，只有 {got} 字节")]
    Truncated { need: usize, got: usize },

    /// IV 长度不符（XOR 层需要 16 字节 AES-CTR IV）。
    #[error("IV 长度非法：{got} 字节，需要 {want} 字节")]
    InvalidIvLength { got: usize, want: usize },

    /// 状态已 poison：先前的失效已使该方向永久不可用，调用方必须弃用整条流。
    #[error("状态已 poison，必须弃用整条流")]
    Poisoned,
}

impl Error {
    /// 本模块所有错误都是不可恢复的安全失效（调用方须弃用整条流），恒为真。
    pub fn is_fatal(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_must_be_32_bytes() {
        assert!(XelKey::new(&[0u8; KEY_LEN]).is_ok());
        for bytes in [&[0u8; 31][..], &[], &[0u8; 33][..]] {
            assert_eq!(
                XelKey::new(bytes),
                Err(Error::InvalidKeyLength {
                    got: bytes.len(),
                    want: KEY_LEN
                })
            );
        }
    }

    /// 密钥材料不得出现在 Debug 输出里。
    #[test]
    fn debug_never_prints_key_bytes() {
        let key = XelKey::new(&[0xA5u8; KEY_LEN]).unwrap();
        let printed = format!("{key:?}");
        assert!(printed.contains("REDACTED"), "Debug 未脱敏：{printed}");
        assert!(
            !printed.contains("165") && !printed.contains("a5"),
            "Debug 泄露密钥字节：{printed}"
        );
        assert_eq!(key.len(), KEY_LEN);
        assert!(!key.is_empty());
    }

    /// 错误消息不得包含注入的密钥／明文材料。
    #[test]
    fn error_display_never_prints_secret_bytes() {
        let errors = [
            Error::InvalidKeyLength {
                got: 32,
                want: 16,
            },
            Error::InvalidHeader,
            Error::InvalidRecordLength {
                got: 1,
                min: MIN_RECORD_BODY_LEN,
                max: MAX_RECORD_BODY_LEN,
            },
            Error::RecordTooLarge { got: 9, max: 8 },
            Error::AuthFailed,
            Error::SequenceOutOfSync {
                expected: 0,
                received: 1,
            },
            Error::SequenceExhausted,
            Error::Truncated { need: 5, got: 2 },
            Error::InvalidIvLength { got: 1, want: 16 },
            Error::Poisoned,
        ];
        for error in errors {
            let text = error.to_string();
            assert!(!text.is_empty());
            assert!(
                !text.contains("165") && !text.contains("0xa5"),
                "错误消息含密钥字节：{text}"
            );
            assert!(error.is_fatal());
        }
    }

    #[test]
    fn reference_constants_are_locked() {
        assert_eq!(RECORD_MAGIC, [23, 3, 3]);
        assert_eq!(RECORD_HEADER_LEN, 5);
        assert_eq!(MIN_RECORD_BODY_LEN, 1 + ss_core::crypto::TAG_LEN);
        assert_eq!(MAX_RECORD_BODY_LEN, 16384 + 256);
    }
}
