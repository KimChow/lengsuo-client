//! VMess **数据段**（body）套件分派与「认证长度段」分帧。
//!
//! 语义来源（只读参考，固定 commit `d2758a02`）：
//! - `proxy/vmess/encoding/client.go` `EncodeRequestBody` / `DecodeResponseBody`：
//!   按 `request.Security` 分派数据段 AEAD——AES-128-GCM 用 16B bodyKey，
//!   ChaCha20-Poly1305 用 `GenerateChacha20Poly1305Key(bodyKey)`（MD5 链扩展 32B）。
//! - `proxy/vmess/encoding/server.go` `DecodeRequestBody` / `EncodeResponseBody`：
//!   服务端同构；**认证长度段**的密钥与 nonce 基值固定取**请求方向**的
//!   `requestBodyKey` / `requestBodyIV`（响应方向也一样——参考复用了请求侧的
//!   `s.requestBodyKey`/`s.requestBodyIV`，见 `server.go` 的 `EncodeResponseBody`），
//!   而载荷 AEAD 用本方向 bodyKey（响应方向 = `SHA256(requestBodyKey)[:16]`）。
//! - `common/crypto/auth.go` `AuthenticationWriter/Reader`：分帧 =
//!   长度段 + 载荷密文(+明文 padding)；长度段有三种形态（Plain / Shake 掩码 /
//!   AEAD 认证长度段）。
//! - `common/crypto/chunk.go` `AEADChunkSizeParser`：认证长度段的线上形态是
//!   `Seal(BE16(总长 - tag))`（2B 明文 + 16B tag = 18B）。
//! - `proxy/vmess/encoding/auth.go` `GenerateChacha20Poly1305Key`：
//!   `MD5(b) || MD5(MD5(b))` 扩展成 32B。
//!
//! **头部 AEAD 不分派**：参考 `proxy/vmess/aead/encrypt.go` 的
//! `SealVMessAEADHeader` / `OpenVMessAEADHeader` 两侧都写死 `crypto.NewAesGcm`，
//! 安全档只作用于**数据段**。本模块因此只管数据段，头部仍恒为 AES-128-GCM
//! （`src/aead.rs` 不需要按档分派；这一点与任务书的初始假设不同，已记入
//! `docs/vmess-status.md` 的偏离清单）。
//!
//! fail-closed：未知/哨兵安全档（UNKNOWN=0、AUTO=2、ZERO=6）与非枚举值在本层
//! 一律 [`Error::Unsupported`]，绝不退化成明文或 AES。
//!
//! 拆分：本文件只放**档位模型**（[`BodySuite`] / [`SizeMode`] 与选项解析）；
//! AEAD 上下文在 [`cipher`]，一帧的组装拆解在 [`frame`]。

mod cipher;
mod frame;
mod stream;

pub use cipher::BodyCipher;
pub use frame::BodyFrame;
pub use stream::{ChunkStreamFrame, CHUNK_STREAM_SLICE};

use crate::consts::{SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE};
use crate::{Error, Result};

/// AEAD tag 长度（AES-128-GCM 与 ChaCha20-Poly1305 同为 16 字节）。
pub const TAG_LEN: usize = 16;

/// 认证长度段的长度段密钥派生路径（参考 `KDF16(bodyKey, "auth_len")`）。
pub const KDF_PATH_AUTH_LEN: &[u8] = b"auth_len";

/// 单个帧载荷的硬上限（含 padding；线上长度段是 u16）。
pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;

/// 参考的缓冲区尺寸 `buf.Size`（`common/buf/buffer.go`）：单帧载荷上限的基准。
pub const REF_BUF_SIZE: usize = 8192;

/// 参考的 padding 长度上限 `ShakeSizeParser.MaxPaddingLen()`。
pub const MAX_PADDING_LEN: usize = 64;

/// 数据段 AEAD 套件（安全档 → 具体实现）。
///
/// 对齐参考 `proxy/vmess/encoding/client.go` 的 `switch request.Security`：
/// `NONE` 无 AEAD、`AES128_GCM` 用 16B 密钥、`CHACHA20_POLY1305` 用 MD5 链
/// 扩展出的 32B 密钥；其余档位参考报 `invalid option: Security`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySuite {
    /// 无 AEAD（明文载荷 + chunk 掩码，参考 `SecurityType_NONE`）。
    None,
    /// AES-128-GCM（16B 密钥）。
    Aes128Gcm,
    /// ChaCha20-Poly1305（32B 密钥 = `MD5(b) || MD5(MD5(b))`）。
    ChaCha20Poly1305,
}

impl BodySuite {
    /// 由线上安全档字节解析；未知/哨兵档位 fail-closed。
    pub fn from_security_byte(security: u8) -> Result<Self> {
        match security {
            SECURITY_NONE => Ok(Self::None),
            SECURITY_AES_128_GCM => Ok(Self::Aes128Gcm),
            SECURITY_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            _ => Err(Error::Unsupported {
                feature: "unknown security type for body segment",
            }),
        }
    }

    /// 套件的安全档字节（`SecurityType` 枚举值）。
    #[must_use]
    pub const fn security_byte(self) -> u8 {
        match self {
            Self::None => SECURITY_NONE,
            Self::Aes128Gcm => SECURITY_AES_128_GCM,
            Self::ChaCha20Poly1305 => SECURITY_CHACHA20_POLY1305,
        }
    }

    /// 每帧密文开销（tag 长度；`None` 为 0）。
    #[must_use]
    pub const fn overhead(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => TAG_LEN,
        }
    }

    /// 是否带 AEAD。
    #[must_use]
    pub const fn is_aead(self) -> bool {
        !matches!(self, Self::None)
    }

    /// 按套件派生 AEAD 密钥：AES 直接用 base；ChaCha 走 MD5 链扩展。
    #[must_use]
    pub fn derive_key(self, base: &[u8]) -> Vec<u8> {
        match self {
            Self::None => Vec::new(),
            Self::Aes128Gcm => base.to_vec(),
            Self::ChaCha20Poly1305 => crate::aead_chacha::expand_key(base).to_vec(),
        }
    }
}

/// 长度段的线上形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeMode {
    /// 裸 BE16 长度（参考 `PlainChunkSizeParser`）。
    Plain,
    /// SHA3-Shake128 掩码后的 BE16 长度（参考 `ShakeSizeParser`）。
    Masked,
    /// AEAD 认证长度段（参考 `AEADChunkSizeParser`）：线上 18 字节 = 密文 2B+tag。
    Authenticated,
}

impl SizeMode {
    /// 长度段在线上的字节数。
    #[must_use]
    pub const fn wire_len(self) -> usize {
        match self {
            Self::Plain | Self::Masked => 2,
            Self::Authenticated => 2 + TAG_LEN,
        }
    }
}

/// 从请求 option 字节推出长度段形态（参考 `EncodeRequestBody` 的选项组合）。
///
/// 优先级对齐参考：`AuthenticatedLength` 会**替换**掉 Shake 解析器，此时掩码流
/// 只用于 `GlobalPadding`。`GlobalPadding` 在没有 `ChunkMasking` 时参考直接报
/// `invalid option: RequestOptionGlobalPadding`，因此这里返回错误。
pub fn size_mode_for_options(option: u8, suite: BodySuite) -> Result<SizeMode> {
    const OPT_CHUNK_MASKING: u8 = 0x04;
    const OPT_GLOBAL_PADDING: u8 = 0x08;
    const OPT_AUTH_LEN: u8 = 0x10;
    if option & OPT_GLOBAL_PADDING != 0 && option & OPT_CHUNK_MASKING == 0 {
        return Err(Error::Unsupported {
            feature: "global padding without chunk masking",
        });
    }
    if suite == BodySuite::None {
        // 参考的 NONE 分支不看 AuthenticatedLength（只有 Plain/Masked 两种）。
        return Ok(if option & OPT_CHUNK_MASKING != 0 {
            SizeMode::Masked
        } else {
            SizeMode::Plain
        });
    }
    if option & OPT_AUTH_LEN != 0 {
        return Ok(SizeMode::Authenticated);
    }
    Ok(if option & OPT_CHUNK_MASKING != 0 {
        SizeMode::Masked
    } else {
        SizeMode::Plain
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"request-body-key";

    #[test]
    fn suite_bytes_and_overheads_match_reference_enum() {
        assert_eq!(BodySuite::None.security_byte(), 5);
        assert_eq!(BodySuite::Aes128Gcm.security_byte(), 3);
        assert_eq!(BodySuite::ChaCha20Poly1305.security_byte(), 4);
        assert_eq!(BodySuite::None.overhead(), 0);
        assert_eq!(BodySuite::Aes128Gcm.overhead(), 16);
        assert_eq!(BodySuite::ChaCha20Poly1305.overhead(), 16);
        assert!(!BodySuite::None.is_aead());
        assert!(BodySuite::Aes128Gcm.is_aead());
    }

    #[test]
    fn chacha_key_is_md5_chain_and_differs_from_aes() {
        let aes = BodySuite::Aes128Gcm.derive_key(&KEY);
        let chacha = BodySuite::ChaCha20Poly1305.derive_key(&KEY);
        assert_eq!(aes.len(), 16);
        assert_eq!(chacha.len(), 32);
        let first = crate::chunkframe::md5_digest(&KEY);
        let second = crate::chunkframe::md5_digest(&first);
        assert_eq!(&chacha[..16], &first[..]);
        assert_eq!(&chacha[16..], &second[..]);
        assert_ne!(&chacha[..16], &aes[..], "ChaCha 档不得复用 AES 密钥");
    }

    #[test]
    fn size_mode_precedence_matches_reference() {
        // 无掩码无 padding → 裸 BE16。
        assert_eq!(
            size_mode_for_options(0x00, BodySuite::Aes128Gcm).expect("可解析"),
            SizeMode::Plain
        );
        // 只有掩码 → Shake 掩码长度段。
        assert_eq!(
            size_mode_for_options(0x04, BodySuite::Aes128Gcm).expect("可解析"),
            SizeMode::Masked
        );
        // 认证长度段优先于掩码（参考用 AEADSizeParser 替换 ShakeSizeParser）。
        assert_eq!(
            size_mode_for_options(0x14, BodySuite::Aes128Gcm).expect("可解析"),
            SizeMode::Authenticated
        );
        // NONE 档不看认证长度段。
        assert_eq!(
            size_mode_for_options(0x10, BodySuite::None).expect("可解析"),
            SizeMode::Plain
        );
        // padding 没有掩码：参考直接报 invalid option。
        assert!(matches!(
            size_mode_for_options(0x08, BodySuite::Aes128Gcm),
            Err(Error::Unsupported { .. })
        ));
    }
}
