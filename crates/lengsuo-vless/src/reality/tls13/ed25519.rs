//! Ed25519 签名（RFC 8032）**内置实现**。
//!
//! # 为什么需要
//!
//! REALITY 服务端在 TLS 1.3 的 `CertificateVerify` 里用 **Ed25519** 签名
//! （参考 `xtls/reality` `handshake_server_tls13.go:160-164` 的
//! `hs.sigAlg = Ed25519`）。要让固定参考 Xray 的 REALITY **客户端**连上本仓
//! 的 REALITY 服务端（第 2 层），本仓必须能产出 Ed25519 签名。
//!
//! 本 crate 依赖里没有 `ed25519-dalek`（且本卡不得改 `Cargo.toml`），
//! 故按 RFC 8032 §5.1 转写。**这是既定偏离**：主理人开基建卡引入
//! `ed25519-dalek` 后本文件可整体删除。
//!
//! # 复用
//!
//! 域运算复用 [`crate::reality::x25519::field`] 的 `GF(2^255-19)` 实现
//! （与 Ed25519 的底层域相同）；标量运算用 4×64 位 limbs，模 `L` 约减用
//! 二进制长除法（512 次移位-比较-减法），正确性由 RFC 8032 §7.1 的
//! 三组测试向量自证。
//!
//! # 文件拆分
//!
//! | 文件 | 内容 |
//! |------|------|
//! | `ed25519.rs` | 公开 API（[`SigningKey`] / [`verify`]）、错误类型 |
//! | `ed25519/curve.rs` | Edwards 曲线点运算与模 `L` 标量算术 |
//! | `ed25519_tests.rs` | RFC 8032 §7.1 测试向量 |

use thiserror::Error;

use crate::reality::hash::sha::Sha512;

use self::curve::{limbs_from_le, scalar_from_sha512, Point, Scalar};

/// Ed25519 公钥长度。
pub const PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 签名长度。
pub const SIGNATURE_LEN: usize = 64;
/// Ed25519 私钥（种子）长度。
pub const SEED_LEN: usize = 32;

/// Ed25519 错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Ed25519Error {
    /// 签名长度不对。
    #[error("Ed25519: invalid signature length")]
    InvalidSignature,
    /// 公钥不是合法的曲线点。
    #[error("Ed25519: invalid public key")]
    InvalidPublicKey,
    /// 签名校验不通过。
    #[error("Ed25519: signature verification failed")]
    VerifyFailed,
}

/// Ed25519 密钥对（由 32 字节种子导出）。
#[derive(Clone)]
pub struct SigningKey {
    seed: [u8; SEED_LEN],
    scalar: Scalar,
    prefix: [u8; 32],
    public: [u8; PUBLIC_KEY_LEN],
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public)
            .field("scalar", &"<redacted>")
            .field("prefix", &"<redacted>")
            .finish()
    }
}

impl SigningKey {
    /// 从 32 字节种子派生密钥对。
    ///
    /// 对齐 RFC 8032 §5.1.5：
    /// `h = SHA-512(seed)`，`a = clamp(h[0..32])`，`A = a·B`，
    /// `prefix = h[32..64]`。
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let h = hasher.finalize();
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&h[..32]);
        // clamp：清除第 3 位、置第 2 位、置第 255 位、清除第 256 位。
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let scalar = Scalar::from_limbs(limbs_from_le(&scalar_bytes));
        let public = Point::base().scalar_mul(&scalar.to_bytes()).compress();
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        Self {
            seed: *seed,
            scalar,
            prefix,
            public,
        }
    }

    /// 公钥（32 字节）。
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// 种子（32 字节）。
    pub fn seed(&self) -> [u8; SEED_LEN] {
        self.seed
    }

    /// 对 `message` 签名，返回 64 字节 `R || S`。
    ///
    /// 对齐 RFC 8032 §5.1.6：
    /// `r = SHA-512(prefix || M) mod L`，`R = r·B`，
    /// `k = SHA-512(R || A || M) mod L`，`S = (r + k·a) mod L`。
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let mut hasher = Sha512::new();
        hasher.update(&self.prefix);
        hasher.update(message);
        let r = scalar_from_sha512(&hasher.finalize());
        let r_point = Point::base().scalar_mul(&r.to_bytes()).compress();

        let mut hasher = Sha512::new();
        hasher.update(&r_point);
        hasher.update(&self.public);
        hasher.update(message);
        let k = scalar_from_sha512(&hasher.finalize());

        let s = r.add_mod_l(&k.mul_mod_l(&self.scalar));

        let mut out = [0u8; SIGNATURE_LEN];
        out[..32].copy_from_slice(&r_point);
        out[32..].copy_from_slice(&s.to_bytes());
        out
    }
}

/// 校验 Ed25519 签名。
///
/// 对齐 RFC 8032 §5.1.7 的验证流程：
/// 检查 `[S]B == R + [k]A`。
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), Ed25519Error> {
    let r_bytes: [u8; 32] = signature[..32].try_into().expect("长度固定");
    let s_bytes: [u8; 32] = signature[32..].try_into().expect("长度固定");
    let s = Scalar::from_limbs(limbs_from_le(&s_bytes));
    // S 必须 < L。
    if s.ge_l() {
        return Err(Ed25519Error::VerifyFailed);
    }
    let a_point = Point::decompress(public_key)?;
    let mut hasher = Sha512::new();
    hasher.update(&r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let k = scalar_from_sha512(&hasher.finalize());
    let lhs = Point::base().scalar_mul(&s.to_bytes());
    let rhs = Point::decompress(&r_bytes)?.add(&a_point.scalar_mul(&k.to_bytes()));
    if lhs.compress() == rhs.compress() {
        Ok(())
    } else {
        Err(Ed25519Error::VerifyFailed)
    }
}

mod curve;

#[cfg(test)]
#[path = "ed25519_tests.rs"]
mod tests;
