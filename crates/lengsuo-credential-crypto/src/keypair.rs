//! ES256（P-256）密钥对。
//!
//! 契约 §1.2.1 / §2.2：
//! - 算法 **ES256 = ECDSA P-256 + SHA-256**。
//! - **私钥用标准 PKCS#8**（RFC 5958 §2 / RFC 5915 的 `ECPrivateKey`），
//!   **不自定义格式** ⇒ 任何时候都能被标准工具解出来。
//! - **签名用定长 r‖s（64 字节）**：WebAuthn 断言签名是定长，
//!   ASN.1 DER 变长签名会破坏 `r‖s` 布局 ⇒ 用 `ECDSA_P256_SHA256_FIXED_SIGNING`。
//!
//! ⛔ 用 `ring` 不用 `p256`：`p256` 不在本仓依赖树里，引入即为新依赖。
//! `ring` 的许可 = Apache-2.0 + ISC + MIT，可商用闭源。
//!
//! ⚠️ **公钥坐标**：`ring` 的 `public_key().as_ref()` 给**未压缩点**
//! `0x04 || X(32) || Y(32)`（65 字节）⇒ `x = &bytes[1..33]`、`y = &bytes[33..65]`。

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;

/// P-256 公钥坐标长度（X 与 Y 各 32 字节）。
pub const COORD_LEN: usize = 32;

/// 未压缩点长度：`0x04 || X(32) || Y(32)`。
pub const UNCOMPRESSED_POINT_LEN: usize = 1 + 2 * COORD_LEN;

/// ES256 定长签名长度：r(32) || s(32)。
pub const SIGNATURE_LEN: usize = 64;

/// 一个 ES256 密钥对（私钥以标准 PKCS#8 DER 保存）。
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// 标准 PKCS#8 v1 DER 私钥字节。
    pkcs8: Zeroizing<Vec<u8>>,
    /// 未压缩公钥点（65 字节）。
    public_point: [u8; UNCOMPRESSED_POINT_LEN],
}

impl KeyPair {
    /// 生成新的 ES256 密钥对。
    ///
    /// 私钥来自 `ring` 的 `generate_pkcs8` ⇒ 标准 PKCS#8 v1。
    pub fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| Error::KeyGeneration)?;
        Self::from_pkcs8(doc.as_ref())
    }

    /// 从标准 PKCS#8 v1 DER 私钥字节恢复密钥对。
    ///
    /// `ring` 会校验公私钥一致性 ⇒ 不一致的私钥直接被拒。
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
            .map_err(|_| Error::KeyRejected)?;
        let point = pair.public_key().as_ref();
        if point.len() != UNCOMPRESSED_POINT_LEN || point[0] != 0x04 {
            return Err(Error::KeyRejected);
        }
        let mut public_point = [0u8; UNCOMPRESSED_POINT_LEN];
        public_point.copy_from_slice(point);
        Ok(Self {
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
            public_point,
        })
    }

    /// 标准 PKCS#8 v1 DER 私钥字节。
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// 未压缩公钥点（65 字节：`0x04 || X || Y`）。
    pub fn public_point(&self) -> &[u8; UNCOMPRESSED_POINT_LEN] {
        &self.public_point
    }

    /// 公钥 X 坐标（32 字节，大端）。
    pub fn x(&self) -> [u8; COORD_LEN] {
        let mut out = [0u8; COORD_LEN];
        out.copy_from_slice(&self.public_point[1..1 + COORD_LEN]);
        out
    }

    /// 公钥 Y 坐标（32 字节，大端）。
    pub fn y(&self) -> [u8; COORD_LEN] {
        let mut out = [0u8; COORD_LEN];
        out.copy_from_slice(&self.public_point[1 + COORD_LEN..1 + 2 * COORD_LEN]);
        out
    }
}

/// `rpIdHash = SHA-256(rp_id)`。
///
/// `rp_id` 是 ASCII 域名，按 UTF-8 字节参与哈希。
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.finalize().into()
}

/// 对 `message` 做 ES256 签名，产出 **64 字节 r‖s**。
///
/// 用 `ECDSA_P256_SHA256_FIXED_SIGNING` ⇒ 定长布局，**不用 ASN.1 变长**。
pub fn sign(key_pair: &KeyPair, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    let rng = SystemRandom::new();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key_pair.pkcs8_der(), &rng)
            .map_err(|_| Error::KeyRejected)?;
    let sig = pair.sign(&rng, message).map_err(|_| Error::KeyGeneration)?;
    let bytes = sig.as_ref();
    if bytes.len() != SIGNATURE_LEN {
        return Err(Error::InvalidLength {
            expected: SIGNATURE_LEN,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// 校验 ES256 定长签名。
///
/// 用 `ring` 的**验签路径**（`ECDSA_P256_SHA256_FIXED`），
/// 与签名路径是 ring 内部两条不同的代码路径（签名在 `suite_b/ecdsa/signing.rs`，
/// 验签在 `suite_b/ecdsa/verification.rs`）。
///
/// ⚠️ 另有一条**完全独立**的验签路径（OpenSSL 命令行）见 `tests/openssl_verify.rs`。
pub fn verify(
    public_point: &[u8; UNCOMPRESSED_POINT_LEN],
    message: &[u8],
    signature: &[u8],
) -> bool {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_point.as_slice())
        .verify(message, signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_has_standard_pkcs8_and_uncompressed_point() {
        let pair = KeyPair::generate().unwrap();
        // 标准 PKCS#8 v1 的固定前缀：SEQUENCE { INTEGER 0, SEQUENCE { OID ecPublicKey, OID prime256v1 } }
        assert_eq!(pair.pkcs8_der()[0], 0x30);
        assert_eq!(pair.pkcs8_der().len(), 138);
        assert_eq!(pair.public_point()[0], 0x04);
        assert_eq!(pair.public_point().len(), 65);
    }

    #[test]
    fn x_and_y_are_the_point_coordinates() {
        let pair = KeyPair::generate().unwrap();
        assert_eq!(pair.x().len(), 32);
        assert_eq!(pair.y().len(), 32);
        assert_eq!(&pair.public_point()[1..33], pair.x());
        assert_eq!(&pair.public_point()[33..65], pair.y());
    }

    #[test]
    fn pkcs8_roundtrip_preserves_public_key() {
        let pair = KeyPair::generate().unwrap();
        let restored = KeyPair::from_pkcs8(pair.pkcs8_der()).unwrap();
        assert_eq!(restored.public_point(), pair.public_point());
    }

    #[test]
    fn sign_produces_fixed_64_byte_signature_that_verifies() {
        let pair = KeyPair::generate().unwrap();
        let sig = sign(&pair, b"payload").unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify(pair.public_point(), b"payload", &sig));
        assert!(!verify(pair.public_point(), b"payload2", &sig));
    }

    #[test]
    fn rp_id_hash_is_sha256_of_utf8_bytes() {
        let expected = Sha256::digest(b"example.com");
        assert_eq!(rp_id_hash("example.com").as_slice(), expected.as_slice());
    }
}
