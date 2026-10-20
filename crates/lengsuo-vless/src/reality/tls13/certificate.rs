//! REALITY 服务端证书伪造：自签 Ed25519 X.509 证书。
//!
//! 参考 `github.com/xtls/reality` 的 `handshake_server_tls13.go:80-86`：
//!
//! ```go
//! certificate := x509.Certificate{SerialNumber: &big.Int{}}
//! _, ed25519Priv, _ = ed25519.GenerateKey(rand.Reader)
//! signedCert, _ = x509.CreateCertificate(rand.Reader, &certificate, &certificate,
//!     ed25519.PublicKey(ed25519Priv[32:]), ed25519Priv)
//! ```
//!
//! 随后 `handshake_server_tls13.go:149-151` 把证书末尾 64 字节（`Signature`
//! 字段）就地改写成 `HMAC-SHA512(auth_key, ed25519_pub)`，客户端据此确认对端
//! 持有同一 `auth_key`。
//!
//! # 本模块的构造
//!
//! 由于本卡不得改 `Cargo.toml`（无法引入 `x509` / `der` 之类的 crate），
//! 这里**按字节**构造与 Go `x509.CreateCertificate` 完全一致的 DER 结构：
//!
//! ```text
//! SEQUENCE (0x30, len 0xAF = 175)
//!   SEQUENCE (0x30, len 0x63 = 99)          -- TBSCertificate
//!     [0]  (0xA0, len 3) 02 01 02          -- version v3
//!     serialNumber (0x02, len 1) 00
//!     signature (0x30, len 5) 06 03 2B 65 70   -- Ed25519 OID 1.3.101.112
//!     issuer  (0x30, len 0)
//!     validity (0x30, len 34)
//!       notBefore (0x18, len 15) "00010101000000Z"
//!       notAfter  (0x18, len 15) "00010101000000Z"
//!     subject (0x30, len 0)
//!     subjectPublicKeyInfo (0x30, len 42)
//!       algorithm (0x30, len 5) 06 03 2B 65 70
//!       subjectPublicKey (0x03, len 33) 00 04 || ed25519_pub(32)
//!   signatureAlgorithm (0x30, len 5) 06 03 2B 65 70
//!   signatureValue (0x03, len 65) 00 || ed25519_sig(64)
//! ```
//!
//! 全部字段长度固定，故字节序列完全确定；只有 Ed25519 公钥与签名随每次
//! 握手变化。本模块用**固定结构 + 变长公钥/签名**的方式拼装，与上面的
//! 逐字段转写等价（`tests` 里用 Go 生成的 DER 做等价性断言）。

use super::ed25519::SigningKey;

/// 自签 Ed25519 证书的 Ed25519 OID（1.3.101.112）DER 编码。
const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
/// `UTCTime "00010101000000Z"`（15 字节内容）。
const UTCTIME: [u8; 15] = *b"00010101000000Z";
/// Ed25519 `SubjectPublicKeyInfo` 的固定前 12 字节
/// （`SEQUENCE{ SEQUENCE{ OID }, BIT STRING{ 00 } }`）。
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// 自签 Ed25519 证书。
#[derive(Clone)]
pub struct SelfSignedCertificate {
    /// 完整 DER。
    pub der: Vec<u8>,
    /// 签名密钥（服务端持有，用于签 `CertificateVerify`）。
    pub signing_key: SigningKey,
}

impl core::fmt::Debug for SelfSignedCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SelfSignedCertificate")
            .field("der_len", &self.der.len())
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl SelfSignedCertificate {
    /// 用给定的 Ed25519 种子生成一张自签证书。
    ///
    /// `seed` 是 Ed25519 的 32 字节种子（参考用 `ed25519.GenerateKey` 现场生成；
    /// 本仓允许调用方注入，便于测试复现）。
    pub fn generate(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_seed(&seed);
        let public = signing_key.public_key();
        // 自签：签名对象是 TBSCertificate 的 DER。
        let tbs = tbs_certificate(&public);
        let signature = signing_key.sign(&tbs);
        let der = assemble(&tbs, &signature);
        Self { der, signing_key }
    }

    /// 证书里的 Ed25519 公钥。
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.public_key()
    }
}

/// TBSCertificate 的 DER 字节（含它自己的 `SEQUENCE` 头）。
///
/// 外层 `SEQUENCE` 的长度是 99（< 128），用短形式 `0x63`；
/// 而整张证书的外层 `SEQUENCE` 长度是 175（≥ 128），Go 的 `encoding/asn1`
/// 用长形式 `0x81 0xaf`。
fn tbs_certificate(public: &[u8; 32]) -> Vec<u8> {
    let mut tbs = Vec::with_capacity(101);
    tbs.push(0x30);
    tbs.push(0x63); // 99 字节内容
    let mut body = Vec::with_capacity(99);
    // [0] version v3
    body.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    // serialNumber = 0
    body.extend_from_slice(&[0x02, 0x01, 0x00]);
    // signature = Ed25519 OID
    body.extend_from_slice(&[0x30, 0x05]);
    body.extend_from_slice(&OID_ED25519);
    // issuer = 空
    body.extend_from_slice(&[0x30, 0x00]);
    // validity
    body.extend_from_slice(&[0x30, 0x22]);
    body.extend_from_slice(&[0x18, 0x0f]);
    body.extend_from_slice(&UTCTIME);
    body.extend_from_slice(&[0x18, 0x0f]);
    body.extend_from_slice(&UTCTIME);
    // subject = 空
    body.extend_from_slice(&[0x30, 0x00]);
    // subjectPublicKeyInfo
    body.extend_from_slice(&[0x30, 0x2a]);
    body.extend_from_slice(&[0x30, 0x05]);
    body.extend_from_slice(&OID_ED25519);
    body.extend_from_slice(&[0x03, 0x21, 0x00]);
    body.extend_from_slice(public);
    debug_assert_eq!(body.len(), 99);
    tbs.extend_from_slice(&body);
    tbs
}

/// 把 TBSCertificate 与签名组装成完整证书 DER。
fn assemble(tbs: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(178);
    // SEQUENCE { TBSCertificate, signatureAlgorithm, signatureValue }
    // 内容共 175 字节（≥ 128），DER 必须用长形式长度：`0x81 0xaf`。
    out.push(0x30);
    out.push(0x81);
    out.push(0xaf);
    out.extend_from_slice(tbs);
    // signatureAlgorithm
    out.extend_from_slice(&[0x30, 0x05]);
    out.extend_from_slice(&OID_ED25519);
    // signatureValue: BIT STRING, 64 字节签名 + 1 字节未用位
    // （长度 65 = 0x41）。
    out.extend_from_slice(&[0x03, 0x41, 0x00]);
    out.extend_from_slice(signature);
    out
}

/// 从证书 DER 里取出 Ed25519 公钥（客户端侧的等价解析，供测试用）。
///
/// 对齐客户端 `parse_reality_certificate` 的 SPKI 前缀定位法。
pub fn public_key_from_der(der: &[u8]) -> Option<[u8; 32]> {
    let position = der
        .windows(SPKI_PREFIX.len())
        .position(|window| window == SPKI_PREFIX)?;
    let key_start = position + SPKI_PREFIX.len();
    if der.len() < key_start + 32 {
        return None;
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&der[key_start..key_start + 32]);
    Some(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go 标准库 `x509.CreateCertificate` 对空 subject/issuer、serial 0、
    /// `UTCTime 00010101000000Z` 的 Ed25519 自签证书：
    ///
    /// ```text
    /// 3081af3063a003020102020100300506032b657030003022180f303030313031303130
    /// 30303030305a180f30303031303130313030303030305a3000302a300506032b6570
    /// 032100 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc86641255
    /// 31b8 300506032b6570034100 7d625f1df8f037ab6b768bb93a6c2315258027ffc
    /// 52788fe10cb69cfe9ba106a48c6f5963559523d5a175e1b98ff71cd450e76c9145f
    /// 7606093a792c16f521
    /// ```
    ///
    /// 种子是 `0x00..0x1f`（Go 侧用 `ed25519.NewKeyFromSeed`）。
    const GO_REFERENCE: &str = "3081af3063a003020102020100300506032b657030003022180f30303031303130313030303030305a180f30303031303130313030303030305a3000302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8300506032b65700341007d625f1df8f037ab6b768bb93a6c2315258027ffc52788fe10cb69cfe9ba106a48c6f5963559523d5a175e1b98ff71cd450e76c9145f7606093a792c16f52100";

    fn hex_decode(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0;
        while index < bytes.len() {
            let high = (bytes[index] as char).to_digit(16).expect("合法十六进制") as u8;
            let low = (bytes[index + 1] as char)
                .to_digit(16)
                .expect("合法十六进制") as u8;
            out.push(high << 4 | low);
            index += 2;
        }
        out
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 本仓构造的证书必须与 Go `x509.CreateCertificate` **逐字节一致**。
    ///
    /// 这是「服务端伪造的证书能被真实 Xray 客户端接受」的前提：
    /// Xray 客户端用 `crypto/x509` 解析证书并取 `PublicKey` 与 `Signature`。
    #[test]
    fn der_is_byte_identical_to_go_x509_create_certificate() {
        let mut seed = [0u8; 32];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let certificate = SelfSignedCertificate::generate(seed);
        assert_eq!(certificate.der.len(), 178);
        assert_eq!(
            hex_encode(&certificate.der),
            GO_REFERENCE,
            "证书 DER 必须与 Go x509.CreateCertificate 逐字节一致"
        );
        // 公钥可被解析回来。
        assert_eq!(
            public_key_from_der(&certificate.der),
            Some(certificate.public_key())
        );
    }

    /// DER 的固定前缀（不含公钥与签名）与 Go 一致。
    #[test]
    fn der_prefix_matches_go() {
        let certificate = SelfSignedCertificate::generate([0x42u8; 32]);
        let reference = hex_decode(GO_REFERENCE);
        assert_eq!(&certificate.der[..64], &reference[..64]);
        assert_eq!(certificate.der.len(), reference.len());
    }

    #[test]
    fn signature_is_ed25519_over_tbs() {
        let certificate = SelfSignedCertificate::generate([0x11u8; 32]);
        // 末 64 字节是 Ed25519 签名。
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&certificate.der[certificate.der.len() - 64..]);
        let tbs = tbs_certificate(&certificate.public_key());
        assert!(
            super::super::ed25519::verify(&certificate.public_key(), &tbs, &signature).is_ok(),
            "证书签名必须能被自身的 Ed25519 公钥验证"
        );
    }

    #[test]
    fn different_seeds_give_different_certificates() {
        let a = SelfSignedCertificate::generate([0x01u8; 32]);
        let b = SelfSignedCertificate::generate([0x02u8; 32]);
        assert_ne!(a.der, b.der);
        assert_ne!(a.public_key(), b.public_key());
    }
}
