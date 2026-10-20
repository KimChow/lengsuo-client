//! REALITY 服务端证书的解析与 `CertificateVerify` 被签消息构造。
//!
//! 从 [`super`] 拆出以符合 400 行软目标；公开 API 不变。
//!
//! 参考实现：`github.com/xtls/reality` 的 `handshake_server_tls13.go:145-160`
//! （自签 Ed25519 证书 + `HMAC-SHA512` 写进证书末尾）与 `auth.go:82`
//! （`signedMessage`）。

use super::super::tls13::handshake::{parse_certificate, HandshakeError};
use super::ClientError;

/// 从 REALITY 服务端证书里取出 `(Ed25519 公钥, 证书签名字段)`。
///
/// 参考的 REALITY 服务端用一张**自签 Ed25519 证书**：
///
/// * `x509.CreateCertificate` 用空 subject/issuer、serial 0、
///   `UTCTime 00010101000000Z` 生成 178 字节 DER；
/// * 证书的 `Signature`（`BIT STRING`，64 字节）被就地改写成
///   `HMAC-SHA512(auth_key, ed25519_pub)`（参考
///   `handshake_server_tls13.go:149-151`：`h.Sum(cert[:len(cert)-64])`）。
///
/// 因此客户端只需要解析 DER，取出 `SubjectPublicKeyInfo` 里的 Ed25519 公钥
/// （32 字节）与末尾 64 字节的签名字段。
pub fn parse_reality_certificate(der: &[u8]) -> Result<([u8; 32], [u8; 64]), ClientError> {
    // Ed25519 的 SPKI 前缀（RFC 8410 §3）：
    // `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 00 04 || key } }`
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let position = der
        .windows(SPKI_PREFIX.len())
        .position(|window| window == SPKI_PREFIX)
        .ok_or(ClientError::NotRealityCertificate)?;
    let key_start = position + SPKI_PREFIX.len();
    if der.len() < key_start + 32 + 64 {
        return Err(ClientError::NotRealityCertificate);
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&der[key_start..key_start + 32]);
    // 证书签名（`BIT STRING` 内容）在 DER 末尾 64 字节。
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&der[der.len() - 64..]);
    Ok((public, signature))
}

/// TLS 1.3 `CertificateVerify` 的被签消息（RFC 8446 §4.4.3）。
///
/// `64 × 0x20` 填充 + `"TLS 1.3, server CertificateVerify\0"` + 转录哈希。
/// 对齐参考 `auth.go:82` 的 `signedMessage`。
pub fn server_signed_message(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 33 + 32);
    out.extend_from_slice(&[0x20u8; 64]);
    out.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    out.extend_from_slice(transcript_hash);
    out
}

/// 解析服务端 `Certificate` 消息，取出叶子证书 DER。
pub fn leaf_certificate(body: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    parse_certificate(body).map(|c| c.der)
}
