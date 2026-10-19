//! REALITY 服务端证书认证标签的构造与校验。
//!
//! 从 [`super`] 拆出以符合 400 行软目标。参考
//! `xtls/reality` `handshake_server_tls13.go:149-151`（生成）与
//! Xray `reality.go:76-114` 的 `UConn.VerifyPeerCertificate`（校验）。

use subtle::ConstantTimeEq;

use super::super::hash::hmac_sha512;
use super::AuthError;

/// 计算 `HMAC-SHA512(key = auth_key, msg = ed25519_pubkey)`。
///
/// 对齐参考 `handshake_server_tls13.go:149-151`：
/// `h := hmac.New(sha512.New, c.AuthKey); h.Write(ed25519Priv[32:])`，
/// 其中 `ed25519Priv[32:]` 即 Ed25519 公钥。64 字节输出填进证书签名字段。
pub fn cert_auth_tag(auth_key: &[u8; 32], ed25519_public: &[u8; 32]) -> [u8; 64] {
    hmac_sha512(auth_key, ed25519_public)
}

/// 校验对端证书携带的 REALITY 认证标签。
///
/// 对齐参考 `UConn.VerifyPeerCertificate`（`reality.go:76-114`）的 REALITY
/// 分支：只有「公钥是 32 字节 Ed25519」且「签名 == HMAC-SHA512(auth_key, pubkey)」
/// 才算通过。本卡不实现「回退到系统证书链」的部分（见报告「未覆盖」）。
///
/// 比较用 [`subtle::ConstantTimeEq`]（参考用 `bytes.Equal`，时序属性更弱；
/// 这里取更严格的实现，属安全加强而非协议偏离）。
pub fn verify_cert_tag(
    auth_key: &[u8; 32],
    peer_public: &[u8],
    peer_signature: &[u8],
) -> Result<(), AuthError> {
    let pubkey: [u8; 32] = peer_public.try_into().map_err(|_| AuthError::NotEd25519)?;
    if peer_signature.len() != 64 {
        return Err(AuthError::CertificateMismatch);
    }
    let expected = cert_auth_tag(auth_key, &pubkey);
    if expected.ct_eq(peer_signature).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(AuthError::CertificateMismatch)
    }
}
