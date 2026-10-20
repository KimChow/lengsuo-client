//! TLS 1.3 握手消息与转录哈希（客户端侧与 REALITY 服务端侧共用）。
//!
//! 参考实现对应 `xtls/reality` 的
//! `handshake_server_tls13.go`（服务端飞行）与
//! `handshake_client_tls13.go`（客户端飞行）。
//!
//! # 为什么自己实现
//!
//! REALITY 的认证载荷密钥依赖 **TLS 握手的 X25519 临时私钥**
//! （参考 `reality.go:156-169`），而 rustls / tokio-rustls 不暴露该私钥，
//! 故只能自建 TLS 1.3 栈。本模块只覆盖 REALITY 用得到的那部分。
//!
//! # 范围（与参考的等价边界）
//!
//! * 套件固定 `TLS_AES_128_GCM_SHA256`（参考 `cipherSuiteTLS13ByID`）。
//! * 密钥组固定 `x25519`（参考 `X25519`）。
//! * 签名算法固定 `ed25519`（参考 `hs.sigAlg = Ed25519`）。
//! * **不实现**：HelloRetryRequest、PSK / 0-RTT、ECH、ML-KEM 混合组、
//!   证书压缩、会话票据。

use thiserror::Error;

use super::messages::{
    handshake_type, put_handshake, CIPHER_SUITE_AES_128_GCM_SHA256, GROUP_X25519, LEGACY_VERSION,
    VERSION_TLS13,
};
use super::schedule::HASH_LEN;

/// 握手失败。全部 fail-closed。
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// 消息类型不是期望的那一个。
    #[error("TLS handshake: unexpected message {0}")]
    UnexpectedMessage(u8),
    /// 消息结构畸形。
    #[error("TLS handshake: malformed message")]
    MalformedMessage,
    /// 收到 `alert` 记录。
    #[error("TLS handshake: peer alert {0}")]
    Alert(u8),
    /// 记录层错误。
    #[error(transparent)]
    Record(#[from] super::record::RecordError),
    /// 密钥协商失败（无 X25519 key_share 等）。
    #[error("TLS handshake: key agreement failed")]
    KeyAgreementFailed,
    /// 服务端没有回 Certificate。
    #[error("TLS handshake: missing certificate")]
    MissingCertificate,
    /// 服务端没有回 CertificateVerify。
    #[error("TLS handshake: missing certificate verify")]
    MissingCertificateVerify,
    /// `Finished` 的 `verify_data` 不匹配。
    #[error("TLS handshake: finished verify data mismatch")]
    FinishedMismatch,
    /// `CertificateVerify` 的签名校验失败。
    #[error("TLS handshake: certificate verify signature mismatch")]
    SignatureMismatch,
    /// 协商到的套件/版本/组不是本实现支持的。
    #[error("TLS handshake: unsupported negotiation")]
    UnsupportedNegotiation,
    /// 底层 I/O 失败。
    #[error("TLS handshake: io error: {0}")]
    Io(String),
    /// 握手状态机被用错了顺序调用。
    #[error("TLS handshake: unexpected handshake step")]
    UnexpectedStep,
}

impl From<super::messages::MessageError> for HandshakeError {
    fn from(e: super::messages::MessageError) -> Self {
        match e {
            super::messages::MessageError::UnexpectedType(t) => Self::UnexpectedMessage(t),
            _ => Self::MalformedMessage,
        }
    }
}

/// 解析出的一条 `Certificate` 消息的叶子证书。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCertificate {
    /// 叶子证书的 DER 字节。
    pub der: Vec<u8>,
}

/// 解析 `Certificate` 握手消息（RFC 8446 §4.4.2）。
///
/// 布局：`certificate_request_context(1) + 证书列表(uint24 长度前缀)`，
/// 列表里每项是 `uint24 长度前缀的 DER` + `uint16 长度前缀的扩展`。
/// 对齐参考 `handshake_messages.go:1455` 的 `certificateMsgTLS13.marshal`。
pub fn parse_certificate(body: &[u8]) -> Result<PeerCertificate, HandshakeError> {
    if body.is_empty() {
        return Err(HandshakeError::MalformedMessage);
    }
    // certificate_request_context：REALITY 服务端恒为空（参考写 `b.AddUint8(0)`）。
    let rest = &body[1..];
    if rest.len() < 3 {
        return Err(HandshakeError::MalformedMessage);
    }
    let list_len = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]) as usize;
    let list = rest
        .get(3..3 + list_len)
        .ok_or(HandshakeError::MalformedMessage)?;
    if list.len() < 3 {
        return Err(HandshakeError::MalformedMessage);
    }
    let cert_len = u32::from_be_bytes([0, list[0], list[1], list[2]]) as usize;
    let der = list
        .get(3..3 + cert_len)
        .ok_or(HandshakeError::MalformedMessage)?;
    Ok(PeerCertificate { der: der.to_vec() })
}

/// 构造 `Certificate` 握手消息（服务端用）。
pub fn build_certificate(der: &[u8]) -> Vec<u8> {
    let mut list = Vec::with_capacity(der.len() + 6);
    list.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
    list.extend_from_slice(der);
    list.extend_from_slice(&0u16.to_be_bytes()); // 无扩展

    let mut body = Vec::with_capacity(list.len() + 4);
    body.push(0); // certificate_request_context
    body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    body.extend_from_slice(&list);

    let mut out = Vec::with_capacity(body.len() + 4);
    put_handshake(&mut out, handshake_type::CERTIFICATE, &body);
    out
}

/// 构造 `CertificateVerify` 握手消息（服务端用）。
///
/// 布局：`signature_algorithm(2) + signature(uint16 长度前缀)`，
/// 对齐参考 `handshake_messages.go:1844`。
pub fn build_certificate_verify(signature_algorithm: u16, signature: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(signature.len() + 4);
    body.extend_from_slice(&signature_algorithm.to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    let mut out = Vec::with_capacity(body.len() + 4);
    put_handshake(&mut out, handshake_type::CERTIFICATE_VERIFY, &body);
    out
}

/// 解析 `CertificateVerify` 握手消息（客户端用）。
///
/// 返回 `(签名算法, 签名)`。
pub fn parse_certificate_verify(body: &[u8]) -> Result<(u16, &[u8]), HandshakeError> {
    if body.len() < 4 {
        return Err(HandshakeError::MalformedMessage);
    }
    let algorithm = u16::from_be_bytes([body[0], body[1]]);
    let len = usize::from(u16::from_be_bytes([body[2], body[3]]));
    let signature = body
        .get(4..4 + len)
        .ok_or(HandshakeError::MalformedMessage)?;
    Ok((algorithm, signature))
}

/// 构造 `Finished` 握手消息。
pub fn build_finished(verify_data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(verify_data.len());
    body.extend_from_slice(verify_data);
    let mut out = Vec::with_capacity(body.len() + 4);
    put_handshake(&mut out, handshake_type::FINISHED, &body);
    out
}

/// 构造 `EncryptedExtensions` 握手消息（空扩展列表）。
pub fn build_encrypted_extensions() -> Vec<u8> {
    let mut body = Vec::with_capacity(2);
    body.extend_from_slice(&0u16.to_be_bytes());
    let mut out = Vec::with_capacity(body.len() + 4);
    put_handshake(&mut out, handshake_type::ENCRYPTED_EXTENSIONS, &body);
    out
}

/// 构造 `ServerHello` 握手消息（服务端用）。
///
/// 布局：`legacy_version(2) + random(32) + session_id_echo(1+n) +
/// cipher_suite(2) + compression(1) + 扩展(uint16 长度前缀)`。
/// 扩展含 `supported_versions`（TLS 1.3）与 `key_share`（x25519）。
/// 对齐参考 `handshake_messages.go:746` 的 `serverHelloMsg.marshal`。
pub fn build_server_hello(random: [u8; 32], session_id: &[u8], key_share: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&CIPHER_SUITE_AES_128_GCM_SHA256.to_be_bytes());
    body.push(0); // compression_method = null

    let mut exts = Vec::with_capacity(64);
    // supported_versions
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&VERSION_TLS13.to_be_bytes());
    // key_share
    exts.extend_from_slice(&0x0033u16.to_be_bytes());
    let mut share = Vec::with_capacity(36);
    share.extend_from_slice(&GROUP_X25519.to_be_bytes());
    share.extend_from_slice(&(32u16).to_be_bytes());
    share.extend_from_slice(key_share);
    exts.extend_from_slice(&(share.len() as u16).to_be_bytes());
    exts.extend_from_slice(&share);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut out = Vec::with_capacity(body.len() + 4);
    put_handshake(&mut out, handshake_type::SERVER_HELLO, &body);
    out
}

/// 转录哈希（RFC 8446 §4.4.1）。
///
/// 参考 `hs.transcript` 是一个 `hash.Hash`，按握手消息的**原始字节**顺序
/// 喂入；`originalBytes()` 优先于重新 marshal（`handshake_messages.go:1939`）。
pub struct Transcript {
    hasher: super::super::hash::sha::Sha256,
}

impl core::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transcript").finish()
    }
}

impl Transcript {
    /// 新建空转录。
    pub fn new() -> Self {
        Self {
            hasher: super::super::hash::sha::Sha256::new(),
        }
    }

    /// 追加一条握手消息的原始字节。
    pub fn write(&mut self, raw: &[u8]) {
        self.hasher.update(raw);
    }

    /// 当前转录哈希。
    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.hasher.clone().finalize()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}
