//! REALITY 客户端：TLS 1.3 握手 + 认证载荷封装。
//!
//! 参考实现：`transport/internet/reality/reality.go` 的 `UClient`
//! （固定基线 Xray 26.3.27 / `d2758a02`），以及
//! `github.com/xtls/reality` 的 `handshake_client_tls13.go`（TLS 1.3 客户端飞行）。
//!
//! # 与参考的对应关系
//!
//! | 参考 | 本模块 |
//! |---|---|
//! | `hello.SessionId = make([]byte, 32)` + `copy(hello.Raw[39:], hello.SessionId)` | [`build_reality_client_hello`] 先把 SessionId 区清零 |
//! | `hello.SessionId[0..3] = 版本三元组`、`[4:8] = Unix 秒`、`[8:] = shortId` | [`super::auth::build_auth_plaintext`] |
//! | `ecdhe.ECDH(publicKey)` + `hkdf.New(sha256.New, AuthKey, random[:20], "REALITY")` | [`super::auth::derive_auth_key`] |
//! | `aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)` | [`super::auth::seal_auth_payload`] |
//! | `copy(hello.Raw[39:], hello.SessionId)` | [`build_reality_client_hello`] 的最后一步 |
//!
//! # 认证标签校验
//!
//! 参考 `UConn.VerifyPeerCertificate`（`reality.go:76-114`）用
//! `HMAC-SHA512(auth_key, ed25519_pubkey)` 与证书的 `Signature` 字段比对。
//! 本模块在 [`RealityClient::verify_certificate`] 里做同样的校验：
//! 证书公钥必须是 Ed25519，且签名必须匹配，否则握手失败（fail-closed）。
//!
//! # 与参考的**协议等价**差异（非偏离项，详见报告）
//!
//! 1. 参考 `reality.go:174` 的 `aead.Seal(hello.SessionId[:0], ...)` 把 48 字节写进
//!    只有 32 字节容量的切片，Go 会 panic；线上真正生效的是
//!    `copy(hello.Raw[39:], hello.SessionId)` 之后的 32 字节。本模块按**协议意图**
//!    实现（16 字节明文 → 32 字节密文填满 SessionId），与服务端 `aead.Open`
//!    的布局一致。
//! 2. 本模块**不实现 uTLS 浏览器指纹**（参考用 utls 的 `HelloChrome_*` 构造
//!    ClientHello）。本仓构造的是规范 TLS 1.3 ClientHello，字段布局与 Go 标准库
//!    的 `HelloGolang` 一致（参考的 REALITY 服务端也接受它）。指纹伪装见报告
//!    「uTLS 指纹状态」。

use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

use super::auth::{
    build_auth_plaintext, derive_auth_key, seal_auth_payload, AuthError, SESSION_ID_LEN,
    SESSION_ID_OFFSET,
};
use super::tls13::handshake::HandshakeError;
use super::tls13::messages::{build_client_hello, ClientHelloParams};
use super::tls13::record::RecordError;
use super::x25519::{x25519, x25519_base};
use super::ClientVersion;

mod cert;
mod state;

pub use cert::{leaf_certificate, parse_reality_certificate, server_signed_message};
pub use state::{ClientSessionKeys, RealityClient};

/// REALITY 客户端握手失败。全部 fail-closed。
#[derive(Debug, Error)]
pub enum ClientError {
    /// 认证载荷相关错误。
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// TLS 握手错误。
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// 记录层错误。
    #[error(transparent)]
    Record(#[from] RecordError),
    /// 服务端证书不是 Ed25519 的 REALITY 证书。
    #[error("REALITY client: peer certificate is not an Ed25519 REALITY certificate")]
    NotRealityCertificate,
    /// 服务端证书的 REALITY 认证标签不匹配（可能被中间人替换）。
    #[error("REALITY client: peer certificate authentication tag mismatch")]
    CertificateTagMismatch,
    /// 服务端协商出的套件/版本/签名算法不受支持。
    #[error("REALITY client: unsupported server negotiation")]
    UnsupportedNegotiation,
    /// 握手状态机被用错了顺序调用。
    #[error("REALITY client: unexpected handshake step")]
    UnexpectedStep,
}

impl ClientError {
    /// 把客户端错误降级成记录层的 [`super::tls13::io::IoError`]。
    ///
    /// 握手驱动（[`super::session::client_handshake`]）在记录层里跑，
    /// 需要把客户端状态机的错误统一成 [`IoError`] 才能用 `?` 传播。
    /// 错误**类型**信息保留在 `Handshake`/`Record` 变体里，不丢语义。
    pub(crate) fn into_io_error(self) -> super::tls13::io::IoError {
        match self {
            Self::Auth(error) => super::tls13::io::IoError::Handshake(
                super::tls13::handshake::HandshakeError::Io(error.to_string()),
            ),
            Self::Handshake(error) => super::tls13::io::IoError::Handshake(error),
            Self::Record(error) => super::tls13::io::IoError::Record(error),
            other => super::tls13::io::IoError::Handshake(
                super::tls13::handshake::HandshakeError::Io(other.to_string()),
            ),
        }
    }
}

/// 构造好的 ClientHello（含 REALITY 认证载荷）。
///
/// `raw` 是**完整**的 ClientHello 握手消息（含 4 字节消息头），
/// 其中 `raw[39..71]` 是 REALITY 认证密文区。
#[derive(Clone)]
pub struct BuiltClientHello {
    /// 完整的 ClientHello 字节（含消息头）。
    pub raw: Vec<u8>,
    /// 本次握手用的 `client_random`。
    pub random: [u8; 32],
    /// 本次握手的 X25519 临时公钥。
    pub ephemeral_public: [u8; 32],
    /// 派生出的 REALITY 认证密钥（32 字节）。
    pub auth_key: [u8; 32],
    /// 本次握手的 X25519 临时私钥种子。
    ///
    /// 客户端在收到 ServerHello 后要用它与服务端的 key_share 做 ECDHE，
    /// 因此**不能**在构造阶段清零；由 [`BuiltClientHello::take_seed`] 交给
    /// [`RealityClient`]，并在其 `Drop` 时清零。
    seed: Option<[u8; 32]>,
}

impl core::fmt::Debug for BuiltClientHello {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BuiltClientHello")
            .field("raw_len", &self.raw.len())
            .field("random", &"<redacted>")
            .field("ephemeral_public", &"<redacted>")
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

impl Drop for BuiltClientHello {
    fn drop(&mut self) {
        self.auth_key.zeroize();
        if let Some(seed) = self.seed.as_mut() {
            seed.zeroize();
        }
    }
}

impl BuiltClientHello {
    /// 取出本次握手的 X25519 临时私钥种子。
    ///
    /// 只能取一次（第二次返回 `None`）。取出的种子必须交给
    /// [`RealityClient`]（或 [`RealityClient::from_built`]），
    /// 否则客户端无法与服务端完成 ECDHE。
    pub fn take_seed(&mut self) -> Option<[u8; 32]> {
        self.seed.take()
    }
}

/// 构造 REALITY 客户端的 ClientHello。
///
/// 步骤严格对齐参考 `reality.go:138-176`：
///
/// 1. 生成 X25519 临时密钥对，算出与 `server_public` 的 ECDH。
/// 2. 用 `client_random[:20]` + ECDH 派生 `auth_key`。
/// 3. 构造 ClientHello（SessionId 区先清零）。
/// 4. 组装 16 字节认证载荷明文并用 `auth_key` 加密，把 32 字节密文写回
///    `raw[39..71]`。
///
/// `version` 是写进认证载荷的 Xray 版本三元组（参考用 `core.Version_x/y/z`）。
/// `unix_time` 是写进认证载荷的 Unix 秒（参考用 `time.Now().Unix()`）。
pub fn build_reality_client_hello<R: RngCore + CryptoRng>(
    server_public: &[u8; 32],
    server_name: &str,
    short_id: &[u8; 8],
    version: ClientVersion,
    unix_time: u32,
    rng: &mut R,
) -> Result<BuiltClientHello, ClientError> {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let ephemeral_public = x25519_base(&seed);
    let shared = x25519(&seed, server_public).map_err(|_| AuthError::InvalidPublicKey)?;

    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);

    // auth_key = HKDF-SHA256(ikm = ECDH, salt = random[:20], info = "REALITY")
    let auth_key = derive_auth_key(&shared, &random)?;
    let mut shared = shared;
    shared.zeroize();

    let mut raw = build_client_hello(&ClientHelloParams {
        random,
        session_id: [0u8; 32],
        server_name: server_name.to_owned(),
        key_share: ephemeral_public,
    });
    // 参考 `copy(hello.Raw[39:], hello.SessionId)`：先把 SessionId 区清零，
    // 使 AEAD 的 AAD 与参考一致（`auth.rs` 的 `seal_auth_payload` 同样清零）。
    raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);

    let plaintext = build_auth_plaintext(version, unix_time, short_id);
    let sealed = seal_auth_payload(&auth_key, &plaintext, &raw)?;
    raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&sealed);

    Ok(BuiltClientHello {
        raw,
        random,
        ephemeral_public,
        auth_key,
        seed: Some(seed),
    })
}
