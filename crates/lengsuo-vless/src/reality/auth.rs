//! REALITY 认证载荷构造与校验（X25519 + HKDF-SHA256 + AES-256-GCM）。
//!
//! 参考双方：
//!
//! * 客户端 `transport/internet/reality/reality.go:117-174`（`UClient` 内联块）
//! * 服务端 `github.com/xtls/reality` `tls.go:224-262`（验证）
//! * 证书签名 `xtls/reality` `handshake_server_tls13.go:145-160`
//!
//! # 密钥派生（两端一致）
//!
//! ```text
//! ecdh     = X25519(client_ephemeral_priv, server_pubkey)    // 32B
//! auth_key = HKDF-SHA256(ikm = ecdh, salt = client_random[0..20],
//!                        info = "REALITY", len = 32)
//! ```
//!
//! 参考把 HKDF 结果**写回 `AuthKey` 同一切片**（`reality.go:167-168`），
//! 后续 AEAD 用的就是派生后的 32 字节；服务端 `tls.go:230-236` 同构。
//!
//! # 认证载荷（32 字节明文）
//!
//! 布局见 [`crate::reality`] 模块文档。AEAD 参数：
//!
//! ```text
//! nonce = client_random[20..32]                 (12B)
//! aad   = 整个 ClientHello 原始字节（hello.Raw）
//! 输出   = 32B 密文 || 16B tag = 48B，从 SessionId 起始处就地写回 raw[39..87]
//! ```
//!
//! 注意参考客户端有一处**不可复现的怪癖**（`reality.go:175`）：
//! `aead.Seal(hello.SessionId[:0], ...)` 把 48 字节写进只有 32 字节容量的
//! `hello.SessionId` 切片——`cap == 32` 时 `Seal` 必然 panic。也就是说
//! `UClient` 的这段代码在真实路径上不可达（会先 panic），
//! 只有 `copy(hello.Raw[39:], hello.SessionId)` 之后的 32 字节落进 raw。
//! 本模块按**协议意图**（服务端 `aead.Open` 的 AAD/nonce 布局）实现，
//! 见报告「偏离清单」第 5 条。
//!
//! # 证书公钥校验（`VerifyPeerCertificate`）
//!
//! 服务端不签发真证书：现场 Ed25519 密钥对的**公钥**做 TLS 证书的
//! `publicKey` 字段，而**签名**字段填
//! `HMAC-SHA512(key = auth_key, msg = ed25519_pubkey)`（`handshake_server_tls13.go:149-151`）。
//! 客户端据此确认对端持有同一 `auth_key`（即知服务端私钥），
//! 避免真证书冲突/MITM 时静默继续。

use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use thiserror::Error;
use zeroize::Zeroize;

use super::hash::hkdf_sha256;
use super::x25519::{x25519, x25519_base};
use super::ClientVersion;

mod cert;

pub use cert::{cert_auth_tag, verify_cert_tag};

/// 被 AEAD 加密的认证载荷长度。
///
/// 参考 `reality.go:175`：`aead.Seal(hello.SessionId[:0], nonce,
/// hello.SessionId[:16], hello.Raw)` —— 明文只有**前 16 字节**，
/// 输出 16 密文 + 16 tag = 32 字节，正好填满 SessionId 字段。
/// （服务端 `tls.go:241` 的 `aead.Open(plainText[:0], ...)` 对称。）
/// 完整的 32 字节 `SessionId` 里，`[16..32]` 不参与认证。
pub const AUTH_PAYLOAD_LEN: usize = 16;
/// X25519 公钥/共享密钥长度。
pub const X25519_LEN: usize = 32;
/// AEAD nonce = `client_random[20..32]`，12 字节。
pub const NONCE_LEN: usize = 12;
/// AEAD tag 长度（AES-GCM）。
pub const TAG_LEN: usize = 16;
/// 认证载荷密文长度 = 16 + 16 = 32（即整个 SessionId）。
pub const AUTH_CIPHERTEXT_LEN: usize = AUTH_PAYLOAD_LEN + TAG_LEN;
/// 短 ID 在明文里的偏移（参考 `plainText[8:]`）。
pub const SHORT_ID_OFFSET: usize = 8;
/// Unix 时间戳偏移（参考 `binary.BigEndian.Uint32(plainText[4:])`）。
pub const TIMESTAMP_OFFSET: usize = 4;
/// ClientHello 中 SessionId 的字节偏移；密文从 `raw[39..87]` 就地写回
/// （参考 `copy(hello.Raw[39:], hello.SessionId)` 及其上行注释
/// 「the fixed location of `Session ID`」）。
pub const SESSION_ID_OFFSET: usize = 39;
/// SessionId 长度（TLS 1.3 固定 32 字节）。
pub const SESSION_ID_LEN: usize = 32;
/// ClientHello 里 `client_random` 的偏移：type(1) + len(3) + version(2)。
pub const RANDOM_OFFSET: usize = 6;
/// `client_random` 长度。
pub const RANDOM_LEN: usize = 32;
/// HKDF salt 取 `client_random` 的前 20 字节（参考 `hello.Random[:20]`）。
pub const HKDF_SALT_LEN: usize = 20;
/// HKDF info 字符串（参考 `[]byte("REALITY")`）。
pub const HKDF_INFO: &[u8] = b"REALITY";

/// REALITY 认证失败。全部 fail-closed。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    /// 服务端公钥非法（低阶点 / 全零）：参考 `ecdh.X25519().NewPublicKey`
    /// 报错，或 `X25519` 返回错误使 `AuthKey == nil`（`reality.go:153-166`）。
    #[error("REALITY: invalid public key (low-order or all-zero)")]
    InvalidPublicKey,
    /// AEAD 解封失败（tag 不符 / AAD 不符 / 长度不足）。
    /// 参考服务端 `aead.Open` 报错后 break，该连接不被认作 REALITY。
    #[error("REALITY: authentication payload rejected")]
    AuthRejected,
    /// 输入缓冲太短，放不下 ClientHello 前缀 + SessionId。
    #[error("REALITY: buffer too short (need {need} bytes, got {got})")]
    BufferTooShort { need: usize, got: usize },
    /// 证书认证标签不匹配。
    #[error("REALITY: certificate auth tag mismatch")]
    CertificateMismatch,
    /// 对端证书公钥不是 32 字节 Ed25519。
    #[error("REALITY: peer certificate public key is not Ed25519")]
    NotEd25519,
}

/// 一段 ClientHello 里参与认证的字节视图。
///
/// 参考客户端持有可写的 `hello.Raw`；服务端从读到的 ClientHello 里取
/// `random` 与 `sessionId`。两侧布局相同，故共用一份视图实现。
#[derive(Debug, Clone, Copy)]
pub struct ClientHelloAuthView<'a> {
    raw: &'a [u8],
}

impl<'a> ClientHelloAuthView<'a> {
    /// 按 TLS 1.3 ClientHello 固定前缀构造（需要到 SessionId 末尾）。
    pub fn new(raw: &'a [u8]) -> Result<Self, AuthError> {
        let need = SESSION_ID_OFFSET + SESSION_ID_LEN;
        if raw.len() < need {
            return Err(AuthError::BufferTooShort {
                need,
                got: raw.len(),
            });
        }
        Ok(Self { raw })
    }

    /// `client_random`（32 字节）。参考 `hello.Random`。
    pub fn random(&self) -> &[u8] {
        &self.raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]
    }

    /// SessionId 当前字节（加密前是明文，加密后是密文）。
    pub fn session_id(&self) -> &[u8] {
        &self.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]
    }

    /// AEAD AAD —— 参考传整个 `hello.Raw`。
    pub fn aad(&self) -> &[u8] {
        self.raw
    }

    /// AEAD nonce —— `client_random[20..32]`。
    pub fn nonce(&self) -> [u8; NONCE_LEN] {
        let r = self.random();
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&r[HKDF_SALT_LEN..RANDOM_LEN]);
        n
    }
}

/// 由 `client_random` 前 20 字节与 ECDH 结果派生 32 字节 `auth_key`。
///
/// 对齐参考 `hkdf.New(sha256.New, AuthKey, hello.Random[:20], []byte("REALITY"))`。
fn derive_auth_key(ecdh: &[u8; 32], random: &[u8]) -> Result<[u8; 32], AuthError> {
    if random.len() < RANDOM_LEN {
        return Err(AuthError::BufferTooShort {
            need: RANDOM_LEN,
            got: random.len(),
        });
    }
    let mut out = [0u8; 32];
    hkdf_sha256(Some(&random[..HKDF_SALT_LEN]), ecdh, HKDF_INFO, &mut out);
    Ok(out)
}

/// 客户端侧的 REALITY 握手密钥材料。
///
/// `Debug` **不输出任何密钥字节**（硬约束：日志/Debug 不得泄漏密钥）。
/// 临时公钥本就明文上行，可以在 Debug 里出现。
pub struct RealityClientKeys {
    ephemeral_public: [u8; X25519_LEN],
    /// ECDH 共享密钥（即参考里 `AuthKey` 的 HKDF 输入）。
    shared: [u8; X25519_LEN],
}

impl Drop for RealityClientKeys {
    fn drop(&mut self) {
        // 硬约束：密钥材料用后清零。
        self.shared.zeroize();
    }
}

impl core::fmt::Debug for RealityClientKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealityClientKeys")
            .field("ephemeral_public", &hex(&self.ephemeral_public))
            .field("shared", &"<redacted>")
            .finish()
    }
}

impl RealityClientKeys {
    /// 生成临时 X25519 密钥对并与服务端公钥协商共享密钥。
    ///
    /// `rng` 注入随机源：真实运行用 `aes_gcm::aead::OsRng`，测试用确定性 RNG。
    /// 参考用 Go 标准库 `ecdh.X25519()`；本卡无该依赖，改用本 crate 内置的
    /// [`super::x25519`]（见报告「偏离清单」）。协议字节完全一致：
    /// 同为 RFC 7748 X25519。
    pub fn generate<R: RngCore + CryptoRng>(
        server_public: &[u8; X25519_LEN],
        rng: &mut R,
    ) -> Result<Self, AuthError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let ephemeral_public = x25519_base(&seed);
        // 对齐参考：全零/低阶点共享密钥必须失败（`X25519` 返回 error、
        // `AuthKey == nil`），不得当作合法共享密钥继续。
        let shared = x25519(&seed, server_public).map_err(|_| AuthError::InvalidPublicKey)?;
        seed.zeroize();
        Ok(Self {
            ephemeral_public,
            shared,
        })
    }

    /// 临时公钥（写入 ClientHello 的 key_share）。
    pub fn ephemeral_public(&self) -> [u8; X25519_LEN] {
        self.ephemeral_public
    }

    /// 与 32 字节 `client_random` 一起派生 `auth_key`。
    ///
    /// 对齐参考：`AuthKey = X25519(priv, server_pub)` 随后
    /// `HKDF(ikm = AuthKey, salt = random[:20], info = "REALITY")`。
    ///
    /// **`auth_key` 不落地保存**：调用方拿到后自行控制生命周期
    /// （`seal_auth_payload` 用完即可丢弃）。
    pub fn derive_auth_key(&self, random: &[u8; RANDOM_LEN]) -> Result<[u8; 32], AuthError> {
        derive_auth_key(&self.shared, random)
    }
}

/// 十六进制小写编码（仅用于 Debug 输出公钥）。
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 构造认证载荷明文（[`AUTH_PAYLOAD_LEN`] = 16 字节）。
///
/// 对齐参考 `reality.go:142-144` 写入 `SessionId[0..16]` 的部分：
/// `[0..3]` 版本三元组、`[3]` 保留 0、`[4..8]` big-endian Unix 秒、
/// `[8..16)` 短 ID。
///
/// `short_id` 超过 8 字节的部分不写入；不足则尾部保持 0
/// （对齐 Go 的 `copy(dst, src)` 语义）。
pub fn build_auth_plaintext(
    version: ClientVersion,
    unix_time: u32,
    short_id: &[u8],
) -> [u8; AUTH_PAYLOAD_LEN] {
    let mut out = [0u8; AUTH_PAYLOAD_LEN];
    out[..3].copy_from_slice(&version.to_bytes());
    out[3] = 0;
    out[TIMESTAMP_OFFSET..TIMESTAMP_OFFSET + 4].copy_from_slice(&unix_time.to_be_bytes());
    // 明文的 `[8..16)` 是 8 字节短 ID；参考的 `SessionId[8..]` 其实是 24 字节
    // 但只有前 8 字节被加密（`Seal(.., SessionId[:16], ..)`），
    // 服务端 `plainText[8:]` 得到的正是这 8 字节。
    let n = short_id.len().min(AUTH_PAYLOAD_LEN - SHORT_ID_OFFSET);
    out[SHORT_ID_OFFSET..SHORT_ID_OFFSET + n].copy_from_slice(&short_id[..n]);
    out
}

/// 解出认证载荷明文（服务端侧）。
///
/// 注意明文只有 [`AUTH_PAYLOAD_LEN`]（16）字节；`SessionId[16..32]` 不在
/// AEAD 覆盖范围内（见 [`AUTH_PAYLOAD_LEN`] 的说明）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPlaintext {
    pub version: ClientVersion,
    /// `[3]` 保留字节；参考未校验，保留以便逐字节比对。
    pub reserved: u8,
    pub unix_time: u32,
    /// `[8..16)`，8 字节短 ID。
    pub short_id: [u8; 8],
}

impl AuthPlaintext {
    /// 从 16 字节明文解析。
    pub fn parse(p: &[u8; AUTH_PAYLOAD_LEN]) -> Self {
        let mut short_id = [0u8; 8];
        short_id.copy_from_slice(&p[SHORT_ID_OFFSET..]);
        Self {
            version: ClientVersion {
                x: p[0],
                y: p[1],
                z: p[2],
            },
            reserved: p[3],
            unix_time: u32::from_be_bytes([
                p[TIMESTAMP_OFFSET],
                p[TIMESTAMP_OFFSET + 1],
                p[TIMESTAMP_OFFSET + 2],
                p[TIMESTAMP_OFFSET + 3],
            ]),
            short_id,
        }
    }

    /// 参与服务端 `config.ShortIds` 查表的 8 字节键（参考 `tls.go:251`）。
    pub fn short_id_key(&self) -> [u8; 8] {
        self.short_id
    }
}

/// 客户端：把认证载荷加密，产出写回 ClientHello 的 32 字节 SessionId。
///
/// 对齐参考 `reality.go:175` 的 `aead.Seal(hello.SessionId[:0],
/// hello.Random[20:], hello.SessionId[:16], hello.Raw)`：
/// 明文 16 字节、AAD 为 SessionId 区清零的完整 ClientHello、nonce 为
/// `random[20..32]`，输出 16 密文 + 16 tag = 32 字节，正好填满 SessionId。
///
/// `raw` 需为完整 ClientHello（至少到 SessionId 末尾），与 `hello.Raw` 一致；
/// 本函数**不修改 `raw`**，由调用方把返回值写入 `raw[39..87]`（对齐参考的
/// `copy(hello.Raw[39:], hello.SessionId)`）。
pub fn seal_auth_payload(
    auth_key: &[u8; 32],
    plaintext: &[u8; AUTH_PAYLOAD_LEN],
    raw: &[u8],
) -> Result<[u8; SESSION_ID_LEN], AuthError> {
    let view = ClientHelloAuthView::new(raw)?;
    let nonce = view.nonce();
    let cipher = Aes256Gcm::new_from_slice(auth_key).expect("AES-256 key is 32 bytes");
    // AAD = ClientHello，其中 SessionId 区域**置零**。
    //
    // 参考 `reality.go:139-141`：`hello.SessionId = make([]byte, 32)` 是一个
    // 新缓冲，`copy(hello.Raw[39:], hello.SessionId)` 把 raw 的该区域写成
    // **零**；真正的 SessionId 内容在此后才填。`aead.Seal(..., hello.Raw)`
    // 因此以「SessionId 区为零」的 raw 作 AAD。服务端 `tls.go:243` 亦显式
    // 把该区域清零后再 `Open`，两端一致。
    let mut aad = raw.to_vec();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AuthError::AuthRejected)?;
    debug_assert_eq!(ct.len(), SESSION_ID_LEN);
    let mut out = [0u8; SESSION_ID_LEN];
    out.copy_from_slice(&ct);
    Ok(out)
}

/// 服务端：用 `auth_key` 解开 ClientHello 的 SessionId，得到 32 字节明文。
///
/// 对齐参考 `tls.go:241-250`：
/// `aead.Open(plainText[:0], random[20:], ciphertext, clientHello.original)`，
/// 其中 `clientHello.original` 是包含**当前（密文态）SessionId** 的原始
/// ClientHello。调用方需保证 `auth_key` 已按同一 `random` 派生。
///
/// 失败一律 [`AuthError::AuthRejected`]，**不得返回部分明文**。
pub fn open_auth_payload(auth_key: &[u8; 32], raw: &[u8]) -> Result<AuthPlaintext, AuthError> {
    let view = ClientHelloAuthView::new(raw)?;
    let nonce = view.nonce();
    let ciphertext = view.session_id();
    // AAD 与 `seal` 对称：SessionId 区域清零后的 ClientHello
    // （对齐 `tls.go:243` 先把 `hs.clientHello.sessionId` 清空再 `Open`）。
    let mut aad = raw.to_vec();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
    let cipher = Aes256Gcm::new_from_slice(auth_key).expect("AES-256 key is 32 bytes");
    let pt = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| AuthError::AuthRejected)?;
    let pt: [u8; AUTH_PAYLOAD_LEN] = pt
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::AuthRejected)?;
    Ok(AuthPlaintext::parse(&pt))
}

/// 服务端侧：由客户端临时公钥与 ClientHello 派生 `auth_key`。
///
/// 对齐参考 `tls.go:230-236`（`curve25519.X25519(server_priv, peerPub)`
/// 后接同一 HKDF）。`server_private` 是服务端 REALITY 私钥。
pub fn derive_auth_key_server(
    server_private: &[u8; 32],
    peer_public: &[u8; 32],
    random: &[u8; RANDOM_LEN],
) -> Result<[u8; 32], AuthError> {
    let shared = x25519(server_private, peer_public).map_err(|_| AuthError::InvalidPublicKey)?;
    derive_auth_key(&shared, random)
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod auth_tests;
