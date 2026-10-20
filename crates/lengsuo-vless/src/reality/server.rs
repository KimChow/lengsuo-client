//! REALITY 服务端认证逻辑层（对齐 `github.com/xtls/reality` `tls.go` 的
//! `Server()` 认证块 + Xray `proxy/vless/inbound/inbound.go` 的 REALITY 分支）。
//!
//! 参考固定 Xray `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`；服务端实现在
//! 依赖 `github.com/xtls/reality@v0.0.0-20260322125925-9234c772ba8f`
//! （`tls.go:216-262` 的 server goroutine 内联块），逐条语义：
//!
//! 1. `config.ServerNames[clientHello.serverName]` 未命中 → 不认证（回落）。
//! 2. 从 key_shares 取 X25519（32 字节）对端公钥；没有则前缀回落。
//! 3. `curve25519.X25519(config.PrivateKey, peerPub)` → `AuthKey`，
//!    再 `hkdf(SHA-256, ikm=AuthKey, salt=random[:20], info="REALITY")` **写回**
//!    同一 `AuthKey` 切片；`aes.NewCipher(AuthKey)` + `cipher.NewGCM`。
//! 4. `copy(ciphertext, sessionId)`；`copy(sessionId, plainText)` —— 把
//!    `raw[39..71]` 清零（`sessionId` 是 `raw[39:]` 的 32 字节视图）；随后
//!    `aead.Open(plainText[:0], random[20:], ciphertext, clientHello.original)`，
//!    即 **AAD = 原始 ClientHello**；`Open` 的密文为 32 + tag 16。
//!    本仓 [`open_auth_payload`] 用「SessionId 区清零的 raw」作 AAD，与其注释一致。
//! 5. `ClientVer = plainText[0..3]`、`ClientTime = Unix(BigEndian.Uint32(
//!    plainText[4:]))`、`ClientShortId = plainText[8..16]`。
//! 6. 准入（全满足才认作 REALITY）：版本上下限 + `MaxTimeDiff` 窗口 +
//!    `config.ShortIds[ClientShortId]`（map 查表；**空短 ID 未配置即拒绝**）。
//!
//! 参考认证失败**不报错**，连接被镜像到 `Dest` 回落；本层不建记录层、
//! 不拨回落目标，只返回 [`RealityReject`] 供调用方决定回落。**不得**静默
//! 降级为「无 REALITY」继续明文处理。
//!
//! **范围**：仅认证逻辑层。真实 TLS 记录层、服务端证书伪造/回落
//! （`MirrorConn`/`RatelimitedConn`/`DetectPostHandshakeRecordsLens`）、
//! uTLS 指纹、与 Xray REALITY 服务端的端到端互通——均不在本卡。
//!
//! # 与参考的差异边界
//!
//! 参考的 `clientHelloMsg` 由 BoringSSL 派生的解析器（`tls.go` 同目录
//! `handshake_messages.go`）解出 `random`/`sessionId`/`keyShares`/`serverName`
//! 后再进认证块。本仓无该解析器，故在本模块内做**最小** ClientHello 切片
//! 走查，只取认证块用到的三项（SNI、X25519 key_share、SessionId 视图）；
//! 不构建 `clientHelloMsg`、不校验记录层，也不覆盖 ECH/ML-KEM。
//! 细节见 `docs/vless-status.md` 偏离清单。

use core::time::Duration;
use thiserror::Error;
use zeroize::Zeroize;

use super::auth::{
    derive_auth_key_server, open_auth_payload, AuthError, RANDOM_LEN, RANDOM_OFFSET,
    SESSION_ID_LEN, SESSION_ID_OFFSET,
};
use super::ClientVersion;

/// TLS 握手消息类型：ClientHello。
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// 扩展 `server_name`（RFC 6066）。
const EXT_SERVER_NAME: u16 = 0x0000;
/// 扩展 `key_share`（RFC 8446）。
const EXT_KEY_SHARE: u16 = 0x0033;
/// 命名组 `x25519`（RFC 8446）。
const GROUP_X25519: u16 = 0x001d;

/// 服务端 REALITY 配置（参考 `Config` 的服务端子集：`PrivateKey` /
/// `ShortIds` / `ServerNames` / `MaxTimeDiff`）。
#[derive(Clone)]
pub struct RealityServerConfig {
    /// X25519 私钥（参考 `config.PrivateKey`；`Debug` 不输出）。
    pub private_key: [u8; 32],
    /// 准入短 ID 白名单（参考 `config.ShortIds`，`map[[8]byte]bool`）。
    /// **空短 ID（全零）只有在显式列入时才接受**。
    pub short_ids: Vec<[u8; 8]>,
    /// 准入 SNI 白名单（参考 `config.ServerNames`）。
    pub server_names: Vec<String>,
    /// 时间戳允许偏差（参考 `config.MaxTimeDiff`；0 表示不校验时间窗，
    /// 对齐参考 `MaxTimeDiff == 0 ||` 的短路语义）。
    pub max_time_diff: Duration,
}

impl core::fmt::Debug for RealityServerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealityServerConfig")
            .field("private_key", &"<redacted>")
            .field("short_ids_len", &self.short_ids.len())
            .field("server_names", &self.server_names)
            .field("max_time_diff", &self.max_time_diff)
            .finish()
    }
}

/// 认证成功后的结果（参考 `Conn` 的 `ClientVer`/`ClientTime`/`ClientShortId`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityAccept {
    pub client_version: ClientVersion,
    pub timestamp: u32,
    pub short_id: [u8; 8],
}

/// 认证拒绝。`Display`/`Debug` 均不含密钥、短 ID 明文、认证载荷明文。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityReject {
    /// 缓冲不足以容纳 ClientHello 前缀 + SessionId。
    #[error("REALITY server: client hello too short (got {got}, need {need})")]
    BufferTooShort { need: usize, got: usize },
    /// 首字节不是 ClientHello（参考 `readClientHello` 的
    /// `unexpectedMessageError`）。
    #[error("REALITY server: not a client hello")]
    NotClientHello,
    /// ClientHello 结构在固定前缀之后不完整/畸形。
    #[error("REALITY server: malformed client hello")]
    MalformedHello,
    /// SNI 不在白名单（参考 `config.ServerNames[serverName]` 未命中）。
    #[error("REALITY server: server name not allowed")]
    ServerNameNotAllowed,
    /// 没有可用的 X25519 对端公钥（参考 `peerPub == nil`）。
    #[error("REALITY server: no supported x25519 key share")]
    NoKeyShare,
    /// X25519/HKDF 派生失败（低阶点、全零共享密钥）。
    #[error("REALITY server: key agreement rejected")]
    KeyAgreementRejected,
    /// AEAD 解封失败（参考 `aead.Open` 报错 → 回落）。
    #[error("REALITY server: authentication payload rejected")]
    AuthRejected,
    /// 时间戳越窗（参考 `time.Since(ClientTime).Abs() > MaxTimeDiff`）。
    #[error("REALITY server: client time outside allowed window")]
    TimeOutOfRange,
    /// 短 ID 未列入白名单（含空短 ID 未显式配置）。
    #[error("REALITY server: short id not allowed")]
    ShortIdNotAllowed,
}

impl From<AuthError> for RealityReject {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::InvalidPublicKey => Self::KeyAgreementRejected,
            AuthError::BufferTooShort { need, got } => Self::BufferTooShort { need, got },
            _ => Self::AuthRejected,
        }
    }
}

/// 服务端准入入口：解 SessionId 认证载荷 → 时间窗 → 短 ID 白名单。
///
/// `raw_client_hello` 为完整 ClientHello 原始字节（参考
/// `clientHello.original`），SessionId 处于**密文态**且定位于
/// `raw[39..71]`；`now_unix` 为服务端当前 Unix 秒（调用方注入时钟）。
///
/// 判定顺序对齐参考：SNI → key_share → X25519/HKDF → `aead.Open` →
/// 时间窗 → 短 ID。任一步失败返回 [`RealityReject`]（fail-closed）。
pub fn accept_hello(
    config: &RealityServerConfig,
    raw_client_hello: &[u8],
    now_unix: u32,
) -> Result<RealityAccept, RealityReject> {
    let hello = ClientHello::parse(raw_client_hello)?;

    // 1) SNI 白名单（参考 `config.ServerNames[clientHello.serverName]`）。
    let server_name = hello.server_name().ok_or(RealityReject::MalformedHello)?;
    if !config.server_names.iter().any(|n| n == server_name) {
        return Err(RealityReject::ServerNameNotAllowed);
    }

    // 2) key_share 里的 X25519 公钥（参考遍历 `keyShares` 找 `X25519`）。
    let peer_public = hello.x25519_key_share().ok_or(RealityReject::NoKeyShare)?;

    // 3) X25519 + HKDF（参考 `curve25519.X25519` + `hkdf.New(...).Read`）。
    let mut random = [0u8; RANDOM_LEN];
    random.copy_from_slice(hello.random);
    let mut auth_key = derive_auth_key_server(&config.private_key, &peer_public, &random)?;

    // 4) AEAD 解封（参考 `aead.Open(..., clientHello.original)`）。
    let plaintext =
        open_auth_payload(&auth_key, raw_client_hello).map_err(|_| RealityReject::AuthRejected);
    auth_key.zeroize();
    let plaintext = plaintext?;

    // 5) 时间窗（参考 `MaxTimeDiff == 0 || |now - ClientTime| <= MaxTimeDiff`）。
    if !time_in_window(plaintext.unix_time, now_unix, config.max_time_diff) {
        return Err(RealityReject::TimeOutOfRange);
    }

    // 6) 短 ID（参考 `config.ShortIds[ClientShortId]`；空短 ID 不默认放行）。
    if !super::shortid::short_id_matches(&config.short_ids, &plaintext.short_id) {
        return Err(RealityReject::ShortIdNotAllowed);
    }

    Ok(RealityAccept {
        client_version: plaintext.version,
        timestamp: plaintext.unix_time,
        short_id: plaintext.short_id,
    })
}

/// 时间窗：参考 `MaxTimeDiff == 0 || time.Since(t).Abs() <= MaxTimeDiff`。
///
/// 参考的 `MaxTimeDiff` 是 `time.Duration`（纳秒精度）；本参数有秒级粒度
/// （`unix_time` 本身是 `u32` 秒），故只比较秒。
fn time_in_window(client_unix: u32, now_unix: u32, max_diff: Duration) -> bool {
    if max_diff.is_zero() {
        return true;
    }
    u64::from(client_unix.abs_diff(now_unix)) <= max_diff.as_secs()
}

/// 最小 ClientHello 切片走查（仅认证块所需字段）。
///
/// 布局对齐 RFC 8446 4.1.2 / 参考 `clientHelloMsg.unmarshal`：
/// type(1) + len(3) + legacy_version(2) + random(32) + session_id(1+n) +
/// cipher_suites(2+n) + compression(1+n) + extensions(2+n)。
struct ClientHello<'a> {
    random: &'a [u8],
    server_name_ext: Option<&'a [u8]>,
    key_share_ext: Option<&'a [u8]>,
}

impl<'a> ClientHello<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, RealityReject> {
        // 固定前缀（含 32 字节 SessionId）必须完整。
        let need = SESSION_ID_OFFSET + SESSION_ID_LEN;
        if raw.len() < need {
            return Err(RealityReject::BufferTooShort {
                need,
                got: raw.len(),
            });
        }
        if raw[0] != TLS_HANDSHAKE_CLIENT_HELLO {
            return Err(RealityReject::NotClientHello);
        }
        let random = &raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];
        // 参考的定长偏移假定 `sessionId` 长 32；本仓同样要求（否则定长
        // `raw[39..71]` 不成立，`open_auth_payload` 会解出错误数据）。
        if raw[SESSION_ID_OFFSET - 1] as usize != SESSION_ID_LEN {
            return Err(RealityReject::MalformedHello);
        }
        let rest = &raw[need..];
        let rest = skip_vec_u16(rest)?; // cipher_suites
        let rest = skip_vec_u8(rest)?; // compression_methods
        let mut server_name_ext = None;
        let mut key_share_ext = None;
        if rest.is_empty() {
            // 无扩展：SNI/key_share 均缺失，交由后续判定拒绝。
            return Ok(Self {
                random,
                server_name_ext,
                key_share_ext,
            });
        }
        let (exts, _) = take_vec_u16(rest)?;
        let mut exts = exts;
        while !exts.is_empty() {
            if exts.len() < 4 {
                return Err(RealityReject::MalformedHello);
            }
            let ty = u16::from_be_bytes([exts[0], exts[1]]);
            let len = usize::from(u16::from_be_bytes([exts[2], exts[3]]));
            let data = exts.get(4..4 + len).ok_or(RealityReject::MalformedHello)?;
            match ty {
                EXT_SERVER_NAME => server_name_ext = Some(data),
                EXT_KEY_SHARE => key_share_ext = Some(data),
                _ => {}
            }
            exts = &exts[4 + len..];
        }
        Ok(Self {
            random,
            server_name_ext,
            key_share_ext,
        })
    }

    /// `server_name` 扩展里的首个 `host_name`（参考 `m.serverName`）。
    fn server_name(&self) -> Option<&'a str> {
        let data = self.server_name_ext?;
        let (list, _) = take_vec_u16(data).ok()?;
        // name_type(1) + name_len(2) + name
        if list.len() < 3 || list[0] != 0 {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([list[1], list[2]]));
        core::str::from_utf8(list.get(3..3 + len)?).ok()
    }

    /// key_share 里第一个 32 字节 `x25519` 条目（参考遍历 `keyShares`）。
    fn x25519_key_share(&self) -> Option<[u8; 32]> {
        let data = self.key_share_ext?;
        let (mut shares, _) = take_vec_u16(data).ok()?;
        while !shares.is_empty() {
            if shares.len() < 4 {
                return None;
            }
            let group = u16::from_be_bytes([shares[0], shares[1]]);
            let len = usize::from(u16::from_be_bytes([shares[2], shares[3]]));
            let key = shares.get(4..4 + len)?;
            if group == GROUP_X25519 && key.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(key);
                return Some(out);
            }
            shares = &shares[4 + len..];
        }
        None
    }
}

/// 跳过 `u8` 长度前缀的向量，返回其后剩余字节。
fn skip_vec_u8(b: &[u8]) -> Result<&[u8], RealityReject> {
    let (&n, rest) = b.split_first().ok_or(RealityReject::MalformedHello)?;
    if rest.len() < usize::from(n) {
        return Err(RealityReject::MalformedHello);
    }
    Ok(&rest[usize::from(n)..])
}

/// 跳过 `u16` 长度前缀的向量，返回其后剩余字节。
fn skip_vec_u16(b: &[u8]) -> Result<&[u8], RealityReject> {
    if b.len() < 2 {
        return Err(RealityReject::MalformedHello);
    }
    let n = usize::from(u16::from_be_bytes([b[0], b[1]]));
    b.get(2 + n..).ok_or(RealityReject::MalformedHello)
}

/// 取 `u16` 长度前缀的向量，返回 `(payload, remainder)`。
fn take_vec_u16(b: &[u8]) -> Result<(&[u8], &[u8]), RealityReject> {
    if b.len() < 2 {
        return Err(RealityReject::MalformedHello);
    }
    let n = usize::from(u16::from_be_bytes([b[0], b[1]]));
    let payload = b.get(2..2 + n).ok_or(RealityReject::MalformedHello)?;
    Ok((payload, &b[2 + n..]))
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod server_tests;
