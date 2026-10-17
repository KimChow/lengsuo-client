//! 加密容器编解码（schema v0，二进制，小端）。
//!
//! 布局：
//!
//! ```text
//! header = magic[8]
//!        || schema_version u32
//!        || kdf_iterations u32 || kdf_key_len u32
//!        || salt[16]
//!        || verifier_len u32 || verifier(nonce||ct||tag)   // 明文为固定值
//! body   = record_count u32 || record*
//! record = sealed_len u32 || sealed(nonce||ct||tag)
//! ```
//!
//! `sealed` 的明文是 `meta || credential_plaintext`，其中
//! `meta = id uuid[16] || scope_kind u8 || target_len u16 || target utf8 || expires_at_ms u64`。
//!
//! 语义要点：
//! - **文件内不出现任何凭据明文，也不出现引用元数据**（id、作用域目标、过期时刻都在密文里）。
//! - 每条记录独立随机 nonce；AAD = `header || record_index`，故元数据被认证绑定，
//!   改一字节即认证失败；把记录搬到另一个文件（salt/verifier 不同）也必然失败。
//! - `verifier` 用同一密钥、独立 AAD 密封固定明文；解不开即口令错误，与记录篡改分开报告。
//! - schema 版本不识别 → 拒绝读取，不尝试解密（fail-closed）。

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::StoreError;
use crate::plaintext::Plaintext;
use crate::reference::{CredentialRef, RefId, Scope, ScopeKind};

/// 作用域目标最大字节数：容器用 u16 长度域承载，超出即不可表示。
/// 与 [`crate::CredentialRef::is_valid`] 挂钩，避免截断长度域写出解不回的回引用。
pub(crate) const MAX_TARGET_LEN: usize = u16::MAX as usize;

/// scope kind 的稳定编码。
const KIND_ENV: u8 = 1;
const KIND_SESSION: u8 = 2;
const KIND_TENANT: u8 = 3;

/// 单条记录：引用元数据 + 待加密明文字节。
pub(crate) struct Record<'a> {
    pub(crate) reference: &'a CredentialRef,
    pub(crate) plaintext: &'a [u8],
}

/// 解码后的记录：引用元数据 + 已解密的明文缓冲。
///
/// `Debug` 安全：两个字段类型的 `Debug` 均为固定掩码，不呈现 id、作用域目标或明文字节。
#[derive(Debug)]
pub(crate) struct OpenedRecord {
    pub(crate) reference: CredentialRef,
    pub(crate) plaintext: Plaintext,
}

fn take<'b>(buf: &mut &'b [u8], len: usize, what: &'static str) -> Result<&'b [u8], StoreError> {
    if buf.len() < len {
        return Err(StoreError::MalformedContainer(what));
    }
    let (head, rest) = buf.split_at(len);
    *buf = rest;
    Ok(head)
}

fn read_u16(buf: &mut &[u8], what: &'static str) -> Result<u16, StoreError> {
    let raw = take(buf, 2, what)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(buf: &mut &[u8], what: &'static str) -> Result<u32, StoreError> {
    let raw = take(buf, 4, what)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(buf: &mut &[u8], what: &'static str) -> Result<u64, StoreError> {
    let raw = take(buf, 8, what)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(raw);
    Ok(u64::from_le_bytes(arr))
}

fn kind_code(kind: ScopeKind) -> u8 {
    match kind {
        ScopeKind::Env => KIND_ENV,
        ScopeKind::Session => KIND_SESSION,
        ScopeKind::Tenant => KIND_TENANT,
    }
}

fn kind_from_code(code: u8) -> Result<ScopeKind, StoreError> {
    match code {
        KIND_ENV => Ok(ScopeKind::Env),
        KIND_SESSION => Ok(ScopeKind::Session),
        KIND_TENANT => Ok(ScopeKind::Tenant),
        _ => Err(StoreError::MalformedContainer("unknown scope kind")),
    }
}

/// 记录元数据字节编码（`meta` 部分，密文内部结构）。
fn encode_meta(reference: &CredentialRef) -> Vec<u8> {
    let target = reference.scope().target();
    let mut out = Vec::with_capacity(27 + target.len());
    out.extend_from_slice(reference.id().as_uuid().as_bytes());
    out.push(kind_code(reference.scope().kind()));
    out.extend_from_slice(&(target.len() as u16).to_le_bytes());
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(&reference.expires_at_ms().to_le_bytes());
    out
}

/// 从 `meta || plaintext` 拆出引用与明文；返回 `(reference, plaintext_bytes)`。
fn decode_record_plain(bytes: &[u8]) -> Result<(CredentialRef, &[u8]), StoreError> {
    let mut rest = bytes;
    let id_bytes = take(&mut rest, 16, "record id truncated")?;
    let kind_byte = take(&mut rest, 1, "record scope kind truncated")?;
    let kind = kind_from_code(kind_byte[0])?;
    let target_len = read_u16(&mut rest, "record target length truncated")? as usize;
    let target = take(&mut rest, target_len, "record target truncated")?;
    let target = std::str::from_utf8(target)
        .map_err(|_| StoreError::MalformedContainer("record target not utf8"))?;
    let expires_at_ms = read_u64(&mut rest, "record expiry truncated")?;
    let id = Uuid::from_slice(id_bytes)
        .map_err(|_| StoreError::MalformedContainer("record id length invalid"))?;
    let scope = match kind {
        ScopeKind::Env => Scope::Env(target.to_owned()),
        ScopeKind::Session => Scope::Session(target.to_owned()),
        ScopeKind::Tenant => Scope::Tenant(target.to_owned()),
    };
    let reference = CredentialRef::with_id(RefId::from_uuid(id), scope, expires_at_ms);
    if !reference.is_valid() {
        return Err(StoreError::MalformedContainer("record scope target empty"));
    }
    Ok((reference, rest))
}

/// 头部字节（magic + 版本 + KDF 参数 + salt + verifier）；同时作为记录 AAD 前缀。
fn build_header_prefix(params: crypto::KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(crypto::HEADER_PREFIX_LEN);
    out.extend_from_slice(&crypto::MAGIC);
    out.extend_from_slice(&params.schema_version.to_le_bytes());
    out.extend_from_slice(&params.iterations.to_le_bytes());
    out.extend_from_slice(&params.key_len.to_le_bytes());
    out.extend_from_slice(salt);
    out
}

fn build_header(params: crypto::KdfParams, salt: &[u8], verifier: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(crypto::HEADER_PREFIX_LEN + 4 + verifier.len());
    out.extend_from_slice(&crypto::MAGIC);
    out.extend_from_slice(&params.schema_version.to_le_bytes());
    out.extend_from_slice(&params.iterations.to_le_bytes());
    out.extend_from_slice(&params.key_len.to_le_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&(verifier.len() as u32).to_le_bytes());
    out.extend_from_slice(verifier);
    out
}

/// 写出完整容器字节。`key` 必须由 `salt` 与口令派生，且与 `params` 一致。
pub(crate) fn encode_container(
    params: crypto::KdfParams,
    salt: &[u8],
    key: &[u8],
    records: &[Record<'_>],
    rng: &mut impl rand::RngCore,
) -> Result<Vec<u8>, StoreError> {
    // verifier 的 AAD = 头部前缀（magic..verifier_len 字段），与解码端一致。
    let mut verifier_aad = build_header_prefix(params, salt);
    verifier_aad.extend_from_slice(&(crypto::VERIFIER_PLAIN.len() as u32 + 12 + 16).to_le_bytes());
    let verifier = crypto::seal(key, &verifier_aad, rng, crypto::VERIFIER_PLAIN)?;
    let header = build_header(params, salt, &verifier);
    let mut out = header.clone();
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (index, record) in records.iter().enumerate() {
        if !record.reference.is_valid() {
            return Err(StoreError::InvalidReference);
        }
        let mut inner = encode_meta(record.reference);
        inner.extend_from_slice(record.plaintext);
        let aad = record_aad(&header, index);
        let sealed = crypto::seal(key, &aad, rng, &inner)?;
        out.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&sealed);
    }
    Ok(out)
}

fn record_aad(header: &[u8], index: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 4);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&(index as u32).to_le_bytes());
    aad
}

/// 已解析头部：KDF 参数、salt、verifier 密文，以及作为记录 AAD 前缀的完整头部字节。
struct Header {
    params: crypto::KdfParams,
    salt: Vec<u8>,
    bytes: Vec<u8>,
    verifier: Vec<u8>,
    /// verifier 密文在 `bytes` 中的起始偏移；其前缀即 verifier 的 AAD。
    verifier_offset: usize,
}

// 手工 `Debug`：字节字段（salt/verifier 密文）只报长度，不随测试失败输出进日志。
impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("params", &self.params)
            .field("salt_len", &self.salt.len())
            .field("header_len", &self.bytes.len())
            .field("verifier_len", &self.verifier.len())
            .finish()
    }
}

/// 解析头部：magic 与版本 fail-closed。
fn decode_header(bytes: &[u8]) -> Result<Header, StoreError> {
    let mut rest = bytes;
    let magic = take(&mut rest, crypto::MAGIC.len(), "magic truncated")?;
    if magic != crypto::MAGIC {
        return Err(StoreError::MalformedContainer("magic mismatch"));
    }
    let schema_version = read_u32(&mut rest, "schema version truncated")?;
    let iterations = read_u32(&mut rest, "kdf iterations truncated")?;
    let key_len = read_u32(&mut rest, "kdf key length truncated")?;
    let params = crypto::KdfParams {
        schema_version,
        iterations,
        key_len,
    };
    // 头部任何字段（含版本）都必须先通过认证才可信：版本门与参数门移到
    // decode_container 的 verifier 认证之后执行（见该函数注释）。
    let salt = take(&mut rest, crypto::SALT_LEN, "salt truncated")?.to_vec();
    let verifier_len = read_u32(&mut rest, "verifier length truncated")? as usize;
    // verifier_len 字段受 AAD 认证绑定；其真实取值恒为定长（固定明文 ⇒ 55 字节）。
    // 超乎可能的巨大长度 ⇒ 字节被篡改 ⇒ 认证失败；普通截断（仍 ≤ 4096）保留
    // MalformedContainer 语义，由下方 take 统一报错。
    if verifier_len > 4096 {
        return Err(StoreError::RecordAuthentication);
    }
    if verifier_len > rest.len() {
        return Err(StoreError::MalformedContainer("verifier truncated"));
    }
    let verifier = take(&mut rest, verifier_len, "verifier truncated")?.to_vec();
    let header_len = bytes.len() - rest.len();
    // verifier 密文之前的全部头部字节（magic..verifier_len 字段），作为 verifier 的 AAD。
    let verifier_offset = header_len - verifier.len();
    Ok(Header {
        params,
        salt,
        bytes: bytes[..header_len].to_vec(),
        verifier,
        verifier_offset,
    })
}

/// 读取并解密容器；口令错误与记录篡改分别报告。
pub(crate) fn decode_container(
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<(crypto::KdfParams, Vec<OpenedRecord>), StoreError> {
    let header = decode_header(bytes)?;
    // KDF 参数在认证前不可信：只拦截「无法服务或会触发高开销派生」的取值
    // （key_len/轮数），不看版本——版本门在认证之后（版本字段本身也被 AAD 绑定）。
    // v0 iterations=1；上限给足余量，仅为拦截被篡改后的巨轮数。
    if header.params.key_len != crypto::KEY_LEN as u32
        || header.params.iterations == 0
        || header.params.iterations > 16
    {
        return Err(StoreError::RecordAuthentication);
    }
    let key = crypto::derive_key(passphrase, &header.salt, header.params)?;
    // 先验证口令：verifier 的 AAD 绑定其前缀（magic..verifier_len 字段），
    // 头部任一字节被篡改都在此处暴露为口令错误；认证通过后才信任版本与参数。
    crypto::open(
        &key,
        &header.bytes[..header.verifier_offset],
        &header.verifier,
    )
    .map_err(|err| match err {
        StoreError::RecordAuthentication => StoreError::WrongPassphrase,
        other => other,
    })?;
    // 口令验证通过后，未识别的 schema 版本才按「版本过新」拒绝（fail-closed 语义不变）。
    if header.params.schema_version != crypto::SCHEMA_VERSION {
        return Err(StoreError::UnsupportedVersion {
            found: header.params.schema_version,
            expected: crypto::SCHEMA_VERSION,
        });
    }

    let mut rest = &bytes[header.bytes.len()..];
    let count = read_u32(&mut rest, "record count truncated")? as usize;
    let mut records = Vec::with_capacity(count.min(8192));
    for index in 0..count {
        let sealed_len = read_u32(&mut rest, "record length truncated")? as usize;
        let sealed = take(&mut rest, sealed_len, "record ciphertext truncated")?;
        let aad = record_aad(&header.bytes, index);
        let inner = crypto::open(&key, &aad, sealed)?;
        let (reference, plaintext_bytes) = decode_record_plain(inner.as_slice())?;
        // 复制出的明文缓冲立刻纳入 Zeroizing，避免留下未受保护的裸明文字节。
        let mut buffer = Vec::with_capacity(plaintext_bytes.len());
        buffer.extend_from_slice(plaintext_bytes);
        records.push(OpenedRecord {
            reference,
            plaintext: Plaintext::from_zeroizing(Zeroizing::new(buffer)),
        });
    }
    if !rest.is_empty() {
        return Err(StoreError::MalformedContainer("container trailing bytes"));
    }
    Ok((header.params, records))
}

#[cfg(test)]
#[path = "container_tests.rs"]
mod tests;
