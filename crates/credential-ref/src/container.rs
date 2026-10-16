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
    let verifier = crypto::seal(key, crypto::VERIFIER_AAD, rng, crypto::VERIFIER_PLAIN)?;
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
    // 版本不识别 → 直接拒绝读取，不尝试解密。
    if params.schema_version != crypto::SCHEMA_VERSION {
        return Err(StoreError::UnsupportedVersion {
            found: params.schema_version,
            expected: crypto::SCHEMA_VERSION,
        });
    }
    if !params.is_supported() {
        return Err(StoreError::MalformedContainer("unsupported kdf parameters"));
    }
    let salt = take(&mut rest, crypto::SALT_LEN, "salt truncated")?.to_vec();
    let verifier_len = read_u32(&mut rest, "verifier length truncated")? as usize;
    let verifier = take(&mut rest, verifier_len, "verifier truncated")?.to_vec();
    let header_len = bytes.len() - rest.len();
    Ok(Header {
        params,
        salt,
        bytes: bytes[..header_len].to_vec(),
        verifier,
    })
}

/// 读取并解密容器；口令错误与记录篡改分别报告。
pub(crate) fn decode_container(
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<(crypto::KdfParams, Vec<OpenedRecord>), StoreError> {
    let header = decode_header(bytes)?;
    let key = crypto::derive_key(passphrase, &header.salt, header.params)?;
    // 先验证口令：verifier 认证失败统一报告为口令错误。
    crypto::open(&key, crypto::VERIFIER_AAD, &header.verifier).map_err(|err| match err {
        StoreError::RecordAuthentication => StoreError::WrongPassphrase,
        other => other,
    })?;

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
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use rand::SeedableRng;

    fn key_for(salt: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        crypto::derive_key(b"pass", salt, KdfParams::V0).expect("derive")
    }

    fn records_for<'a>(references: &'a [CredentialRef], plaintexts: &[&'a str]) -> Vec<Record<'a>> {
        references
            .iter()
            .zip(plaintexts)
            .map(|(reference, plaintext)| Record {
                reference,
                plaintext: plaintext.as_bytes(),
            })
            .collect()
    }

    fn deterministic_rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0x5EED)
    }

    #[test]
    fn meta_is_self_delimiting_and_restores_reference() {
        let reference = CredentialRef::session("sess-42", 1_700_000_000_123);
        let mut inner = encode_meta(&reference);
        inner.extend_from_slice(b"token-bytes");
        let (decoded, plaintext) = decode_record_plain(&inner).expect("decodes");
        assert_eq!(decoded, reference);
        assert_eq!(plaintext, b"token-bytes");
    }

    #[test]
    fn empty_scope_target_fails_closed() {
        let reference = CredentialRef::env(String::new(), 10);
        let inner = encode_meta(&reference);
        assert!(matches!(
            decode_record_plain(&inner),
            Err(StoreError::MalformedContainer(_))
        ));
    }

    #[test]
    fn unknown_scope_kind_fails_closed() {
        let reference = CredentialRef::tenant("t1", 10);
        let mut inner = encode_meta(&reference);
        inner[16] = 99;
        assert!(matches!(
            decode_record_plain(&inner),
            Err(StoreError::MalformedContainer(_))
        ));
    }

    #[test]
    fn container_roundtrip_restores_all_records() {
        let salt = [7u8; crypto::SALT_LEN];
        let references = vec![
            CredentialRef::env("env-1", 100),
            CredentialRef::tenant("tenant-9", u64::MAX),
        ];
        let plaintexts = ["aaa", "bbbb"];
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&references, &plaintexts),
            &mut deterministic_rng(),
        )
        .expect("encode");
        let (_params, opened) = decode_container(&bytes, b"pass").expect("decode");
        assert_eq!(opened.len(), 2);
        assert_eq!(opened[0].reference, references[0]);
        assert_eq!(opened[1].reference, references[1]);
        assert_eq!(opened[0].plaintext.as_bytes(), b"aaa");
        assert_eq!(opened[1].plaintext.as_bytes(), b"bbbb");
    }

    #[test]
    fn container_exposes_no_plaintext_or_metadata() {
        let salt = [3u8; crypto::SALT_LEN];
        let reference = CredentialRef::env("env-visible-target", u64::MAX);
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(std::slice::from_ref(&reference), &["credential-plaintext"]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        for needle in [
            b"credential-plaintext".as_slice(),
            b"env-visible-target".as_slice(),
            reference.id().as_uuid().as_bytes(),
            &u64::MAX.to_le_bytes(),
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "container leaks metadata/plaintext"
            );
        }
        // salt 与版本号本身是格式信息，允许明文出现在头部。
        assert!(bytes[..crypto::HEADER_PREFIX_LEN].contains(&3u8));
    }

    #[test]
    fn wrong_passphrase_reports_wrong_passphrase_not_tamper() {
        let salt = [5u8; crypto::SALT_LEN];
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&[CredentialRef::env("e", 1)], &["x"]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        assert!(matches!(
            decode_container(&bytes, b"wrong"),
            Err(StoreError::WrongPassphrase)
        ));
    }

    #[test]
    fn tampered_record_byte_fails_authentication() {
        let salt = [9u8; crypto::SALT_LEN];
        let bytes = &mut encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&[CredentialRef::env("e", 1)], &["payload"]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(matches!(
            decode_container(bytes, b"pass"),
            Err(StoreError::RecordAuthentication)
        ));
    }

    #[test]
    fn tampered_metadata_length_fails_authentication() {
        // 元数据在密文内部，无法在不破坏 AEAD 的前提下改写。
        let salt = [11u8; crypto::SALT_LEN];
        let bytes = &mut encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&[CredentialRef::env("e", 1)], &["payload"]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        let last = bytes.len() - 6;
        bytes[last] ^= 0x01;
        assert!(decode_container(bytes, b"pass").is_err());
    }

    #[test]
    fn record_moved_to_other_file_fails_authentication() {
        let salt_a = [1u8; crypto::SALT_LEN];
        let salt_b = [2u8; crypto::SALT_LEN];
        let bytes_a = encode_container(
            KdfParams::V0,
            &salt_a,
            &key_for(&salt_a),
            &records_for(&[CredentialRef::env("a", 1)], &["secret-a"]),
            &mut deterministic_rng(),
        )
        .expect("encode a");
        // 取 A 的第一条记录（长度字段之后的 sealed 字节），拼进 B 的头部之后。
        let bytes_b = encode_container(
            KdfParams::V0,
            &salt_b,
            &key_for(&salt_b),
            &records_for(&[CredentialRef::env("b", 2)], &["secret-b"]),
            &mut deterministic_rng(),
        )
        .expect("encode b");
        let header_b = decode_header(&bytes_b).expect("header b");
        // 直接构造：B 头部 + 记录数 1 + A 的记录。
        let mut moved = header_b.bytes.clone();
        moved.extend_from_slice(&1u32.to_le_bytes());
        let header_a = decode_header(&bytes_a).expect("header a");
        let mut rest = &bytes_a[header_a.bytes.len()..];
        let count = read_u32(&mut rest, "count").expect("count");
        assert_eq!(count, 1);
        let sealed_len = read_u32(&mut rest, "len").expect("len") as usize;
        let sealed = take(&mut rest, sealed_len, "sealed").expect("sealed");
        moved.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        moved.extend_from_slice(sealed);
        assert!(matches!(
            decode_container(&moved, b"pass"),
            Err(StoreError::RecordAuthentication)
        ));
    }

    #[test]
    fn unknown_schema_version_refuses_to_decrypt() {
        let salt = [4u8; crypto::SALT_LEN];
        let mut bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&[CredentialRef::env("e", 1)], &["payload"]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        // 把头部 schema_version 改成 2（magic 之后 4 字节）。
        bytes[crypto::MAGIC.len()..crypto::MAGIC.len() + 4].copy_from_slice(&2u32.to_le_bytes());
        match decode_container(&bytes, b"pass") {
            Err(StoreError::UnsupportedVersion { found, expected }) => {
                assert_eq!(found, 2);
                assert_eq!(expected, crypto::SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn magic_mismatch_and_truncation_fail_closed() {
        let salt = [6u8; crypto::SALT_LEN];
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&[CredentialRef::env("e", 1)], &["payload"]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 0xFF;
        assert!(matches!(
            decode_container(&wrong_magic, b"pass"),
            Err(StoreError::MalformedContainer(_))
        ));
        // 逐长度截断：任何前缀都不允许解出记录。
        for cut in 1..bytes.len() {
            let err =
                decode_container(&bytes[..cut], b"pass").expect_err("truncated prefix must fail");
            assert!(
                matches!(
                    err,
                    StoreError::MalformedContainer(_) | StoreError::UnsupportedVersion { .. }
                ),
                "cut {cut} gave {err:?}"
            );
        }
        // 尾部多余字节。
        let mut appended = bytes.clone();
        appended.extend_from_slice(b"garbage");
        assert!(matches!(
            decode_container(&appended, b"pass"),
            Err(StoreError::MalformedContainer(_))
        ));
    }

    #[test]
    fn empty_record_count_roundtrips() {
        let salt = [8u8; crypto::SALT_LEN];
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &[],
            &mut deterministic_rng(),
        )
        .expect("encode empty");
        let (_params, opened) = decode_container(&bytes, b"pass").expect("decode empty");
        assert!(opened.is_empty());
    }

    #[test]
    fn zero_length_plaintext_roundtrips() {
        let salt = [10u8; crypto::SALT_LEN];
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&[CredentialRef::env("e", 1)], &[""]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        let (_params, opened) = decode_container(&bytes, b"pass").expect("decode");
        assert_eq!(opened.len(), 1);
        assert!(opened[0].plaintext.as_bytes().is_empty());
    }

    #[test]
    fn utf8_and_large_payloads_roundtrip() {
        let salt = [12u8; crypto::SALT_LEN];
        let big = "x".repeat(100_000);
        let references = vec![CredentialRef::env("环境-Ω", 1), CredentialRef::env("e", 2)];
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&references, &["密码-秘密", &big]),
            &mut deterministic_rng(),
        )
        .expect("encode");
        let (_params, opened) = decode_container(&bytes, b"pass").expect("decode");
        assert_eq!(opened[0].reference, references[0]);
        assert_eq!(opened[0].plaintext.as_bytes(), "密码-秘密".as_bytes());
        assert_eq!(opened[1].plaintext.as_bytes(), big.as_bytes());
    }

    #[test]
    fn target_length_over_u16_is_rejected_before_write() {
        // 作用域目标超过 u16 长度域时不可表示：encode 必须拒绝，
        // 绝不写出被截断长度域的记录（那会解出一个被污染的回引用）。
        let salt = [13u8; crypto::SALT_LEN];
        let reference = CredentialRef::env("z".repeat(MAX_TARGET_LEN + 1), 1);
        assert!(
            !reference.is_valid(),
            "over-long target must already be an invalid reference"
        );
        let err = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(&[reference], &["p"]),
            &mut deterministic_rng(),
        )
        .expect_err("over-long target must be refused");
        assert!(matches!(err, StoreError::InvalidReference), "got {err:?}");

        // 边界：恰好 MAX_TARGET_LEN 的目标可写可读。
        let edge = CredentialRef::env("y".repeat(MAX_TARGET_LEN), 7);
        assert!(edge.is_valid());
        let bytes = encode_container(
            KdfParams::V0,
            &salt,
            &key_for(&salt),
            &records_for(std::slice::from_ref(&edge), &["p"]),
            &mut deterministic_rng(),
        )
        .expect("encode edge");
        let (_params, opened) = decode_container(&bytes, b"pass").expect("decode edge");
        assert_eq!(opened[0].reference, edge);
    }

    #[test]
    fn empty_passphrase_is_rejected_before_derivation() {
        assert!(matches!(
            crypto::derive_key(b"", &[0u8; crypto::SALT_LEN], KdfParams::V0),
            Err(StoreError::WrongPassphrase)
        ));
    }

    #[test]
    fn kdf_params_v0_is_supported() {
        assert!(KdfParams::V0.is_supported());
        let mut other = KdfParams::V0;
        other.key_len = 16;
        assert!(!other.is_supported());
        other.key_len = crypto::KEY_LEN as u32;
        other.schema_version = 2;
        assert!(!other.is_supported());
    }

    #[test]
    fn derive_key_is_deterministic_and_salt_bound() {
        let salt_a = [1u8; crypto::SALT_LEN];
        let salt_b = [2u8; crypto::SALT_LEN];
        let k1 = crypto::derive_key(b"pass", &salt_a, KdfParams::V0).expect("derive");
        let k2 = crypto::derive_key(b"pass", &salt_a, KdfParams::V0).expect("derive");
        let k3 = crypto::derive_key(b"pass", &salt_b, KdfParams::V0).expect("derive");
        assert_eq!(k1.as_slice(), k2.as_slice());
        assert_ne!(k1.as_slice(), k3.as_slice());
        assert_eq!(k1.len(), crypto::KEY_LEN);
    }
}
