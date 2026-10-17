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
    // 规格演进：版本字段已被 verifier AAD 认证绑定，字节篡改会先撞认证失败；
    // 版本门只对「认证通过的未识别版本」触发 ⇒ 直接以版本 2 编码（其余参数同 V0）。
    let bytes = encode_container(
        KdfParams {
            schema_version: 2,
            iterations: 1,
            key_len: 32,
        },
        &salt,
        &crypto::derive_key(
            b"pass",
            &salt,
            KdfParams {
                schema_version: 2,
                iterations: 1,
                key_len: 32,
            },
        )
        .expect("derive"),
        &records_for(&[CredentialRef::env("e", 1)], &["payload"]),
        &mut deterministic_rng(),
    )
    .expect("encode");
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
        let err = decode_container(&bytes[..cut], b"pass").expect_err("truncated prefix must fail");
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
