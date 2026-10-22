//! 逐字节布局测试：把契约的每一个字节位置都钉死。
//!
//! ⛔ 这些期望值是**写死在源码里的常量**（不是从外部脚本生成的），
//! 所以「实现和期望同时错」不会互相掩盖。

mod support;

use lengsuo_credential_crypto::attestation;
use lengsuo_credential_crypto::authdata;
use lengsuo_credential_crypto::cose;
use lengsuo_credential_crypto::flags;
use lengsuo_credential_crypto::keypair;
use support::{FIXED_CREDENTIAL_ID, FIXED_PKCS8, FIXED_RP_ID, FIXED_X, FIXED_Y};

/// 契约 §2.2 的 COSE_Key 固定模板。
const COSE_KEY_TEMPLATE: [u8; 77] = [
    // [165, 1, 2, 3, 38, 32, 1, 33, 88, 32] (10B)
    165, 1, 2, 3, 38, 32, 1, 33, 88, 32, //
    // x: 32 字节
    0x79, 0x89, 0x53, 0xe7, 0xe8, 0x13, 0x4f, 0xdf, 0x3c, 0x13, 0x9f, 0x63, 0xd3, 0xfb, 0xcc, 0xc2,
    0x52, 0xa2, 0x8b, 0x6c, 0xa5, 0x05, 0x9e, 0x61, 0x83, 0x74, 0xa8, 0x12, 0x31, 0x24, 0x0f, 0x3f,
    // [34, 88, 32] (3B)
    34, 88, 32, //
    // y: 32 字节
    0xc8, 0x32, 0x67, 0xae, 0xc7, 0x25, 0xe1, 0x8b, 0x66, 0x17, 0x6c, 0x36, 0x85, 0xd1, 0x25, 0x72,
    0x01, 0xa6, 0x70, 0x33, 0x81, 0x95, 0x85, 0xa2, 0x2a, 0x29, 0x63, 0x50, 0x15, 0x9a, 0xe7, 0x0b,
];

/// 契约 §1.3：credential_id 是 16 字节原始字节（不是 base64 变体）。
const CRED_ID_LEN: u16 = 16;

#[test]
fn cose_key_is_exactly_77_bytes_with_the_contract_template() {
    let key = cose::cose_key(&FIXED_X, &FIXED_Y);
    assert_eq!(key.len(), 77);
    assert_eq!(key.len(), cose::COSE_KEY_LEN);
    assert_eq!(key, COSE_KEY_TEMPLATE);
    // 逐字节：头 10 字节。
    assert_eq!(
        &key[0..10],
        &[165, 1, 2, 3, 38, 32, 1, 33, 88, 32],
        "COSE_Key 头必须是契约的 10 字节"
    );
    // 逐字节：x 坐标。
    assert_eq!(&key[10..42], &FIXED_X);
    // 逐字节：y 坐标前的 3 字节头。
    assert_eq!(&key[42..45], &[34, 88, 32]);
    // 逐字节：y 坐标。
    assert_eq!(&key[45..77], &FIXED_Y);
}

#[test]
fn cose_key_coordinates_come_from_the_uncompressed_point() {
    let pair = keypair::KeyPair::from_pkcs8(FIXED_PKCS8).unwrap();
    assert_eq!(pair.x(), FIXED_X);
    assert_eq!(pair.y(), FIXED_Y);
    assert_eq!(pair.public_point()[0], 0x04);
    assert_eq!(pair.public_point().len(), 65);
    // COSE_Key 的 x/y 就是未压缩点的第 1..33 / 33..65 字节。
    let key = cose::cose_key(&pair.x(), &pair.y());
    assert_eq!(&key[10..42], &pair.public_point()[1..33]);
    assert_eq!(&key[45..77], &pair.public_point()[33..65]);
}

#[test]
fn auth_data_segments_are_at_the_contract_offsets() {
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let key = cose::cose_key(&FIXED_X, &FIXED_Y);
    let data = authdata::build(
        &rp_id_hash,
        flags::MANAGED_DEFAULT,
        0x0000_0001,
        &FIXED_CREDENTIAL_ID,
        &key,
    )
    .unwrap();

    // 总长 = 32 + 1 + 4 + 16 + 2 + 16 + 77 = 148。
    assert_eq!(data.len(), 148);
    assert_eq!(data.len(), authdata::FIXED_LEN + CRED_ID_LEN as usize);

    // rpIdHash(32)：SHA-256(rp_id)。
    assert_eq!(&data[0..32], &rp_id_hash);
    // flags(1) = 0x45。
    assert_eq!(data[32], 0x45);
    // signCount(4, 大端)。
    assert_eq!(&data[33..37], &[0x00, 0x00, 0x00, 0x01]);
    // aaguid(16) 全零。
    assert_eq!(&data[37..53], &[0u8; 16]);
    // credIdLen(2, 大端) = 16。
    assert_eq!(&data[53..55], &[0x00, 0x10]);
    // credId(16)。
    assert_eq!(&data[55..71], &FIXED_CREDENTIAL_ID);
    // COSE_Key(77)。
    assert_eq!(&data[71..148], &COSE_KEY_TEMPLATE);
}

#[test]
fn auth_data_aaguid_is_all_zero() {
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let key = cose::cose_key(&FIXED_X, &FIXED_Y);
    let data = authdata::build(
        &rp_id_hash,
        flags::MANAGED_DEFAULT,
        0,
        &FIXED_CREDENTIAL_ID,
        &key,
    )
    .unwrap();
    assert_eq!(authdata::aaguid_of(&data).unwrap(), [0u8; 16]);
    assert!(data[37..53].iter().all(|b| *b == 0));
}

#[test]
fn flags_defaults_and_bit_values_are_pinned() {
    assert_eq!(flags::MANAGED_DEFAULT, 0x45);
    assert_eq!(flags::FLAG_UP, 0x01);
    assert_eq!(flags::FLAG_UV, 0x04);
    assert_eq!(flags::FLAG_BE, 0x08);
    assert_eq!(flags::FLAG_BS, 0x10);
    assert_eq!(flags::FLAG_AT, 0x40);
    assert_eq!(flags::FLAG_ED, 0x80);
    // AT 与 ED 必须不同（不能都写 0x40）。
    assert_ne!(flags::FLAG_AT, flags::FLAG_ED);
}

#[test]
fn sign_count_is_big_endian_and_increments() {
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let key = cose::cose_key(&FIXED_X, &FIXED_Y);
    for (counter, expected) in [
        (0u32, [0x00, 0x00, 0x00, 0x00]),
        (1, [0x00, 0x00, 0x00, 0x01]),
        (256, [0x00, 0x00, 0x01, 0x00]),
        (0x0102_0304, [0x01, 0x02, 0x03, 0x04]),
    ] {
        let data = authdata::build(
            &rp_id_hash,
            flags::MANAGED_DEFAULT,
            counter,
            &FIXED_CREDENTIAL_ID,
            &key,
        )
        .unwrap();
        assert_eq!(&data[33..37], &expected, "signCount 必须是��端");
    }
}

#[test]
fn attestation_object_cbor_bytes_are_pinned() {
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let key = cose::cose_key(&FIXED_X, &FIXED_Y);
    let auth = authdata::build(
        &rp_id_hash,
        flags::MANAGED_DEFAULT,
        1,
        &FIXED_CREDENTIAL_ID,
        &key,
    )
    .unwrap();
    let obj = attestation::build(&auth).unwrap();

    // 逐字节钉死 CBOR 头。
    assert_eq!(obj[0], 0xa3, "顶层必须是 map(3)");
    assert_eq!(&obj[1..5], b"\x63fmt", "\"fmt\" 文本键");
    assert_eq!(&obj[5..10], b"\x64none", "\"none\" 文本值");
    assert_eq!(&obj[10..18], b"\x67attStmt", "\"attStmt\" 文本键");
    assert_eq!(obj[18], 0xa0, "attStmt 必须是空 map");
    assert_eq!(&obj[19..28], b"\x68authData", "\"authData\" 文本键");
    // ⚠️ authData 长 148 > 24 ⇒ 必须用 0x58 + 1 字节长度。
    assert_eq!(obj[28], 0x58, "长 bytes 必须走 0x58 不定长头");
    assert_eq!(obj[29], 148, "长度字节必须是 148");
    assert_eq!(obj.len(), 30 + 148);
    assert_eq!(&obj[30..], &auth[..]);
}

#[test]
fn attestation_object_uses_the_none_format_and_empty_att_stmt() {
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let key = cose::cose_key(&FIXED_X, &FIXED_Y);
    let auth = authdata::build(
        &rp_id_hash,
        flags::MANAGED_DEFAULT,
        1,
        &FIXED_CREDENTIAL_ID,
        &key,
    )
    .unwrap();
    let obj = attestation::build(&auth).unwrap();
    assert!(obj.windows(4).any(|w| w == b"none"));
    assert_eq!(attestation::auth_data_of(&obj).unwrap(), auth.as_slice());
}
