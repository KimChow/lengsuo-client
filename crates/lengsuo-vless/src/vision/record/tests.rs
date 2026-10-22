//! Vision 记录层（AEAD）的单元测试（从父模块拆出以保持单文件 ≤400 行软约束）。
//!
//! 断言与拆分前逐字一致，未增删任何用例。

use super::*;

const CTX: &str = "vision-record-test-context";
const KEY: [u8; 32] = [0xA1; 32];

#[test]
fn length_and_header_roundtrip() {
    assert_eq!(encode_length(0x1234), [0x12, 0x34]);
    assert_eq!(decode_length(&[0x12, 0x34]), 0x1234);

    let mut header = [0u8; HEADER_LEN];
    encode_header(&mut header, 17);
    assert_eq!(header, [23, 3, 3, 0, 17]);
    assert_eq!(decode_header(&header).unwrap(), 17);

    let mut max = [0u8; HEADER_LEN];
    encode_header(&mut max, MAX_BODY_LEN);
    assert_eq!(&max[..3], &[23, 3, 3]);
    assert_eq!(decode_header(&max).unwrap(), MAX_BODY_LEN);
}

#[test]
fn header_rejects_bad_magic_and_bounds() {
    let mut header = [0u8; HEADER_LEN];
    encode_header(&mut header, 20);
    header[0] = 22;
    assert_eq!(decode_header(&header), Err(Error::InvalidHeader));
    header = [23, 3, 3, 0, 16];
    assert_eq!(decode_header(&header), Err(Error::InvalidHeader)); // 16 < 17
    header = [23, 3, 3, 0x41, 0x01]; // 16641
    assert_eq!(decode_header(&header), Err(Error::InvalidHeader));
}

#[test]
fn nonce_increments_big_endian() {
    let mut nonce = [0u8; NONCE_LEN];
    increase_nonce(&mut nonce);
    assert_eq!(nonce[11], 1);
    let mut carry = [0u8; NONCE_LEN];
    carry[11] = 0xFF;
    increase_nonce(&mut carry);
    assert_eq!(&carry[10..], &[1, 0]);
}

/// `Aead::new(ctx, key)` 内部走 `blake3::derive_key`（而非注入已派生密钥），
/// 且派生结果与 Go `blake3.DeriveKey` 黄金向量一致（同 `xel_golden.rs` 实跑值）。
#[test]
fn new_aead_derives_key_from_context_and_material() {
    // Go 实跑：blake3.DeriveKey(32×0x42, 32×0xA1) == 25e1ad…82b9。
    let expected = [
        0x25, 0xe1, 0xad, 0x43, 0x43, 0x23, 0xaf, 0x1a, 0x27, 0x8d, 0x1c, 0xb0, 0xb6, 0x02, 0xd3,
        0x6f, 0xbf, 0x7f, 0xa3, 0xaf, 0xd8, 0xb8, 0x2e, 0x1b, 0x31, 0xd9, 0x28, 0x1b, 0x7e, 0x6f,
        0x82, 0xb9,
    ];
    let ctx = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    assert_eq!(blake3::derive_key(ctx, &[0xA1u8; 32]), expected);
    // 同一派生语境下加密可被对端独立实例解密（跨实例一致性，非注入共享）。
    let mut sender = Aead::new(ctx, &[0xA1u8; 32], Cipher::Aes256Gcm);
    let mut receiver = Aead::new(ctx, &[0xA1u8; 32], Cipher::Aes256Gcm);
    let ct = sender.seal(None, b"probe", b"hdr").unwrap();
    assert_eq!(receiver.open(None, &ct, b"hdr").unwrap(), b"probe");
}

#[test]
fn record_writer_reader_roundtrip_at_every_split() {
    // 写侧按参考把 9000 字节切成 8192 + 808 两条记录，读侧逐「记录」返回明文。
    let payloads: Vec<Vec<u8>> = vec![
        b"first vision record".to_vec(),
        vec![7u8; 1],
        vec![0xEEu8; 400],
        vec![0xCDu8; 9000],
    ];
    let expected: Vec<Vec<u8>> = vec![
        b"first vision record".to_vec(),
        vec![7u8; 1],
        vec![0xEEu8; 400],
        vec![0xCDu8; 8192],
        vec![0xCDu8; 808],
    ];
    for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
        let mut writer = RecordWriter::new(CTX, &KEY, cipher);
        let mut wire = Vec::new();
        for payload in &payloads {
            wire.extend_from_slice(&writer.seal(payload).unwrap());
        }
        for step in [1usize, 2, 5, 22, 40, wire.len()] {
            let mut reader = RecordReader::new(CTX, &KEY, cipher);
            let mut got = Vec::new();
            for chunk in wire.chunks(step) {
                reader.push(chunk).unwrap();
                while let Some(plain) = reader.next_plaintext().unwrap() {
                    got.push(plain);
                }
            }
            reader.finish().unwrap();
            assert_eq!(got, expected, "{cipher:?} 分块步长 {step}");
        }
    }
}

#[test]
fn record_body_is_header_and_tag_length() {
    let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
    let record = writer.seal(b"payload").unwrap();
    assert_eq!(record.len(), HEADER_LEN + 7 + TAG_LEN);
    assert_eq!(&record[..3], &[23, 3, 3]);
    assert_eq!(&record[3..5], &[0, 23]); // 7 + 16
}

#[test]
fn tampered_header_breaks_authentication() {
    let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
    let wire = writer.seal(b"payload").unwrap();
    let mut reader = RecordReader::new(CTX, &KEY, Cipher::Aes256Gcm);
    let mut tampered = wire.clone();
    tampered[4] ^= 0x01;
    reader.push(&tampered).unwrap();
    let outcome = reader.next_plaintext();
    assert!(
        matches!(outcome, Err(Error::InvalidHeader) | Err(Error::AuthFailed)),
        "头部改动必须失败：{outcome:?}"
    );
    assert!(reader.is_poisoned());
}

#[test]
fn truncated_stream_poisons_on_finish() {
    let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
    let wire = writer.seal(b"record body that is long enough").unwrap();
    let mut reader = RecordReader::new(CTX, &KEY, Cipher::Aes256Gcm);
    reader.push(&wire[..wire.len() - 3]).unwrap();
    assert!(reader.next_plaintext().unwrap().is_none());
    assert!(matches!(reader.finish(), Err(Error::Truncated { .. })));
    assert!(reader.is_poisoned());
}

#[test]
fn debug_output_never_contains_key_bytes() {
    let aead = Aead::new(CTX, &[0xA7u8; 32], Cipher::Aes256Gcm);
    let printed = format!("{aead:?}");
    assert!(!printed.contains("167"), "Debug 泄露密钥字节：{printed}");
}
