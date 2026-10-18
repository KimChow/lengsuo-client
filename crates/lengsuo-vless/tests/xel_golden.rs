//! XEL 记录层金标字节对照：参考 Go 实现（Xray-core d2758a0
//! `proxy/vless/encryption/{common.go,xor.go}` 的记录路径）在 47 上实跑产出的
//! 黄金字节，与 [`lengsuo_vless::xel`] 的编解码逐字节对拍。
//!
//! **这是金标字节对照，不是进程级互通。** 进程级互通要求 mlkem768x25519plus
//! 会话握手（`server.go` 的 `Handshake` 强制 KEM），该握手属明确范围外；且
//! Xray 配置无「只开记录层」入口（`infra/conf/vless.go:97` 的 decryption 解析
//! 强制 `mlkem768x25519plus.<native|xorpub|random>.<seconds>…` 前缀）。本文件
//! 证明的是：在相同密钥材料与上下文字节下，双方记录层产出的线上字节**逐字节
//! 一致**、且 Rust 端能解开参考端产物——加密方向与分帧语义与参考一致。
//!
//! 参考生成器（47 上 `/tmp/xelgold/main.go`，逐字复刻参考记录路径，命令与
//! 输出见 `results/close-vless-xel-handoff.md`）：
//! - AEAD：`NewAEAD(ctx, key, useAES)`（blake3 派生）→ 每条明文封
//!   `头(23 3 3 + BE16(len+16)) + AEAD(body)`，AAD = 5 字节头，nonce 先加后用；
//! - XOR：`blake3.DeriveKey("VLESS", key)` 派生 AES-256-CTR 密钥，只有 5 字节
//!   头被掩蔽，体原样上线（机密性由底层 TLS 提供，与参考同设计）；
//! - AEAD 明文四条：`"first XEL golden record"`、`[0x00]`、`[0xEE; 400]`、
//!   `"tail record \xff\x00\x80"`；XOR 记录三条（裸体，均 ≥17 字节对齐本仓
//!   头部长度下限）：`"xor payload one!!"`、`[0x5A; 17]`、`[0x77; 300]`；
//! - 密钥材料全为测试假值：会话主密钥 32×0xA1、派生上下文 32×"B"（0x42）、
//!   XOR 主密钥 32×0x2A、XOR IV 16×0x11。
//!
//! **密钥注入方式**：参考把 `blake3.DeriveKey(ctx, UnitedKey)` 的产物交给 AEAD；
//! 本仓 `XelKey` 即 AEAD 密钥本身（握手不在范围内），因此 Rust 侧用同一
//! blake3 派生结果作 `XelKey`，派生一致性另由 `blake3_derive_matches_go` 锁定。

use lengsuo_vless::xel::{
    aead::{nonce_for_sequence, XelCipher},
    frame::{RecordFramer, RecordHeader},
    record::{RecordReader, RecordWriter},
    xor::XorMask,
    XelKey,
};

/// AEAD 会话主密钥（UnitedKey 占位，32×0xA1）。
const UNITED_KEY: [u8; 32] = [0xA1; 32];
/// AEAD 派生上下文（32 个 ASCII 'B' = 0x42；Rust blake3 API 要求 &str）。
const DERIVE_CTX: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
/// XOR 主密钥（32×0x2A）与 CTR IV（16×0x11）。
const XOR_KEY: [u8; 32] = [0x2A; 32];
const XOR_IV: [u8; 16] = [0x11; 16];

/// 十六进制向量文件（`tests/vectors/xel_*.hex`，Go 实跑产物原样落盘）。
const HEX_AEAD_AES: &str = include_str!("vectors/xel_aead_aes.hex");
const HEX_AEAD_CHACHA: &str = include_str!("vectors/xel_aead_chacha.hex");
const HEX_AEAD_NONCE_CARRY: &str = include_str!("vectors/xel_aead_nonce_carry.hex");
const HEX_XOR_MASKED: &str = include_str!("vectors/xel_xor_masked.hex");

fn parse_hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(cleaned.len().is_multiple_of(2), "十六进制长度必须为偶数");
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("合法十六进制字节"))
        .collect()
}

/// `blake3.DeriveKey(ctx, UnitedKey)` 的 Rust 侧产物（= 注入 `XelKey` 的 AEAD 密钥）。
fn derived_key() -> XelKey {
    XelKey::new(&blake3::derive_key(DERIVE_CTX, &UNITED_KEY)).unwrap()
}

/// 与参考生成器相同的明文序列（AEAD 四条）。
fn aead_plaintexts() -> Vec<Vec<u8>> {
    vec![
        b"first XEL golden record".to_vec(),
        vec![0x00],
        vec![0xEE; 400],
        b"tail record \xff\x00\x80".to_vec(),
    ]
}

/// 与参考生成器相同的记录序列（XOR 三条，裸体）。
fn xor_bodies() -> Vec<Vec<u8>> {
    vec![
        b"xor payload one!!".to_vec(),
        vec![0x5A; 17],
        vec![0x77; 300],
    ]
}

/// 用本仓 RecordWriter 对相同明文序列封流，返回完整线上字节。
fn rust_seal_stream(cipher: XelCipher, plaintexts: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = RecordWriter::new(cipher, derived_key());
    let mut stream = Vec::new();
    for pt in plaintexts {
        stream.extend_from_slice(&writer.seal(pt).unwrap());
    }
    stream
}

/// 从参考流逐条还原明文。
fn rust_open_stream(cipher: XelCipher, wire: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = RecordReader::new(cipher, derived_key());
    reader.push(wire).expect("参考流必须通过分帧");
    let mut plaintexts = Vec::new();
    while let Some(pt) = reader.next_plaintext().expect("参考记录必须可解") {
        plaintexts.push(pt);
    }
    reader.finish().expect("流必须恰好结束");
    plaintexts
}

/// blake3 派生对齐：`derive_ctx` 向量（Go `blake3.DeriveKey(0x42×32, 0xA1×32)`）。
#[test]
fn blake3_derive_matches_go() {
    let expected = parse_hex("25e1ad434323af1a278d1cb0b602d36fbf7fa3afd8b82e1b31d9281b7e6f82b9");
    assert_eq!(
        blake3::derive_key(DERIVE_CTX, &UNITED_KEY).as_slice(),
        expected.as_slice()
    );
    // XOR 派生（上下文固定 "VLESS"）。
    let expected_vless =
        parse_hex("3f1702b416dc86bb1ed00942a08c6362cd11e56dccce451430985be4011c6af0");
    assert_eq!(
        blake3::derive_key("VLESS", &XOR_KEY).as_slice(),
        expected_vless.as_slice()
    );
}

#[test]
fn rust_encode_matches_go_reference_aes() {
    let go = parse_hex(HEX_AEAD_AES);
    assert_eq!(go.len(), 523, "参考流长度");
    let ours = rust_seal_stream(XelCipher::Aes256Gcm, &aead_plaintexts());
    assert_eq!(ours.len(), go.len(), "Rust 流长度必须与参考一致");
    assert_eq!(ours, go, "AES-256-GCM 记录流必须与参考逐字节一致");
}

#[test]
fn rust_encode_matches_go_reference_chacha() {
    let go = parse_hex(HEX_AEAD_CHACHA);
    assert_eq!(go.len(), 523, "参考流长度");
    let ours = rust_seal_stream(XelCipher::ChaCha20Poly1305, &aead_plaintexts());
    assert_eq!(ours, go, "ChaCha20-Poly1305 记录流必须与参考逐字节一致");
}

#[test]
fn rust_decode_opens_go_reference_streams() {
    let go_aes = parse_hex(HEX_AEAD_AES);
    assert_eq!(
        rust_open_stream(XelCipher::Aes256Gcm, &go_aes),
        aead_plaintexts(),
        "AES 参考流明文逐条还原"
    );
    let go_chacha = parse_hex(HEX_AEAD_CHACHA);
    assert_eq!(
        rust_open_stream(XelCipher::ChaCha20Poly1305, &go_chacha),
        aead_plaintexts(),
        "ChaCha 参考流明文逐条还原"
    );
}

/// nonce 轨道语义：Rust 侧 64 位大端轨道进位与参考 96 位从 byte[11] 起进位在
/// 「序号数值相同 ⇒ nonce 数值相同」上逐点一致（两边都是nonce 的数值递增，
/// 只是存储宽度不同；轨道上的每个 nonce 字节序列一致）。
#[test]
fn nonce_track_matches_reference_carry_semantics() {
    let nonce = nonce_for_sequence(0x100);
    assert_eq!(
        &nonce[4..],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00],
        "0x100 的 64 位轨道"
    );
    assert_eq!(&nonce[..4], &[0x00; 4], "64 位轨道高 32 位恒零");
    assert_eq!(
        &nonce_for_sequence(0xFFFF)[4..],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]
    );
    assert_eq!(
        &nonce_for_sequence(0x1_0000)[4..],
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
        "进位跨过 byte[4]"
    );
}

/// nonce 进位向量：参考生成器把 nonce 快进 255 次后封两条明文
/// （"carry probe 1"/"carry probe 2"）。本仓读取端不可注入起始序号（握手
/// 范围外的会话状态），故只做结构对照：头序列与体长合法；密文轨道一致性
/// 由 encode 用例在序号 1..4 上完整证明、进位语义由 nonce 轨道用例锁定。
#[test]
fn nonce_carry_vector_structure() {
    let go = parse_hex(HEX_AEAD_NONCE_CARRY);
    assert_eq!(go.len(), 68, "参考流长度（两条记录）");
    let mut cursor = 0usize;
    let mut bodies = Vec::new();
    while cursor < go.len() {
        let header = RecordHeader::decode(&go[cursor..]).expect("参考头合法");
        bodies.push(header.body_len());
        cursor += header.record_len();
    }
    assert_eq!(
        bodies,
        vec![13 + 16, 13 + 16],
        "两条记录体长（13 字节明文 + tag）"
    );
}

#[test]
fn xor_mask_unmasks_go_reference_headers() {
    let go = parse_hex(HEX_XOR_MASKED);
    let key = XelKey::new(&XOR_KEY).unwrap();
    let mut mask = XorMask::new(&key, &XOR_IV, &key, &XOR_IV).expect("IV 合法");
    let mut plain = go.clone();
    mask.unmask_incoming(&mut plain).expect("参考流必须可还原");
    let mut cursor = 0usize;
    let mut bodies = Vec::new();
    while cursor < plain.len() {
        let header = RecordHeader::decode(&plain[cursor..]).expect("还原后的头必须合法");
        let start = cursor + 5;
        bodies.push(plain[start..start + header.body_len()].to_vec());
        cursor += header.record_len();
    }
    assert_eq!(bodies, xor_bodies(), "三条记录体逐字节还原");
}

#[test]
fn rust_xor_mask_matches_go_reference_bytes() {
    // Rust 侧对相同记录序列做掩蔽，输出必须与参考流逐字节一致。
    let mut stream = Vec::new();
    for body in xor_bodies() {
        let header = RecordHeader::new(body.len()).unwrap().encode();
        stream.extend_from_slice(&header);
        stream.extend_from_slice(&body);
    }
    let key = XelKey::new(&XOR_KEY).unwrap();
    let mut mask = XorMask::new(&key, &XOR_IV, &key, &XOR_IV).unwrap();
    mask.mask_outgoing(&mut stream).unwrap();
    let go = parse_hex(HEX_XOR_MASKED);
    assert_eq!(stream.len(), go.len(), "掩蔽流长度必须一致");
    assert_eq!(stream, go, "XOR 掩蔽流必须与参考逐字节一致");
}

/// 分帧器对参考 AES 流的渐进喂入：任意 7 字节分块都必须产出同样的记录序列。
#[test]
fn framer_reassembles_go_stream_at_arbitrary_chunks() {
    let go = parse_hex(HEX_AEAD_AES);
    let mut framer = RecordFramer::new();
    let mut records = Vec::new();
    for chunk in go.chunks(7) {
        framer.push(chunk).expect("参考流分块合法");
        while let Some(record) = framer.next_record().unwrap() {
            records.push(record);
        }
    }
    framer.finish().expect("无残字节");
    assert_eq!(records.len(), 4, "四条记录");
    for record in &records {
        let header = RecordHeader::decode(record).expect("记录头合法");
        assert_eq!(record.len(), header.record_len(), "记录长度自洽");
    }
}

/// 负例：错钥解密必须失败并 poison（锁定 ctx/密钥参与派生的敏感性）。
#[test]
fn wrong_key_fails_decryption_and_poisons() {
    let mut writer = RecordWriter::new(XelCipher::Aes256Gcm, derived_key());
    let wire = writer.seal(b"context sensitivity probe").unwrap();
    let mut reader = RecordReader::new(XelCipher::Aes256Gcm, XelKey::new(&[0xA2; 32]).unwrap());
    reader.push(&wire).unwrap();
    assert!(reader.next_plaintext().is_err(), "错钥必须解密失败");
    assert!(reader.is_poisoned(), "认证失败后必须 poison");
}
