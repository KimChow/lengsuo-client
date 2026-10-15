//! 固定 salt 的确定性向量测试（只存在于 `cfg(test)`，生产 `seal` 只用随机 salt）。
//!
//! 向量由 tools/gen_ss_udp_vectors.py 实际生成；使用 hashlib（MD5）、hmac（HKDF-SHA1）与
//! cryptography（AES-GCM / ChaCha20-Poly1305；XChaCha20-Poly1305 按
//! HChaCha20 + ChaCha20-Poly1305 组合，HChaCha20 先经 draft-irtf-cfrg-xchacha-03 §2.2.1
//! 测试向量自检）独立算出，用来交叉校验本实现的密钥派生与单包封装。
//!
//! 这些只是**有限原语的辅助样本**：不是参考实现的实跑抓包，也不构成与任何
//! 参考实现的互通证明。互通验收状态见 `docs/shadowsocks-status.md`。

use super::*;
use ss_core::kdf::evp_bytes_to_key;

/// 测试专用假口令，不代表任何真实凭据。
pub(super) const PASSWORD: &str = "passw0rd";

pub(super) const PAYLOAD: &[u8] = b"udp-payload-0123456789";

pub(super) fn v4() -> TargetAddr {
    TargetAddr::V4([192, 0, 2, 1], 443)
}

pub(super) fn domain() -> TargetAddr {
    TargetAddr::Domain("example.invalid".into(), 53)
}

pub(super) fn v6() -> TargetAddr {
    TargetAddr::V6(
        [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
        ],
        8080,
    )
}

/// 固定 salt：`0x00, 0x01, …`，长度取套件 `salt_len()`（AES-128-GCM 16，其余 32）。
pub(super) fn rising_salt(len: usize) -> Vec<u8> {
    (0..len as u8).collect()
}

/// 十六进制解码（测试内自带，避免为本 crate 引入 hex 依赖）。
pub(super) fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex 字面量长度必须为偶数");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex 字面量必须合法"))
        .collect()
}

pub(super) fn suite_of(name: &str) -> CipherSuite {
    CipherSuite::from_name(name).expect("向量里的套件名必须已知")
}

/// 全部四类支持的套件。
pub(super) const SUITE_NAMES: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
];

/// 一条向量：(套件名, 目标标签, 期望包总长, 期望包字节 hex)。
type Vector = (&'static str, &'static str, usize, &'static str);

const VECTORS: &[Vector] = &[
    ("aes-128-gcm", "v4", 61, "000102030405060708090a0b0c0d0e0f87fcee516428f75c271cc4019bc236aafe70ce23a2e590f799ce6de187950d4e888a0c1282c61a1b77e89af51b"),
    ("aes-128-gcm", "domain", 73, "000102030405060708090a0b0c0d0e0f85338b2b04443c452642801f8cda36acfb14d666f7a78eb3cd8136b6df353a86598b9bba6cd5052bb3a86c8875484c16c5479abc19b3a15991"),
    ("aes-128-gcm", "v6", 73, "000102030405060708090a0b0c0d0e0f821cef5edd294c29436ce971fabb5ac49f0b7366f7a78eb3cd8136b6df353a86598b9bba6cd5052bb3694377d990b1820b0dbd0c8a9a7c2fdd"),
    ("aes-256-gcm", "v4", 77, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0bf06f8de3402b8c646176929ab01c99287564ed5017f3d1756082029e01ff8488665149f4edbb212ecca27e71"),
    ("aes-256-gcm", "domain", 89, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f093f0af7832ce095653f328c8da81c9f2d117ca80555ed95212fd955c683d1ce193ff4d8e82525b291f00830e6c9880452d5a96eea8d6dc005"),
    ("aes-256-gcm", "v6", 89, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0e106e825a4190f900115be2fbc970f7490ed9a80555ed95212fd955c683d1ce193ff4d8e82525b291f96ec722d4eac8eedcf144fb7d6145c8"),
    ("chacha20-ietf-poly1305", "v4", 77, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f4db19a1628fe590bdc1685bdd1553879fecfdaab7166a4b28ee4808ff0d2907d096fafcbe6ed423a3b8efc84cc"),
    ("chacha20-ietf-poly1305", "domain", 89, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f4f7eff6c48929212dd48c1a3c64d387ffbabc2ee2424baf6daabdbd8a860a5f286b8afd319226fb99e81f0ea6eafefbe598a0958f96086fcfb"),
    ("chacha20-ietf-poly1305", "v6", 89, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f48519b1991ffe27eb866a8cdb02c54179fb467ee2424baf6daabdbd8a860a5f286b8afd319226fb99e7284b6df42c1a285eef1f29ca782b18d"),
    ("xchacha20-ietf-poly1305", "v4", 77, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fdde6109b21e8993891d037eafc309e4fed5dda6a5c98b1f895545510aa6e23194636f0506f37c421785968e932"),
    ("xchacha20-ietf-poly1305", "domain", 89, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fdf2975e141845221908e73f4eb289e49e839c22f09daafbcc11b0e47f22011b56ea38e4a504442739ab361fd7123b5b15de43f5b58d3c556cf"),
    ("xchacha20-ietf-poly1305", "v6", 89, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fd806119498e9224df5a01a9a9d49f2218c26672f09daafbcc11b0e47f22011b56ea38e4a504442739a43ad133e5354eee51b6beae6fd0a0951"),
];

fn target_of(label: &str) -> TargetAddr {
    match label {
        "v4" => v4(),
        "domain" => domain(),
        "v6" => v6(),
        other => panic!("未知目标标签 {other}"),
    }
}

/// 用测试假口令构造编解码器（构造失败即 panic，向量本身要求成功）。
pub(super) fn codec(suite: CipherSuite) -> UdpCodec {
    UdpCodec::new(suite, PASSWORD.as_bytes()).expect("测试假口令应能构造编解码器")
}

/// 四套件 × IPv4/域名/IPv6：固定 salt 逐字节比对，并确认可解回同一语义。
#[test]
fn fixed_salt_seal_matches_independent_vectors() {
    for (name, label, want_len, want_hex) in VECTORS {
        let suite = suite_of(name);
        let codec = codec(suite);
        let salt = rising_salt(suite.salt_len());
        let got = codec
            .seal_with_salt(&salt, &target_of(label), PAYLOAD)
            .expect("固定 salt 封装不应失败");
        assert_eq!(got.len(), *want_len, "{name}/{label} 包总长不符");
        assert_eq!(
            got,
            unhex(want_hex),
            "{name}/{label} 包字节与独立辅助向量不符"
        );

        let (target, payload) = codec.open(&got).unwrap();
        assert_eq!(target, target_of(label), "{name}/{label} 目标地址不符");
        assert_eq!(payload, PAYLOAD, "{name}/{label} 载荷不符");
    }
}

/// 派生长度对应关系：AES-128-GCM 用 16 字节 salt/密钥，其余三套用 32 字节。
#[test]
fn master_key_and_salt_lengths_follow_suite() {
    for name in SUITE_NAMES {
        let suite = suite_of(name);
        let codec = codec(suite);
        assert_eq!(codec.salt_len(), suite.salt_len());
        assert_eq!(codec.suite(), suite);
        // 子模块可访问私有字段：主密钥长度必须等于套件密钥长度。
        assert_eq!(codec.key.raw().len(), suite.key_len());
        // 主密钥由 EVP_BytesToKey(MD5) 派生，与 ss-core 的已知向量一致。
        assert_eq!(
            codec.key.raw(),
            evp_bytes_to_key(PASSWORD.as_bytes(), suite.key_len())
        );
    }
}

/// salt 长度必须与套件一致：错误长度在写出任何字节前失败。
#[test]
fn wrong_salt_length_is_rejected() {
    for name in SUITE_NAMES {
        let suite = suite_of(name);
        let codec = codec(suite);
        let short = rising_salt(suite.salt_len() - 1);
        let err = codec
            .seal_with_salt(&short, &v4(), PAYLOAD)
            .expect_err("短 salt 必须被拒绝");
        assert!(
            matches!(err, Error::KeyLength(KeyError::SaltLength { want, got })
                if want == suite.salt_len() && got == want - 1),
            "{name} 的 salt 长度错误信息不符：{err:?}"
        );
        let long = rising_salt(suite.salt_len() + 1);
        assert!(matches!(
            codec.seal_with_salt(&long, &v4(), PAYLOAD),
            Err(Error::KeyLength(KeyError::SaltLength { .. }))
        ));
    }
}

/// 空口令没有可派生的主密钥，构造期就失败，不留半构造状态。
#[test]
fn empty_password_is_rejected_at_construction() {
    for name in SUITE_NAMES {
        // UdpCodec 故意没有 Debug（主密钥不得进入输出），因此逐臂匹配而非 expect_err。
        match UdpCodec::new(suite_of(name), b"") {
            Ok(_) => panic!("{name} 的空口令竟被接受"),
            Err(err) => assert!(
                matches!(err, Error::KeyLength(KeyError::EmptyPassword { key_len })
                    if key_len == suite_of(name).key_len()),
                "{name} 的空口令错误类型不符：{err}"
            ),
        }
    }
}

/// `seal` 每包取新随机 salt，并为新 salt 建新 AEAD 上下文：
/// 同一目标与载荷连封两次必然不同，salt 段也必然不同。
#[test]
fn each_packet_gets_a_fresh_random_salt() {
    for name in SUITE_NAMES {
        let suite = suite_of(name);
        let codec = codec(suite);
        let first = codec.seal(&v4(), PAYLOAD).unwrap();
        let second = codec.seal(&v4(), PAYLOAD).unwrap();
        let salt_len = suite.salt_len();
        assert_ne!(
            &first[..salt_len],
            &second[..salt_len],
            "{name} 两个包的 salt 不应相同"
        );
        assert_ne!(first, second, "{name} 重复封装不应产出相同字节");
        // 固定 salt 下同一 (subkey, nonce=全 0) 会产出相同字节，正说明跨包
        // 必须换 salt；本实现的 seal 从不复用 salt。
        let salt = rising_salt(salt_len);
        assert_eq!(
            codec.seal_with_salt(&salt, &v4(), PAYLOAD).unwrap(),
            codec.seal_with_salt(&salt, &v4(), PAYLOAD).unwrap(),
        );
    }
}
