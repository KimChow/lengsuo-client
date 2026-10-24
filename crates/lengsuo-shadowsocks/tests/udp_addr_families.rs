//! W4 核验卡：地址族（域名 / IPv6）在 **UDP 整包读取**上的回归锁。
//!
//! UDP 读端 = 认证后明文首字节 `& 0x0F` 再 `TargetAddr::decode`
//! （`src/udp.rs` `decode_plaintext` → `ss-core/src/target.rs:60-118`）。
//! 整包在内存里，没有「跨 chunk」：任何字段不满 ⇒ `TooShort` 包在
//! `UdpError::Address` 里拒绝（fail-closed，无部分状态）。
//!
//! 拒绝路径的线上字节用固定 salt 手工构造（`UdpCodec::seal` 只编码合法目标，
//! 造不出非法地址字节），做法与 `tests/udp_atyp_mask.rs` 一致。
//!
//! 字符集注记（本卡实测复核，证据见 `docs/shadowsocks-status.md` 本卡小节）：
//! 参考 `addrParser` 为 TCP/UDP 共用，域名分支无条件 `isValidDomain`
//! （参考仓 `common/protocol/address.go:219-221`），因此参考在 **UDP 上同样
//! 拒绝**非法字符域名；本端 UDP 路径仅拒 NUL 与非 UTF-8
//! （`ss-core/src/target.rs:95-100`，有意偏离 V-S3）。本文件按**现状**锁定
//! 该偏离（含 `/` 域名被接受），不冒充 fail-closed，交主理人定夺是否对齐。

use lengsuo_shadowsocks::udp::{Error, UdpCodec};
use ss_core::crypto::{CipherSuite, SessionAead};
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};
use ss_core::target::TargetAddr;

const PASSWORD: &str = "addr-family-fixed-vector-password";
const SALT: [u8; 16] = [
    0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn codec() -> UdpCodec {
    UdpCodec::new(CipherSuite::Aes128Gcm, PASSWORD.as_bytes()).expect("假口令应能构造编解码器")
}

/// 用固定 salt 按参考线格式封装：salt ‖ AEAD(plaintext)。
fn seal_fixed(plaintext: &[u8]) -> Vec<u8> {
    let suite = CipherSuite::Aes128Gcm;
    let master = evp_bytes_to_key(PASSWORD.as_bytes(), suite.key_len());
    let subkey = hkdf_sha1_subkey(&master, &SALT, suite.key_len());
    let mut aead = SessionAead::new(suite, subkey);
    let mut packet = SALT.to_vec();
    packet.extend_from_slice(&aead.seal(plaintext).expect("固定向量封装不应失败"));
    packet
}

#[test]
fn domain_length_255_roundtrips() {
    let target = TargetAddr::Domain("a".repeat(255), 443);
    let packet = codec()
        .seal(&target, b"payload")
        .expect("255 长度域名应可封装");
    let (got, payload) = codec().open(&packet).expect("应能解封");
    assert_eq!(got, target);
    assert_eq!(payload, b"payload");
}

#[test]
fn domain_empty_is_rejected() {
    let plaintext = [0x03, 0x00, 0x01, 0xBB];
    let err = codec().open(&seal_fixed(&plaintext)).unwrap_err();
    assert!(
        matches!(err, Error::Address(ss_core::Error::InvalidLength(0))),
        "空域名必须拒绝：{err:?}"
    );
}

#[test]
fn domain_with_nul_is_rejected() {
    let plaintext = [0x03, 3, b'a', 0, b'b', 0x01, 0xBB];
    let err = codec().open(&seal_fixed(&plaintext)).unwrap_err();
    assert!(
        matches!(err, Error::Address(ss_core::Error::InvalidLength(3))),
        "{err:?}"
    );
}

#[test]
fn domain_non_utf8_is_rejected() {
    let plaintext = [0x03, 2, 0xFF, 0xFE, 0x01, 0xBB];
    let err = codec().open(&seal_fixed(&plaintext)).unwrap_err();
    assert!(
        matches!(err, Error::Address(ss_core::Error::InvalidLength(2))),
        "{err:?}"
    );
}

#[test]
fn udp_domain_charset_is_looser_than_reference_v_s3() {
    // 参考 address.go:219 无条件 isValidDomain ⇒ `a/b.c` 在参考 TCP 与 UDP
    // 上都会被拒；本端 UDP 只拒 NUL/非 UTF-8（V-S3 有意偏离）⇒ 接受。
    // 本用例锁定**现状**而非宣称 fail-closed；对齐与否由主理人定夺。
    let plaintext = [0x03, 5, b'a', b'/', b'b', b'.', b'c', 0x01, 0xBB];
    let (target, payload) = codec()
        .open(&seal_fixed(&plaintext))
        .expect("现状（V-S3）：非法字符域名在 UDP 被接受");
    assert_eq!(target, TargetAddr::Domain("a/b.c".into(), 443));
    assert!(payload.is_empty());
}

#[test]
fn unknown_and_masked_unknown_atyp_are_rejected() {
    let direct = [0x07, 0x01, 0xBB];
    let err = codec().open(&seal_fixed(&direct)).unwrap_err();
    assert!(
        matches!(err, Error::Address(ss_core::Error::InvalidAddressType(7))),
        "映射外族字节必须拒绝：{err:?}"
    );
    // 0x17 掩码后 = 0x07：掩码只去标志位，不改变「映射外 ⇒ 拒绝」。
    let flagged = [0x17, 0x01, 0xBB];
    let err = codec().open(&seal_fixed(&flagged)).unwrap_err();
    assert!(
        matches!(err, Error::Address(ss_core::Error::InvalidAddressType(7))),
        "{err:?}"
    );
    // 0x12 掩码后 = 0x02：合法掩码、但映射表无 0x02 ⇒ 仍拒绝。
    let mapped_out = [0x12, 0x01, 0xBB];
    let err = codec().open(&seal_fixed(&mapped_out)).unwrap_err();
    assert!(
        matches!(err, Error::Address(ss_core::Error::InvalidAddressType(2))),
        "{err:?}"
    );
}

#[test]
fn ipv6_compressed_forms_roundtrip() {
    let localhost = std::net::Ipv6Addr::LOCALHOST.octets();
    let doc = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 2001:db8::1
    ];
    for (ip, port) in [(localhost, 53u16), (doc, 8080)] {
        let target = TargetAddr::V6(ip, port);
        let packet = codec().seal(&target, b"v6").expect("应可封装");
        let (got, payload) = codec().open(&packet).expect("应能解封");
        assert_eq!(got, target);
        assert_eq!(payload, b"v6");
    }
}

#[test]
fn ipv6_truncated_variants_are_rejected() {
    let cases: [(&str, Vec<u8>, usize, usize); 3] = [
        (
            "16 字节体断半",
            {
                let mut p = vec![0x04];
                p.extend_from_slice(&[0u8; 15]);
                p
            },
            19,
            16,
        ),
        ("只有族字节", vec![0x04], 19, 1),
        (
            "端口断半",
            {
                let mut p = vec![0x04];
                p.extend_from_slice(&[0u8; 16]);
                p.push(0x00);
                p
            },
            19,
            18,
        ),
    ];
    for (name, plaintext, need, got) in cases {
        let err = codec().open(&seal_fixed(&plaintext)).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Address(ss_core::Error::TooShort { need: n, got: g }) if n == need && g == got
            ),
            "{name} 必须按 TooShort({need}, {got}) 拒绝：{err:?}"
        );
    }
}

#[test]
fn domain_port_truncated_is_rejected() {
    let plaintext = [0x03, 3, b'a', b'b', b'c', 0x00]; // 端口只有 1 字节
    let err = codec().open(&seal_fixed(&plaintext)).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Address(ss_core::Error::TooShort { need: 7, got: 6 })
        ),
        "{err:?}"
    );
}
