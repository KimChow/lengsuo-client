//! 传统 Shadowsocks AEAD UDP 公开 API 的边界测试（使用假口令，与生产凭据无关）。
//!
//! 职责拆分：固定 salt 的逐字节向量在 `src/udp/vectors.rs`（需要私有构造函数），
//! 本文件只经 `UdpCodec::new` / `seal` / `open` 验证语义、边界与 fail-closed 行为。

use lengsuo_shadowsocks::udp::{Error, UdpCodec, MAX_PACKET_LEN};
use ss_core::crypto::CipherSuite;
use ss_core::target::TargetAddr;

const PASSWORD: &str = "passw0rd";
const WRONG_PASSWORD: &str = "wr0ng-passw0rd";
const PAYLOAD: &[u8] = b"udp-payload-0123456789";

const ALL_SUITES: [CipherSuite; 4] = [
    CipherSuite::Aes128Gcm,
    CipherSuite::Aes256Gcm,
    CipherSuite::ChaCha20IetfPoly1305,
    CipherSuite::XChaCha20IetfPoly1305,
];

fn targets() -> Vec<TargetAddr> {
    vec![
        TargetAddr::V4([192, 0, 2, 1], 443),
        TargetAddr::Domain("example.invalid".into(), 53),
        TargetAddr::V6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
            ],
            8080,
        ),
    ]
}

/// 用假口令构造编解码器；构造失败即视为测试环境错误。
fn codec(suite: CipherSuite) -> UdpCodec {
    UdpCodec::new(suite, PASSWORD.as_bytes()).expect("假口令应能构造编解码器")
}

/// 用指定假口令构造（错密码用例）。
fn codec_with(suite: CipherSuite, password: &str) -> UdpCodec {
    UdpCodec::new(suite, password.as_bytes()).expect("假口令应能构造编解码器")
}

/// 四套件 × 三类目标：随机 salt 封装机也解得回，且目标/载荷语义一致。
#[test]
fn roundtrip_all_suites_and_target_kinds() {
    for suite in ALL_SUITES {
        let codec = codec(suite);
        for target in targets() {
            let packet = codec.seal(&target, PAYLOAD).unwrap();
            assert_eq!(
                packet.len(),
                suite.salt_len() + PAYLOAD.len() + target.encoded_len() + 16
            );
            let (got_target, got_payload) = codec.open(&packet).unwrap();
            assert_eq!(got_target, target);
            assert_eq!(got_payload, PAYLOAD);
        }
    }
}

/// 空载荷与最大合规载荷都要能封解；边界值 = MAX_PACKET_LEN 恰好通过。
#[test]
fn extreme_payload_sizes_roundtrip_within_limit() {
    let codec = codec(CipherSuite::Aes128Gcm);
    let (target, _) = (TargetAddr::V4([192, 0, 2, 1], 53), ());
    let packet = codec.seal(&target, b"").unwrap();
    let (got_target, got_payload) = codec.open(&packet).unwrap();
    assert_eq!(got_target, target);
    assert!(got_payload.is_empty());

    // salt(16) + addr(7) + payload + tag(16) <= 65507 ⇒ payload = 65507-39。
    let max_payload = vec![0xA5u8; MAX_PACKET_LEN - 16 - 7 - 16];
    let packet = codec.seal(&target, &max_payload).unwrap();
    assert_eq!(packet.len(), MAX_PACKET_LEN);
    let (_, payload) = codec.open(&packet).unwrap();
    assert_eq!(payload, max_payload);

    // 超限 1 字节：封装侧直接拒绝，不产出包。
    let over = vec![0xA5u8; max_payload.len() + 1];
    let err = codec.seal(&target, &over).expect_err("超限载荷必须被拒绝");
    assert!(
        matches!(err, Error::TooLong { got, .. } if got == MAX_PACKET_LEN + 1),
        "{err:?}"
    );
}

/// 每个截断位置（salt 中段、salt 尾、tag 内、tag 前）都必须失败，且不得泄露目标。
#[test]
fn every_truncation_point_fails_closed() {
    for suite in ALL_SUITES {
        let codec = codec(suite);
        let target = TargetAddr::V4([192, 0, 2, 1], 443);
        let packet = codec.seal(&target, PAYLOAD).unwrap();
        assert!(packet.len() >= suite.salt_len() + 16 + 7);
        for cut in 0..packet.len() {
            let result = codec.open(&packet[..cut]);
            let err = match result {
                Ok(_) => panic!("{suite:?} 截断到 {cut} 字节竟被接受"),
                Err(err) => err,
            };
            // 短于 salt+tag 报 TooShort；其余截断落在认证或地址解析上。
            assert!(
                matches!(
                    err,
                    Error::TooShort { .. } | Error::Authentication | Error::Address(_)
                ),
                "{suite:?} 截断到 {cut} 字节的错误类型不符：{err:?}"
            );
        }
    }
}

/// 错误口令一律认证失败；不得解析出任何目标地址。
#[test]
fn wrong_password_fails_closed() {
    for suite in ALL_SUITES {
        let sender = codec(suite);
        let receiver = codec_with(suite, WRONG_PASSWORD);
        let packet = sender
            .seal(&TargetAddr::V4([192, 0, 2, 1], 443), PAYLOAD)
            .unwrap();
        let err = receiver
            .open(&packet)
            .expect_err("错误口令必须拒绝他人封装的包");
        assert!(
            matches!(err, Error::Authentication),
            "{suite:?} 错误：{err:?}"
        );
    }
}

/// 密文与 tag 的每个字节被翻转都只导致认证失败，绝不返回明文目标。
#[test]
fn single_byte_tampering_fails_closed_everywhere() {
    let suite = CipherSuite::Aes256Gcm;
    let codec = codec(suite);
    let packet = codec
        .seal(&TargetAddr::Domain("example.invalid".into(), 53), PAYLOAD)
        .unwrap();
    for i in 0..packet.len() {
        let mut tampered = packet.clone();
        tampered[i] ^= 0x01;
        let err = codec.open(&tampered).expect_err("篡改不应通过");
        if i < suite.salt_len() {
            // salt 篡改 = 派生错误 subkey，等价错口令 ⇒ 认证失败。
            assert!(
                matches!(err, Error::Authentication),
                "salt 偏移 {i}：{err:?}"
            );
        } else {
            assert!(
                matches!(err, Error::Authentication),
                "密文偏移 {i}：{err:?}"
            );
        }
    }
}

/// 密文末尾附加多余字节破坏 tag 对齐，必须失败。
#[test]
fn trailing_garbage_fails_closed() {
    let codec = codec(CipherSuite::Aes128Gcm);
    let mut packet = codec
        .seal(&TargetAddr::V4([192, 0, 2, 1], 443), PAYLOAD)
        .unwrap();
    packet.push(0x00);
    assert!(matches!(codec.open(&packet), Err(Error::Authentication)));
}

/// 非法域名目标在封装侧就被拒绝：空域名、含 NUL、超过 255 字节。
#[test]
fn invalid_domain_targets_rejected_before_any_bytes() {
    let codec = codec(CipherSuite::Aes256Gcm);
    let bad = [
        TargetAddr::Domain(String::new(), 80),
        TargetAddr::Domain("bad\0host".into(), 80),
        TargetAddr::Domain("a".repeat(256), 80),
    ];
    for target in bad {
        let err = codec
            .seal(&target, PAYLOAD)
            .expect_err("非法域名必须被拒绝");
        assert!(matches!(err, Error::Address(_)), "{err:?}");
    }
}

/// 超过 UDP 上限的整包在解封侧同样拒绝（即便前缀是合法包）。
#[test]
fn oversized_datagram_rejected_on_open() {
    let codec = codec(CipherSuite::Aes128Gcm);
    let mut packet = codec
        .seal(&TargetAddr::V4([192, 0, 2, 1], 443), PAYLOAD)
        .unwrap();
    let valid_len = packet.len();
    while packet.len() <= MAX_PACKET_LEN {
        packet.push(0);
    }
    // 现在超过上限；多出的字节即使补在合法包之后也不得进入认证路径。
    assert!(packet.len() > MAX_PACKET_LEN);
    let _ = valid_len;
    assert!(matches!(codec.open(&packet), Err(Error::TooLong { .. })));
}

/// 不同包必须携带不同随机 salt；解封按包内 salt 派生，不依赖任何共享状态。
#[test]
fn distinct_salts_across_packets_and_stateless_open() {
    let codec = codec(CipherSuite::XChaCha20IetfPoly1305);
    let mut salts = Vec::new();
    let mut packets = Vec::new();
    for _ in 0..8 {
        let packet = codec
            .seal(&TargetAddr::V4([192, 0, 2, 1], 443), PAYLOAD)
            .unwrap();
        salts.push(packet[..32].to_vec());
        packets.push(packet);
    }
    for (i, a) in salts.iter().enumerate() {
        for (j, b) in salts.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "第 {i} 与第 {j} 个包 salt 相同");
            }
        }
    }
    // 乱序解封也成立：每包独立派生，不存在会话 nonce 依赖。
    let mut reversed = packets.clone();
    reversed.reverse();
    for packet in &reversed {
        let (target, payload) = codec.open(packet).unwrap();
        assert_eq!(target, TargetAddr::V4([192, 0, 2, 1], 443));
        assert_eq!(payload, PAYLOAD);
    }
}

/// 套件与口令必须成对使用；AES-128 与 AES-256 的 salt 长度不同，错拆分段失败。
#[test]
fn cross_suite_salt_length_mismatch_fails() {
    let sender = codec(CipherSuite::Aes128Gcm);
    let receiver = codec(CipherSuite::Aes256Gcm);
    let packet = sender
        .seal(&TargetAddr::V4([192, 0, 2, 1], 443), PAYLOAD)
        .unwrap();
    // AES-256 侧按 32 字节拆 salt，前缀相同也只会认证失败。
    assert!(matches!(
        receiver.open(&packet),
        Err(Error::TooShort { .. } | Error::Authentication)
    ));
}
