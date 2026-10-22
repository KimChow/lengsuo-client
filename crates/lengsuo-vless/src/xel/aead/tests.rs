//! XEL AEAD 后端的单元测试（从父模块拆出以保持单文件 ≤400 行软约束）。
//!
//! 断言与拆分前逐字一致，未增删任何用例。

use super::super::Error;
use super::*;
use crate::xel::XelKey;

fn key(byte: u8) -> XelKey {
    XelKey::new(&[byte; TAG_LEN * 2]).unwrap()
}

const CIPHERS: [XelCipher; 2] = [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305];

#[test]
fn nonce_is_big_endian_and_starts_at_one() {
    assert_eq!(
        nonce_for_sequence(1),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        "先加后用：首次取用必须以 1 结尾"
    );
    assert_eq!(nonce_for_sequence(2)[11], 2);
    assert_eq!(
        nonce_for_sequence(256),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
    );
    let wide = nonce_for_sequence(u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(&wide[..4], &[0, 0, 0, 0]);
    assert_eq!(&wide[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(nonce_for_sequence(1).len(), NONCE_LEN);
}

#[test]
fn seal_open_roundtrip_keeps_record_boundary() {
    for cipher in CIPHERS {
        let mut sender = AeadDirection::new(cipher, key(0x11));
        let mut receiver = AeadDirection::new(cipher, key(0x11));
        let (sequence, body) = sender.seal_at_next(b"hdr", b"record one").unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(body.len(), 10 + TAG_LEN);
        assert_eq!(
            receiver.open_at(1, b"hdr", &body).unwrap(),
            b"record one",
            "{cipher:?} 记录边界必须逐字节保持"
        );
        assert_eq!(sender.sequence(), 1);
    }
}

#[test]
fn sequence_increments_are_observable() {
    let mut sender = AeadDirection::new(XelCipher::Aes256Gcm, key(0x22));
    assert_eq!(sender.sequence(), 0);
    assert_eq!(sender.next_nonce_preview()[11], 1);
    let first = sender.seal_at_next(b"", b"a").unwrap();
    let second = sender.seal_at_next(b"", b"a").unwrap();
    assert_eq!((first.0, second.0), (1, 2), "序号必须严格递增且可观测");
    assert_eq!(first.1[11] % 2, second.1[11] % 2, "仅为可读性检查");
    assert_eq!(sender.next_nonce_preview()[11], 3);
    assert_eq!(sender.sequence(), 2);
}

#[test]
fn aad_changes_break_authentication() {
    for cipher in CIPHERS {
        let mut sender = AeadDirection::new(cipher, key(0x33));
        let mut receiver = AeadDirection::new(cipher, key(0x33));
        let (_, body) = sender.seal_at_next(b"headA", b"same").unwrap();
        assert_eq!(
            receiver.open_at(1, b"headB", &body),
            Err(Error::AuthFailed),
            "{cipher:?} 头部（AAD）改动必须认证失败"
        );
        assert!(receiver.is_poisoned(), "认证失败后必须永久 poison");
        assert_eq!(receiver.open_at(2, b"headA", &body), Err(Error::Poisoned));
    }
}

#[test]
fn tampered_tag_and_body_are_auth_failed() {
    for cipher in CIPHERS {
        for tweak in ["tag", "body"] {
            let mut sender = AeadDirection::new(cipher, key(0x44));
            let mut receiver = AeadDirection::new(cipher, key(0x44));
            let (_, mut body) = sender.seal_at_next(b"", b"payload!").unwrap();
            let index = match tweak {
                "tag" => body.len() - 1,
                _ => body.len() / 2,
            };
            body[index] ^= 0x01;
            assert_eq!(receiver.open_at(1, b"", &body), Err(Error::AuthFailed));
            assert!(receiver.is_poisoned());
        }
    }
}

#[test]
fn wrong_key_fails_closed_without_panic() {
    for cipher in CIPHERS {
        let mut sender = AeadDirection::new(cipher, key(0x55));
        let mut victim = AeadDirection::new(cipher, key(0x99));
        let (_, body) = sender.seal_at_next(b"aad", b"secret text").unwrap();
        assert_eq!(victim.open_at(1, b"aad", &body), Err(Error::AuthFailed));
        assert!(victim.is_poisoned());
        // poison 后不得再解密任何记录（哪怕序号正确）。
        assert_eq!(victim.open_at(2, b"aad", &body), Err(Error::Poisoned));
    }
}

#[test]
fn short_body_is_rejected_before_crypto() {
    let mut receiver = AeadDirection::new(XelCipher::Aes256Gcm, key(0x66));
    assert!(matches!(
        receiver.open_at(1, b"", &[0u8; TAG_LEN - 1]),
        Err(Error::InvalidRecordLength { .. })
    ));
    assert!(receiver.is_poisoned());
}

#[test]
fn direction_debug_hides_key_bytes() {
    let state = AeadDirection::new(XelCipher::Aes256Gcm, key(0xA5));
    let printed = format!("{state:?}");
    assert!(!printed.contains("165"), "Debug 泄露密钥字节：{printed}");
    assert!(printed.contains("REDACTED"), "Debug 未标脱敏：{printed}");
}

#[test]
fn body_len_accounts_for_tag_and_limit() {
    let state = AeadDirection::new(XelCipher::Aes256Gcm, key(0x77));
    assert_eq!(state.body_len(0).unwrap(), TAG_LEN);
    assert_eq!(
        state
            .body_len(super::super::MAX_RECORD_BODY_LEN - TAG_LEN)
            .unwrap(),
        super::super::MAX_RECORD_BODY_LEN
    );
    assert_eq!(
        state.body_len(super::super::MAX_RECORD_BODY_LEN - TAG_LEN + 1),
        Err(Error::RecordTooLarge {
            got: super::super::MAX_RECORD_BODY_LEN - TAG_LEN + 1,
            max: super::super::MAX_RECORD_BODY_LEN - TAG_LEN,
        })
    );
}
