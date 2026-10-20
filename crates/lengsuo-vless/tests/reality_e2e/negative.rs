//! 第 3 层：**负例**（每条都有断言，且必须 fail-closed）。

use crate::support::vectors as vec;

use lengsuo_vless::reality::auth::open_auth_payload;
use lengsuo_vless::reality::tls13::ed25519;
use lengsuo_vless::reality::tls13::record::{content_type, RecordError, RecordLayer};
use lengsuo_vless::reality::tls13::schedule::TrafficKey;
use lengsuo_vless::reality::x25519::x25519;

/// 错口令（不同的 `auth_key`）必须解封失败，不得返回部分明文。
#[test]
fn wrong_auth_key_is_rejected() {
    let mut wrong = vec::REALITY_AUTH_KEY;
    wrong[0] ^= 0xff;
    let err = open_auth_payload(&wrong, &vec::AUTH_CLIENT_HELLO);
    assert!(err.is_err(), "错口令必须被拒绝");
}

/// 篡改认证载荷密文（哪怕只改一个 bit）必须解封失败。
#[test]
fn tampered_auth_payload_is_rejected() {
    let mut raw = vec::AUTH_CLIENT_HELLO.to_vec();
    raw[39] ^= 0x01;
    assert!(open_auth_payload(&vec::REALITY_AUTH_KEY, &raw).is_err());
}

/// 截断的 ClientHello 必须报错（`BufferTooShort`），不得 panic。
#[test]
fn truncated_client_hello_is_rejected() {
    let err = open_auth_payload(&vec::REALITY_AUTH_KEY, &vec::AUTH_CLIENT_HELLO[..40]);
    assert!(err.is_err(), "截断的 ClientHello 必须被拒绝");
}

/// 截断的记录必须解析失败（`MalformedHeader`），不得 panic。
#[test]
fn truncated_record_is_rejected_without_panic() {
    let mut layer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    let wire = layer.seal_application(b"payload").expect("封装不应失败");
    for cut in [0usize, 1, 4, 5, 16, wire.len() - 1] {
        let mut peer = RecordLayer::new(&TrafficKey {
            key: vec::RECORD_KEY,
            iv: vec::RECORD_IV,
        });
        assert!(
            peer.open(&wire[..cut]).is_err(),
            "截断到 {cut} 字节必须失败"
        );
    }
    // 完整记录仍然可用（截断测试没有污染序号）。
    let mut peer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    let (kind, payload) = peer.open(&wire).expect("完整记录应能解封");
    assert_eq!(kind, content_type::APPLICATION_DATA);
    assert_eq!(payload, b"payload");
}

/// 被篡改的记录必须解封失败（AEAD 标签不符）。
#[test]
fn tampered_record_is_rejected() {
    let mut layer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    let mut wire = layer.seal_application(b"payload").expect("封装不应失败");
    let last = wire.len() - 1;
    wire[last] ^= 0xff;
    let mut peer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    assert_eq!(peer.open(&wire), Err(RecordError::DecryptFailed));
}

/// 记录头里的长度字段与实际长度不符必须被拒绝。
#[test]
fn record_length_mismatch_is_rejected() {
    let mut layer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    let mut wire = layer.seal_application(b"payload").expect("封装不应失败");
    wire[4] ^= 0x01;
    let mut peer = RecordLayer::new(&TrafficKey {
        key: vec::RECORD_KEY,
        iv: vec::RECORD_IV,
    });
    assert_eq!(peer.open(&wire), Err(RecordError::MalformedHeader));
}

/// Ed25519 用错误的公钥验签必须失败。
#[test]
fn ed25519_wrong_public_key_is_rejected() {
    let other = ed25519::SigningKey::from_seed(&[0x42; 32]).public_key();
    assert!(
        ed25519::verify(&other, b"message", &vec::ED25519_T1_SIG).is_err(),
        "错误公钥必须验签失败"
    );
}

/// 被篡改的签名必须验签失败。
#[test]
fn ed25519_tampered_signature_is_rejected() {
    let mut signature = vec::ED25519_T1_SIG;
    signature[0] ^= 0x01;
    assert!(ed25519::verify(&vec::ED25519_T1_PUBLIC, b"", &signature).is_err());
}

/// X25519 用不同的对端公钥必须得到不同的共享密钥。
#[test]
fn x25519_distinct_peers_give_distinct_secrets() {
    let a = x25519(&vec::X25519_ALICE_SECRET, &vec::X25519_BOB_PUBLIC).unwrap();
    let b = x25519(&vec::X25519_ALICE_SECRET, &vec::X25519_ALICE_PUBLIC).unwrap();
    assert_ne!(a.to_vec(), b.to_vec());
}
