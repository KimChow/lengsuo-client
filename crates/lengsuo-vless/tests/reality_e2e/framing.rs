//! 第 2 层：**握手消息与记录层分帧**（结构级）。

use lengsuo_vless::reality::tls13::certificate::SelfSignedCertificate;
use lengsuo_vless::reality::tls13::handshake::build_finished;
use lengsuo_vless::reality::tls13::messages::{handshake_type, parse_handshake};

/// 握手消息的 4 字节头与类型必须能被解析器还原。
#[test]
fn handshake_message_framing_roundtrips() {
    let finished = build_finished(&[0xabu8; 32]);
    assert_eq!(&finished[..4], &[handshake_type::FINISHED, 0, 0, 32]);
    let (kind, body, consumed) = parse_handshake(&finished).expect("Finished 消息应能解析");
    assert_eq!(kind, handshake_type::FINISHED);
    assert_eq!(body.len(), 32);
    assert_eq!(consumed, finished.len());
    // 截断的消息必须解析失败（fail-closed）。
    assert!(parse_handshake(&finished[..10]).is_err());
}

/// `Certificate` 消息必须能被解析回叶子证书 DER。
#[test]
fn certificate_message_carries_leaf_der() {
    let certificate = SelfSignedCertificate::generate([0x31; 32]);
    let message = lengsuo_vless::reality::tls13::handshake::build_certificate(&certificate.der);
    let body = &message[4..];
    let parsed = lengsuo_vless::reality::tls13::handshake::parse_certificate(body)
        .expect("Certificate 消息应能解析");
    assert_eq!(parsed.der, certificate.der);
}
