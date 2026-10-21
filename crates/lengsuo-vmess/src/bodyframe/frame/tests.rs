use super::*;

use crate::bodyframe::BodySuite;

const KEY: [u8; 16] = *b"request-body-key";
const IV: [u8; 16] = *b"request-body-iv!";

/// `Result::expect_err` 需要 `T: Debug`，而 `BodyCipher`/`BodyFrame` 刻意
/// 不实现 `Debug`（内含密钥）。这里显式取错误变体。
fn expect_err<T>(result: Result<T>) -> Error {
    match result {
        Ok(_) => panic!("预期失败但成功了"),
        Err(error) => error,
    }
}

fn roundtrip(suite: BodySuite, option: u8) {
    let mut seal = BodyFrame::for_request(suite, &KEY, &IV, &KEY, &IV, option).expect("可建");
    let mut open = BodyFrame::for_request(suite, &KEY, &IV, &KEY, &IV, option).expect("可建");
    let mut wire = Vec::new();
    seal.seal(&mut wire, b"hello").expect("可写");
    seal.seal(&mut wire, &[0x5Au8; 300]).expect("可写");
    seal.seal(&mut wire, b"").expect("EOF 可写");

    let mut cursor = &wire[..];
    let first = open.open_from(&mut cursor).expect("可解");
    assert_eq!(
        first.as_deref(),
        Some(&b"hello"[..]),
        "suite={suite:?} option={option:#x}"
    );
    let second = open.open_from(&mut cursor).expect("可解");
    assert_eq!(second.as_deref(), Some(&[0x5Au8; 300][..]));
    let eof = open.open_from(&mut cursor).expect("可解");
    assert!(eof.is_none(), "终止帧应得到 None 而非空载荷");
    assert!(cursor.is_empty(), "不得吞尾部字节");
}

#[test]
fn roundtrip_all_suites_all_size_modes() {
    for suite in [
        BodySuite::None,
        BodySuite::Aes128Gcm,
        BodySuite::ChaCha20Poly1305,
    ] {
        for option in [0x00u8, 0x04, 0x0C] {
            roundtrip(suite, option);
        }
        if suite != BodySuite::None {
            roundtrip(suite, 0x10); // 认证长度段
            roundtrip(suite, 0x1C); // 认证长度段 + 掩码 + padding
        }
    }
}

#[test]
fn cross_suite_ciphertext_does_not_open() {
    let mut aes_seal =
        BodyFrame::for_request(BodySuite::Aes128Gcm, &KEY, &IV, &KEY, &IV, 0).expect("可建");
    let mut wire = Vec::new();
    aes_seal.seal(&mut wire, b"cross-suite").expect("可写");
    let mut chacha_open =
        BodyFrame::for_request(BodySuite::ChaCha20Poly1305, &KEY, &IV, &KEY, &IV, 0).expect("可建");
    let err = expect_err(chacha_open.open(&wire));
    assert!(matches!(err, Error::AuthFailed), "实际 {err:?}");
}

#[test]
fn authenticated_length_tamper_is_rejected() {
    let mut seal = BodyFrame::for_request(BodySuite::ChaCha20Poly1305, &KEY, &IV, &KEY, &IV, 0x10)
        .expect("可建");
    let mut wire = Vec::new();
    seal.seal(&mut wire, b"payload").expect("可写");
    wire[3] ^= 0x01; // 破坏认证长度段密文
    let mut open = BodyFrame::for_request(BodySuite::ChaCha20Poly1305, &KEY, &IV, &KEY, &IV, 0x10)
        .expect("可建");
    let err = expect_err(open.open(&wire));
    assert!(matches!(err, Error::AuthFailed), "实际 {err:?}");
}

#[test]
fn global_padding_without_masking_is_rejected() {
    let err = expect_err(BodyFrame::for_request(
        BodySuite::Aes128Gcm,
        &KEY,
        &IV,
        &KEY,
        &IV,
        0x08,
    ));
    assert!(matches!(err, Error::Unsupported { .. }));
}
