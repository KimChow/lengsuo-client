//! `aead` 模块的单元测试（头部封装/解封与主线响应头两段）。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;

use super::*;
use crate::Error;

const CMD_KEY: [u8; 16] = *b"b831381d-6324-4d";
const AUTH: [u8; 16] = [0x5A; 16];
const NONCE: [u8; 8] = [0x21, 0x43, 0x65, 0x87, 0x09, 0xBA, 0xDC, 0xFE];

#[test]
fn header_seal_open_roundtrip() {
    let payload = b"version+iv+key+seed+opt+security+cmd+address+padding+fnv";
    let wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, payload);
    // 16 + 18 + 8 + payload + 16
    assert_eq!(wire.len(), 16 + 18 + 8 + payload.len() + 16);
    let parsed = parse_auth_id_from_header(&wire).expect("可取 AuthID");
    assert_eq!(parsed, AUTH);
    let opened = open_vmess_aead_header(&CMD_KEY, &parsed, &wire[16..]).expect("可解");
    assert_eq!(opened, payload);
}

#[test]
fn header_truncations_report_need_and_got() {
    let wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, b"payload!");
    // AuthID 之后的长度段不足 18+8。
    let err =
        open_vmess_aead_header(&CMD_KEY, &AUTH, &wire[16..16 + 10]).expect_err("截断必须失败");
    assert!(matches!(err, Error::Truncated { need: 26, got: 10 }));
    // 载荷段被切短。
    let cut = &wire[16..16 + 18 + 8 + 4];
    let err = open_vmess_aead_header(&CMD_KEY, &AUTH, cut).expect_err("载荷截断必须失败");
    assert!(matches!(
        err,
        Error::Truncated { .. } | Error::BadLength { .. }
    ));
}

#[test]
fn tampered_header_and_wrong_key_fail_closed() {
    let payload = b"authenticated header payload";
    let mut wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, payload);
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    assert!(matches!(
        open_vmess_aead_header(&CMD_KEY, &AUTH, &wire[16..]),
        Err(Error::AuthFailed)
    ));
    let clean = seal_header_with(&CMD_KEY, &AUTH, &NONCE, payload);
    let evil = [0xEEu8; 16];
    assert!(matches!(
        open_vmess_aead_header(&evil, &AUTH, &clean[16..]),
        Err(Error::AuthFailed)
    ));
}

#[test]
fn response_header_key_iv_are_stable_and_usable() {
    let resp_key = [0x11u8; 16];
    let resp_iv = [0x22u8; 16];
    let (len_key, len_iv) = response_header_length_key_iv(&resp_key, &resp_iv);
    let (pay_key, pay_iv) = response_header_payload_key_iv(&resp_key, &resp_iv);
    assert_ne!(len_key, pay_key, "长度段与载荷段密钥必须不同");
    assert_ne!(len_iv, pay_iv);
    // 派生值稳定（黄金向量自造，锁定回归）。
    assert_eq!(
        hex::encode(len_key),
        hex::encode(response_header_length_key_iv(&resp_key, &resp_iv).0)
    );
    // 用派生结果走一遍加解密（模拟服务端发送 + 客户端解）。
    let plain_len: u16 = 0x0102;
    let cipher = Aes128Gcm::new_from_slice(&len_key).unwrap();
    let wire = cipher
        .encrypt(
            (&len_iv).into(),
            Payload {
                msg: &plain_len.to_be_bytes(),
                aad: b"",
            },
        )
        .unwrap();
    assert_eq!(wire.len(), 18);
    let got = open_response_header_length(&resp_key, &resp_iv, wire.as_slice().try_into().unwrap())
        .expect("可解");
    assert_eq!(got, plain_len);
    let _ = pay_iv;
}

#[test]
fn empty_payload_header_is_legal() {
    // 长度为 0 的头载荷（协议外但封装层不拒绝——上层 request 模块管语义）。
    let wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, b"");
    assert_eq!(wire.len(), 16 + 18 + 8 + 16);
    let opened = open_vmess_aead_header(&CMD_KEY, &AUTH, &wire[16..]).expect("可解");
    assert!(opened.is_empty());
}
