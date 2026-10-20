//! D-S1：TCP 读侧 chunk 长度上限必须与参考 `common/crypto/auth.go:179` 对齐。
//!
//! 参考把**含 16B tag** 的 size 与 `buf.Size = 8192` 比较，因此载荷明文上限是
//! 8192 - 16 = 8176。本仓此前比较的是去掉 tag 的明文长，导致 8177..=8192
//! 被错误接受。

use ss_core::chunk::{read_chunk, MAX_CHUNK_PAYLOAD};
use ss_core::crypto::{CipherSuite, SessionAead};
use ss_core::kdf::hkdf_sha1_subkey;
use ss_core::Error;

fn aead_pair() -> (SessionAead, SessionAead) {
    let subkey = hkdf_sha1_subkey(&[3u8; 16], &[9u8; 16], 16);
    (
        SessionAead::new(CipherSuite::Aes128Gcm, subkey.clone()),
        SessionAead::new(CipherSuite::Aes128Gcm, subkey),
    )
}

/// 按线上格式构造一个合法 chunk：AEAD(BE16(stored)) ‖ AEAD(payload)。
fn chunk_wire(enc: &mut SessionAead, stored: usize, payload: &[u8]) -> Vec<u8> {
    let mut wire = enc.seal(&(stored as u16).to_be_bytes()).unwrap();
    wire.extend_from_slice(&enc.seal(payload).unwrap());
    wire
}

#[tokio::test]
async fn payload_8176_is_accepted() {
    let (mut enc, mut dec) = aead_pair();
    let payload = vec![0x5Au8; 8176];
    let wire = chunk_wire(&mut enc, payload.len(), &payload);
    let got = read_chunk(&mut &wire[..], &mut dec).await.unwrap();
    assert_eq!(got.unwrap(), payload);
}

#[tokio::test]
async fn payload_8177_is_rejected() {
    // 8177 + 16 = 8193 > buf.Size(8192)：参考拒绝，本仓必须同样拒绝。
    let (mut enc, mut dec) = aead_pair();
    let payload = vec![0x5Au8; 8177];
    let wire = chunk_wire(&mut enc, payload.len(), &payload);
    let err = read_chunk(&mut &wire[..], &mut dec).await.unwrap_err();
    assert!(matches!(err, Error::InvalidLength(_)), "实际错误：{err:?}");
}

#[test]
fn max_payload_constant_stays_8192() {
    // 公开常量表示参考的 buf.Size（含 tag），不因读侧判据收窄而改名或改值。
    assert_eq!(MAX_CHUNK_PAYLOAD, 8192);
}
