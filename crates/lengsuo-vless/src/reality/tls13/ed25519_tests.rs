//! Ed25519 的单元测试（从 `ed25519.rs` 拆出以符合 400 行软目标）。
//!
//! 覆盖 RFC 8032 §7.1 的三组测试向量，以及若干负向用例。

use super::curve::{mod_l_512, L_LIMBS};
use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// RFC 8032 §7.1 测试向量 1。
#[test]
fn rfc8032_vector_1() {
    let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .unwrap();
    let key = SigningKey::from_seed(&seed);
    assert_eq!(
        hex(&key.public_key()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let sig = key.sign(b"");
    assert_eq!(
        hex(&sig),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    assert_eq!(verify(&key.public_key(), b"", &sig), Ok(()));
}

/// RFC 8032 §7.1 测试向量 2。
#[test]
fn rfc8032_vector_2() {
    let seed: [u8; 32] = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        .try_into()
        .unwrap();
    let key = SigningKey::from_seed(&seed);
    assert_eq!(
        hex(&key.public_key()),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    let sig = key.sign(&[0x72]);
    assert_eq!(
        hex(&sig),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    assert_eq!(verify(&key.public_key(), &[0x72], &sig), Ok(()));
}

/// RFC 8032 §7.1 测试向量 3（1024 字节消息）。
#[test]
fn rfc8032_vector_3() {
    let seed: [u8; 32] = unhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
        .try_into()
        .unwrap();
    let key = SigningKey::from_seed(&seed);
    assert_eq!(
        hex(&key.public_key()),
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    );
    let message = [0xafu8; 1024];
    let sig = key.sign(&message);
    assert_eq!(
        hex(&sig),
        "91cfa38aae22e6eef96d956584f4bec4b32cf751fa169b880f7d86604127d2990682be9ec5d01a2774905b6aadc5e9449bcca24e98ce3546c693a76ce8b5e60f"
    );
    assert_eq!(verify(&key.public_key(), &message, &sig), Ok(()));
}

/// 篡改消息必须验签失败。
#[test]
fn tampered_message_fails() {
    let key = SigningKey::from_seed(&[0x42; 32]);
    let sig = key.sign(b"hello");
    assert_eq!(
        verify(&key.public_key(), b"hellp", &sig),
        Err(Ed25519Error::VerifyFailed)
    );
}

/// 篡改签名必须验签失败。
#[test]
fn tampered_signature_fails() {
    let key = SigningKey::from_seed(&[0x42; 32]);
    let mut sig = key.sign(b"hello");
    sig[0] ^= 0x01;
    assert_eq!(
        verify(&key.public_key(), b"hello", &sig),
        Err(Ed25519Error::VerifyFailed)
    );
}

/// 随机密钥的签名/验签必须自洽。
#[test]
fn randomized_sign_verify_roundtrip() {
    for seed in 0u8..16 {
        let key = SigningKey::from_seed(&[seed; 32]);
        let message = [seed.wrapping_mul(7); 100];
        let sig = key.sign(&message);
        assert_eq!(verify(&key.public_key(), &message, &sig), Ok(()));
    }
}

/// 标量约减必须给出 `< L` 的结果。
#[test]
fn scalar_reduction_is_bounded() {
    // 2^512 - 1 约减后必须 < L。
    let max = [u64::MAX; 8];
    let reduced = mod_l_512(&max);
    assert!(!reduced.ge_l());
    // L 本身约减后应为 0。
    let mut l_bytes = [0u64; 8];
    l_bytes[..4].copy_from_slice(&L_LIMBS);
    let reduced_l = mod_l_512(&l_bytes);
    assert_eq!(reduced_l.to_bytes(), [0u8; 32]);
}
