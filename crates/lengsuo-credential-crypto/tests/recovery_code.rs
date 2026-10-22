//! 恢复码 KDF 的测试。
//!
//! ⛔ Argon2id 的期望值是**写死的常量**（来自独立实现的 Argon2 参考值，
//! 见交付报告的取证说明）⇒ 不会「实现和期望一起错」。

mod support;

use lengsuo_credential_crypto::kdf::{
    self, BASE32_ALPHABET, KDF_PARAMS_V1, RECOVERY_CODE_LEN, RECOVERY_ENTROPY_LEN,
};
use support::FixedEntropy;

#[test]
fn kdf_params_are_the_frozen_v1_values() {
    assert_eq!(KDF_PARAMS_V1.memory_cost, 65536);
    assert_eq!(KDF_PARAMS_V1.time_cost, 3);
    assert_eq!(KDF_PARAMS_V1.parallelism, 1);
    assert_eq!(KDF_PARAMS_V1.output_len, 32);
    assert_eq!(KDF_PARAMS_V1.salt_len, 16);
    assert_eq!(KDF_PARAMS_V1.version, kdf::KDF_PARAMS_VERSION);
}

#[test]
fn base32_alphabet_is_rfc4648() {
    assert_eq!(BASE32_ALPHABET, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    // 不含数字 0、1、8、9（Crockford 才会把它们排除/改写）⇒ 证明选的是 RFC 4648。
    for &banned in b"0189" {
        assert!(
            !BASE32_ALPHABET.contains(&banned),
            "RFC 4648 字母表不得含 {:?}",
            banned as char
        );
    }
    // 字母 A-Z 与数字 2-7 都在。
    for &required in b"AZ27" {
        assert!(BASE32_ALPHABET.contains(&required));
    }
}

#[test]
fn recovery_code_is_32_chars_in_four_groups() {
    let mut entropy = FixedEntropy::repeating();
    let code = kdf::generate_recovery_code(&mut entropy).unwrap();
    assert_eq!(code.chars.len(), RECOVERY_CODE_LEN);
    assert_eq!(code.chars.len(), 32);
    assert!(!code.chars.contains('-'), "字符本体不含分隔符");
    assert!(!code.chars.contains('='), "base32 无 padding");

    let display = code.display();
    assert_eq!(display.len(), 35, "32 字符 + 3 个 '-'");
    let groups: Vec<&str> = display.split('-').collect();
    assert_eq!(groups.len(), 4);
    for group in &groups {
        assert_eq!(group.len(), 8);
    }
    // 分组只是展示形态 ⇒ 拼回去等于字符本体。
    assert_eq!(groups.concat(), code.chars);
}

#[test]
fn recovery_entropy_is_160_bits() {
    let mut entropy = FixedEntropy::repeating();
    let code = kdf::generate_recovery_code(&mut entropy).unwrap();
    assert_eq!(code.entropy.len(), RECOVERY_ENTROPY_LEN);
    assert_eq!(code.entropy.len(), 20, "32 个 base32 字符 ⇔ 160 bit");
    // 熵不得用补零凑长度：20 字节里必须真的带随机内容。
    assert!(code.entropy.iter().any(|b| *b != 0));
}

#[test]
fn recovery_code_is_deterministic_for_a_fixed_entropy() {
    let a = kdf::generate_recovery_code(&mut FixedEntropy::new(&[7u8; 20])).unwrap();
    let b = kdf::generate_recovery_code(&mut FixedEntropy::new(&[7u8; 20])).unwrap();
    assert_eq!(a, b);
    // 20 字节 0x07 ⇒ 每 5 字节一组 = 0x0707070707 ⇒ base32 固定 4 字符一循环。
    assert_eq!(a.chars, "A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYH");
    assert_eq!(a.chars.len(), 32);
}

#[test]
fn argon2id_matches_the_frozen_reference_vector() {
    // Argon2id v1.3，m=65536 KiB, t=3, p=1, salt=16B, out=32B。
    // password = "password", salt = 0x00..0x0f。
    //
    // ⛔ 期望值由**独立于本仓的 Argon2 实现**产出（Go 生态的 `x/crypto/argon2`，
    // 与本仓用的 Rust `argon2` crate 是两套完全不同的代码路径）
    // ⇒ 这不是「自家 roundtrip」。
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let dek = kdf::derive_dek(b"password", &salt, &KDF_PARAMS_V1).unwrap();
    assert_eq!(dek.len(), 32);
    assert_eq!(
        hex::encode(dek.as_slice()),
        "def6fd068289b9a0cf1114f8e978a2c4dab6faef377d895b9c2d59fc93fc5653"
    );
}

#[test]
fn argon2id_matches_a_second_reference_vector() {
    // 另一组独立输入（salt = 0x10..0x1f），防止只对一组输入「碰巧对上」。
    let salt = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let dek = kdf::derive_dek(b"password", &salt, &KDF_PARAMS_V1).unwrap();
    assert_eq!(
        hex::encode(dek.as_slice()),
        "90f6a69322975421c72b618e821ed666bf8beab6b4c02003b41719ef10a9f1af"
    );
}

#[test]
fn argon2id_matches_a_recovery_code_shaped_reference_vector() {
    // 密码形态就是 32 个 base32 字符（恢复码本体，不含分隔符）。
    let salt = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];
    let dek = kdf::derive_dek(b"MZXW6YTBOIMZXW6YTBOIMZXW6YTBOI", &salt, &KDF_PARAMS_V1).unwrap();
    assert_eq!(
        hex::encode(dek.as_slice()),
        "e51f049049ca22ce9777b28e8e4c1016b04283a5d0cdaec08b2774150d0313da"
    );
}

#[test]
fn derive_dek_rejects_a_salt_of_the_wrong_length() {
    let err = kdf::derive_dek(b"password", &[0u8; 15], &KDF_PARAMS_V1).unwrap_err();
    assert_eq!(err, lengsuo_credential_crypto::Error::KdfParams);
    let err = kdf::derive_dek(b"password", &[0u8; 17], &KDF_PARAMS_V1).unwrap_err();
    assert_eq!(err, lengsuo_credential_crypto::Error::KdfParams);
}

#[test]
fn different_salts_give_different_deks() {
    let a = kdf::derive_dek(b"pw", &[0u8; 16], &KDF_PARAMS_V1).unwrap();
    let b = kdf::derive_dek(b"pw", &[1u8; 16], &KDF_PARAMS_V1).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn kdf_params_version_is_carried_in_the_struct() {
    // 参数变更 = 已发恢复码全部失效 ⇒ 参数必须版本化。
    let mut params = KDF_PARAMS_V1;
    assert_eq!(params.version, 1);
    params.version = 2;
    assert_eq!(params.version, 2);
    assert_ne!(params.version, KDF_PARAMS_V1.version);
}
