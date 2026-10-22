//! 信封（Envelope v1）的逐字节测试。
//!
//! ⚠️ **字节序一律大端**——这是跨仓最容易错的一处，这里用固定向量钉死。

mod support;

use lengsuo_credential_crypto::envelope::{self, Envelope, SealParams};
use lengsuo_credential_crypto::flags;
use support::{
    FixedEntropy, FIXED_CREDENTIAL_ID, FIXED_DEK, FIXED_MASTER_KEY, FIXED_PKCS8, FIXED_RP_ID,
};

/// 契约 §1.1 的 magic：0x4C534347（"LSCG"）。
const MAGIC: [u8; 4] = [0x4c, 0x53, 0x43, 0x47];

/// 固定熵：先给 12 字节（priv nonce），再给 12 字节（wrapped_dek nonce）。
fn fixed_entropy() -> FixedEntropy {
    FixedEntropy::new(&[
        // priv_ciphertext 的 nonce
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, //
        // wrapped_dek 的 nonce
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    ])
}

fn seal() -> Envelope {
    let mut entropy = fixed_entropy();
    envelope::seal(
        &SealParams {
            rp_id: FIXED_RP_ID,
            flags: flags::MANAGED_DEFAULT,
            master_key: &FIXED_MASTER_KEY,
            dek: &FIXED_DEK,
            private_key_pkcs8: FIXED_PKCS8,
        },
        &mut entropy,
    )
    .unwrap()
}

#[test]
fn header_fields_are_big_endian() {
    let env = seal();
    // magic（4B，大端）
    assert_eq!(&env.header[0..4], &MAGIC);
    // version（4B，大端）= 1
    assert_eq!(&env.header[4..8], &[0x00, 0x00, 0x00, 0x01]);
    // wrapped_dek_len（4B，大端）= 60
    assert_eq!(&env.header[8..12], &[0x00, 0x00, 0x00, 0x3c]);
    // ciphertext_len（4B，大端）= N + 28 = 138 + 28 = 166
    assert_eq!(&env.header[12..16], &[0x00, 0x00, 0x00, 0xa6]);
    // aaguid_len（4B，大端）= 16
    assert_eq!(&env.header[16..20], &[0x00, 0x00, 0x00, 0x10]);
    // rp_id_len（2B，大端）= 12（"example.test"）
    assert_eq!(&env.header[20..22], &[0x00, 0x0c]);
    // flags（2B，大端）= 0x45
    assert_eq!(&env.header[22..24], &[0x00, 0x45]);
}

#[test]
fn wrapped_dek_is_sixty_bytes_nonce_tag_ciphertext() {
    let env = seal();
    assert_eq!(env.wrapped_dek.len(), 60);
    assert_eq!(env.wrapped_dek.len(), envelope::WRAPPED_DEK_LEN);
    // nonce(12) 是注入的固定值。
    assert_eq!(
        &env.wrapped_dek[0..12],
        &[0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb]
    );
    // 剩下 48 字节 = tag(16) || ct(32)。
    assert_eq!(env.wrapped_dek.len() - 12, 48);
}

#[test]
fn priv_ciphertext_is_n_plus_28_bytes() {
    let env = seal();
    // N = PKCS#8 DER 长度 = 138（不是固定值，取决于编码）。
    let n = FIXED_PKCS8.len();
    assert_eq!(n, 138);
    assert_eq!(env.priv_ciphertext.len(), n + 28);
    assert_eq!(env.priv_ciphertext.len(), n + envelope::PRIV_OVERHEAD);
    // 头里存的是**总长**（N+28），不是 N。
    assert_eq!(env.ciphertext_len() as usize, n + 28);
    // nonce(12) 是注入的固定值。
    assert_eq!(
        &env.priv_ciphertext[0..12],
        &[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab]
    );
}

#[test]
fn aaguid_inside_the_envelope_is_all_zero() {
    let env = seal();
    assert_eq!(env.aaguid, [0u8; 16]);
    assert!(env.aaguid.iter().all(|b| *b == 0));
}

#[test]
fn seal_is_deterministic_for_a_fixed_entropy() {
    let a = seal();
    let b = seal();
    assert_eq!(a.to_bytes(), b.to_bytes());
    assert_eq!(a, b);
}

#[test]
fn parse_round_trips_the_sealed_envelope() {
    let env = seal();
    let bytes = env.to_bytes();
    let parsed = envelope::parse(&bytes).unwrap();
    assert_eq!(parsed, env);
    assert_eq!(parsed.rp_id, FIXED_RP_ID);
    assert_eq!(parsed.aaguid, [0u8; 16]);
    assert_eq!(parsed.wrapped_dek, env.wrapped_dek);
    assert_eq!(parsed.priv_ciphertext, env.priv_ciphertext);
}

#[test]
fn open_recovers_the_private_key() {
    let env = seal();
    let plain = envelope::open(&env, &FIXED_MASTER_KEY).unwrap();
    assert_eq!(plain.as_slice(), FIXED_PKCS8);
}

#[test]
fn open_fails_closed_when_the_header_is_tampered() {
    let mut env = seal();
    // 改 flags ⇒ AAD 与封入时不同 ⇒ 必须解封失败（防篡改）。
    env.header[23] = 0x00;
    let err = envelope::open(&env, &FIXED_MASTER_KEY).unwrap_err();
    assert_eq!(err, lengsuo_credential_crypto::Error::EnvelopeAuthFailed);
}

#[test]
fn open_fails_closed_with_the_wrong_master_key() {
    let env = seal();
    let wrong = [0x99u8; 32];
    let err = envelope::open(&env, &wrong).unwrap_err();
    assert_eq!(err, lengsuo_credential_crypto::Error::EnvelopeAuthFailed);
}

#[test]
fn parse_rejects_a_bad_magic() {
    let mut env = seal();
    env.header[0] = 0x00;
    assert_eq!(
        envelope::parse(&env.to_bytes()).unwrap_err(),
        lengsuo_credential_crypto::Error::EnvelopeBadMagic
    );
}

#[test]
fn parse_rejects_an_unsupported_version() {
    let mut env = seal();
    // version 是 u32 大端 ⇒ 改最低字节即得版本 2。
    env.header[7] = 0x02;
    assert_eq!(
        envelope::parse(&env.to_bytes()).unwrap_err(),
        lengsuo_credential_crypto::Error::EnvelopeVersion {
            expected: 1,
            got: 2
        }
    );
}

#[test]
fn credential_id_is_sixteen_raw_bytes_not_base64() {
    // 契约 §1.3：16 字节原始字节。16 字节 base64url 变体会是 22 字符 ⇒ 形状不同。
    assert_eq!(FIXED_CREDENTIAL_ID.len(), 16);
    assert_eq!(lengsuo_credential_crypto::authdata::CREDENTIAL_ID_LEN, 16);
}
