//! 断言签名的自证测试。
//!
//! 契约没有规定「断言签名」的线格式，但 WebAuthn 规范规定：
//! 签名对象 = `authData || SHA-256(clientDataJSON)`，签名 = **64 字节 r‖s**（ES256）。
//!
//! ⛔ **不用「签出来的再���同一个函数解」当验收**：
//! - 路径 A：`ring` 的**验签 API**（`ECDSA_P256_SHA256_FIXED`）——
//!   与签名 API 是 ring 内部两条不同的代码路径；
//! - 路径 B（最强）：**OpenSSL 命令行**独立验签 —— 见 `tests/openssl_verify.rs`。
//!
//! 本文件用**固定私钥夹具** ⇒ 签名不可复现（ECDSA 用随机 nonce），
//! 所以这里验证的是「验签通过 / 篡改被拒」，
//! 而**可复现的字节**由 COSE_Key / authData / 信封向量承担。

mod support;

use lengsuo_credential_crypto::attestation;
use lengsuo_credential_crypto::authdata;
use lengsuo_credential_crypto::cose;
use lengsuo_credential_crypto::flags;
use lengsuo_credential_crypto::keypair;
use sha2::{Digest, Sha256};
use support::{FIXED_CREDENTIAL_ID, FIXED_PKCS8, FIXED_RP_ID};

/// 构造一份完整的断言材料（authData + clientDataJSON）。
fn assertion_material() -> (keypair::KeyPair, Vec<u8>, Vec<u8>) {
    let pair = keypair::KeyPair::from_pkcs8(FIXED_PKCS8).unwrap();
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let cose_key = cose::cose_key(&pair.x(), &pair.y());
    let auth = authdata::build(
        &rp_id_hash,
        flags::MANAGED_DEFAULT,
        1,
        &FIXED_CREDENTIAL_ID,
        &cose_key,
    )
    .unwrap();
    // 客户端数据 JSON（合成，非真实浏览器输出）。
    let client_data =
        br#"{"type":"webauthn.get","challenge":"AAA","origin":"https://example.test"}"#;
    let client_hash = Sha256::digest(client_data);
    let mut signed = auth.clone();
    signed.extend_from_slice(&client_hash);
    (pair, auth, signed)
}

#[test]
fn assertion_signature_verifies_over_auth_data_plus_client_data_hash() {
    let (pair, auth, signed) = assertion_material();
    let sig = keypair::sign(&pair, &signed).unwrap();
    // ES256 定长 r‖s = 64 字节（⛔ 不是 ASN.1 DER 变长）。
    assert_eq!(sig.len(), 64);
    assert!(keypair::verify(pair.public_point(), &signed, &sig));
    // 签名对象确实是 authData || SHA-256(clientDataJSON)。
    assert_eq!(&signed[..auth.len()], &auth[..]);
}

#[test]
fn a_tampered_auth_data_invalidates_the_signature() {
    let (pair, _, signed) = assertion_material();
    let sig = keypair::sign(&pair, &signed).unwrap();
    let mut tampered = signed.clone();
    tampered[0] ^= 0x01; // 动 rpIdHash 的一个比特。
    assert!(!keypair::verify(pair.public_point(), &tampered, &sig));
}

#[test]
fn a_tampered_client_data_hash_invalidates_the_signature() {
    let (pair, _, signed) = assertion_material();
    let sig = keypair::sign(&pair, &signed).unwrap();
    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(!keypair::verify(pair.public_point(), &tampered, &sig));
}

#[test]
fn a_signature_from_another_key_is_rejected() {
    let (pair, _, signed) = assertion_material();
    let other = keypair::KeyPair::generate().unwrap();
    let sig = keypair::sign(&other, &signed).unwrap();
    assert!(!keypair::verify(pair.public_point(), &signed, &sig));
}

#[test]
fn attestation_object_carries_the_signed_auth_data() {
    let (pair, auth, _) = assertion_material();
    let obj = attestation::build(&auth).unwrap();
    let recovered = attestation::auth_data_of(&obj).unwrap();
    assert_eq!(recovered, auth.as_slice());
    // 从 attestationObject 里取出的 authData 仍能验签。
    let mut signed = recovered.to_vec();
    let client_data =
        br#"{"type":"webauthn.get","challenge":"AAA","origin":"https://example.test"}"#;
    signed.extend_from_slice(&Sha256::digest(client_data));
    let sig = keypair::sign(&pair, &signed).unwrap();
    assert!(keypair::verify(pair.public_point(), &signed, &sig));
}
