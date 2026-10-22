//! ⭐ 固定测试向量：**跨仓字节一致性的唯一防漂移手段**。
//!
//! `tests/vectors/credential-crypto-v1.json` 是 W2（服务端）/ W3（Rust host）卡
//! 引用的**同一份**文件 ⇒ 字段名用英文、语义自解释。
//!
//! 两条保证：
//! 1. **可复现**：向量里的每个字节都由固定熵 + 固定私钥夹具产生
//!    ⇒ 任何一端重跑都得到同样的字节。
//! 2. **不靠外部脚本生成期望值**：本测试只做「实现 ⇒ 与 JSON 字面量逐字节比对」，
//!    JSON 里的值是**字面量**（不是测试运行时算出来的）。
//!    结构部分的正确性由 `byte_layout.rs` 里的硬编码常量独立保证；
//!    KDF 由 Go 生态的 Argon2 独立实现交叉核对；
//!    签名由 `openssl` 命令行独立验签。

mod support;

use lengsuo_credential_crypto::attestation;
use lengsuo_credential_crypto::authdata;
use lengsuo_credential_crypto::cose;
use lengsuo_credential_crypto::envelope::{self, SealParams};
use lengsuo_credential_crypto::flags;
use lengsuo_credential_crypto::kdf;
use lengsuo_credential_crypto::keypair;
use serde_json::Value;
use std::path::PathBuf;
use support::{
    FixedEntropy, FIXED_CREDENTIAL_ID, FIXED_DEK, FIXED_MASTER_KEY, FIXED_PKCS8, FIXED_RP_ID,
};

/// 向量文件路径。
fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("credential-crypto-v1.json")
}

/// 固定熵：12 字节 priv nonce + 12 字节 wrapped_dek nonce。
fn envelope_entropy() -> FixedEntropy {
    FixedEntropy::new(&[
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, //
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    ])
}

/// 固定熵：20 字节恢复码熵（160 bit）+ 16 字节 salt。
fn recovery_entropy() -> FixedEntropy {
    FixedEntropy::new(&[
        // 恢复码熵（20 字节 = 160 bit）
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, // salt（16 字节）
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f,
    ])
}

/// 读向量文件。
fn load() -> Value {
    let path = vector_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("读不到向量文件 {}：{}", path.display(), e));
    serde_json::from_str(&text).expect("向量文件必须是合法 JSON")
}

/// 按点分路径取值（`"cose_key.hex"`）。
fn lookup<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn hex_field(v: &Value, path: &str) -> String {
    lookup(v, path)
        .unwrap_or_else(|| panic!("向量文件缺字段 {}", path))
        .as_str()
        .unwrap_or_else(|| panic!("向量字段 {} 必须是字符串", path))
        .to_owned()
}

#[test]
fn vectors_reproduce_the_implementation_byte_for_byte() {
    let v = load();

    // ---- COSE_Key ----
    let pair = keypair::KeyPair::from_pkcs8(FIXED_PKCS8).unwrap();
    let cose_key = cose::cose_key(&pair.x(), &pair.y());
    assert_eq!(hex_field(&v, "cose_key.hex"), hex::encode(cose_key));
    assert_eq!(
        lookup(&v, "cose_key.length").and_then(Value::as_u64),
        Some(77),
        "COSE_Key 必须恰好 77 字节"
    );
    assert_eq!(
        lookup(&v, "cose_key.length").and_then(Value::as_u64),
        Some(77)
    );

    // ---- authData ----
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let auth = authdata::build(
        &rp_id_hash,
        flags::MANAGED_DEFAULT,
        1,
        &FIXED_CREDENTIAL_ID,
        &cose_key,
    )
    .unwrap();
    assert_eq!(hex_field(&v, "auth_data.hex"), hex::encode(&auth));
    assert_eq!(
        lookup(&v, "auth_data.length").and_then(Value::as_u64),
        Some(148)
    );
    let segments = lookup(&v, "auth_data.segments")
        .and_then(Value::as_object)
        .expect("auth_data.segments 必须是对象");
    for (name, expected) in [
        ("rp_id_hash", 32u64),
        ("flags", 1),
        ("sign_count", 4),
        ("aaguid", 16),
        ("cred_id_len", 2),
        ("cred_id", 16),
        ("cose_key", 77),
    ] {
        assert_eq!(
            segments.get(name).and_then(Value::as_u64),
            Some(expected),
            "auth_data.segments.{} 长度不符",
            name
        );
    }
    // aaguid 全零。
    assert_eq!(hex_field(&v, "auth_data.aaguid_hex"), "00".repeat(16));

    // ---- attestationObject ----
    let att = attestation::build(&auth).unwrap();
    assert_eq!(hex_field(&v, "attestation_object.hex"), hex::encode(&att));
    assert_eq!(
        lookup(&v, "attestation_object.length").and_then(Value::as_u64),
        Some(att.len() as u64)
    );
    assert_eq!(hex_field(&v, "attestation_object.fmt"), "none");
    assert_eq!(
        lookup(&v, "attestation_object.att_stmt_entries").and_then(Value::as_u64),
        Some(0)
    );

    // ---- 信封 ----
    let mut entropy = envelope_entropy();
    let env = envelope::seal(
        &SealParams {
            rp_id: FIXED_RP_ID,
            flags: flags::MANAGED_DEFAULT,
            master_key: &FIXED_MASTER_KEY,
            dek: &FIXED_DEK,
            private_key_pkcs8: FIXED_PKCS8,
        },
        &mut entropy,
    )
    .unwrap();
    assert_eq!(
        hex_field(&v, "envelope.header_hex"),
        hex::encode(env.header)
    );
    assert_eq!(
        lookup(&v, "envelope.header_len").and_then(Value::as_u64),
        Some(24)
    );
    assert_eq!(
        lookup(&v, "envelope.wrapped_dek_len").and_then(Value::as_u64),
        Some(60),
        "wrapped_dek_len 必须是 60"
    );
    assert_eq!(
        lookup(&v, "envelope.priv_ciphertext_len").and_then(Value::as_u64),
        Some(env.priv_ciphertext.len() as u64)
    );
    assert_eq!(
        lookup(&v, "envelope.priv_ciphertext_len").and_then(Value::as_u64),
        Some((FIXED_PKCS8.len() + 28) as u64),
        "priv_ciphertext 总长必须是 N + 28"
    );
    assert_eq!(hex_field(&v, "envelope.rp_id"), FIXED_RP_ID);
    assert_eq!(hex_field(&v, "envelope.aaguid_hex"), "00".repeat(16));

    // ---- 恢复码 ----
    let mut entropy = recovery_entropy();
    let (code, salt, dek) =
        kdf::derive_from_recovery_code(&kdf::KDF_PARAMS_V1, &mut entropy).unwrap();
    assert_eq!(hex_field(&v, "recovery_code.chars"), code.chars);
    assert_eq!(hex_field(&v, "recovery_code.display"), code.display());
    assert_eq!(hex_field(&v, "recovery_code.salt_hex"), hex::encode(salt));
    assert_eq!(
        hex_field(&v, "recovery_code.derived_dek_hex"),
        hex::encode(&*dek)
    );
    assert_eq!(code.chars.len(), 32);
    assert_eq!(code.display().matches('-').count(), 3);

    let params = lookup(&v, "recovery_code.kdf_params")
        .and_then(Value::as_object)
        .expect("recovery_code.kdf_params 必须是对象");
    assert_eq!(
        params.get("algorithm").and_then(Value::as_str),
        Some("argon2id")
    );
    assert_eq!(params.get("version").and_then(Value::as_u64), Some(19));
    assert_eq!(
        params.get("memory_cost_kib").and_then(Value::as_u64),
        Some(65536)
    );
    assert_eq!(params.get("time_cost").and_then(Value::as_u64), Some(3));
    assert_eq!(params.get("parallelism").and_then(Value::as_u64), Some(1));
    assert_eq!(params.get("output_len").and_then(Value::as_u64), Some(32));
    assert_eq!(params.get("salt_len").and_then(Value::as_u64), Some(16));
    assert_eq!(
        params.get("params_version").and_then(Value::as_u64),
        Some(1)
    );
}

/// 向量文件里的**纯结构**常量必须是契约里的那些值（防止有人改坏向量文件）。
#[test]
fn vector_file_structural_constants_match_the_contract() {
    let v = load();
    // 契约 §2.2 的 COSE_Key 固定模板。
    assert_eq!(hex_field(&v, "cose_key.prefix_hex"), "a5010203262001215820");
    assert_eq!(hex_field(&v, "cose_key.y_prefix_hex"), "225820");
    // 契约 §2.1 的标志位。
    assert_eq!(
        lookup(&v, "flags.default").and_then(Value::as_u64),
        Some(0x45)
    );
    assert_eq!(lookup(&v, "flags.at").and_then(Value::as_u64), Some(0x40));
    assert_eq!(lookup(&v, "flags.ed").and_then(Value::as_u64), Some(0x80));
    // 契约 §1.1 的信封 magic。
    assert_eq!(hex_field(&v, "envelope.magic_hex"), "4c534347");
    // 契约 §4 的 base32 变体。
    assert_eq!(
        hex_field(&v, "recovery_code.base32_alphabet"),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    );
    assert_eq!(
        lookup(&v, "recovery_code.entropy_bits").and_then(Value::as_u64),
        Some(160)
    );
    assert_eq!(
        lookup(&v, "recovery_code.chars")
            .and_then(Value::as_str)
            .map(str::len),
        Some(32)
    );
}
