//! ⭐ **独立验签路径**：`openssl` 命令行验签。
//!
//! 任务书 §2.9 要求「⛔ 不要用「签出来的再用同一个函数解」当验收」，
//! 并建议「用 `openssl` 命令行独立验签」。
//!
//! 本文件走一条**与本仓代码完全无关**的验签路径：
//! - 本仓用 `ring` 的 ECDSA P-256 签名；
//! - 验签由系统 `openssl`（OpenSSL 3.x，独立的密码学实现）完成。
//!
//! ⛔ `openssl` 不在 ⇒ 用例**跳过**（`eprintln!` 明说跳过原因），
//! **不静默当成通过**。
//!
//! 用例带 `#[ignore]`：CI 环境未必有 `openssl`，
//! 需要时用 `cargo test -- --ignored` 实跑（退出码见交付报告）。

mod support;

use lengsuo_credential_crypto::keypair;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use support::{FIXED_CREDENTIAL_ID, FIXED_PKCS8, FIXED_RP_ID};

/// 找一个可用的 `openssl`；找不到返回 `None`。
fn openssl_bin() -> Option<PathBuf> {
    for candidate in ["openssl", "/usr/bin/openssl", "/usr/local/bin/openssl"] {
        let out = Command::new(candidate).arg("version").output();
        if let Ok(out) = out {
            if out.status.success() {
                return Some(PathBuf::from(candidate));
            }
        }
    }
    None
}

/// 读 `openssl version`（用于报告里写明是哪套独立实现）。
fn openssl_version(openssl: &PathBuf) -> String {
    Command::new(openssl)
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|e| format!("<读不到版本：{}>", e))
}

/// 把公钥点写成 PEM（SubjectPublicKeyInfo）。
fn public_key_pem(point: &[u8]) -> String {
    // SubjectPublicKeyInfo = SEQUENCE { AlgorithmIdentifier, BIT STRING }
    // AlgorithmIdentifier = SEQUENCE { OID id-ecPublicKey, OID prime256v1 }
    // BIT STRING = 0x00 || 0x04 || X || Y
    let mut der: Vec<u8> = Vec::new();
    der.extend_from_slice(&[0x30, 0x59]); // SEQUENCE (89)
    der.extend_from_slice(&[0x30, 0x13]); // SEQUENCE (19)
    der.extend_from_slice(&[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    der.extend_from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    der.extend_from_slice(&[0x03, 0x42, 0x00]); // BIT STRING (66)
    der.extend_from_slice(point);
    // PEM base64 换行 64 列。
    let b64 = base64_encode(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// 标准 base64（带 padding）。
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// 把 64 字节 r‖s 转成 OpenSSL 要的 DER 签名（`SEQUENCE { INTEGER r, INTEGER s }`）。
fn sig_to_der(sig: &[u8; 64]) -> Vec<u8> {
    fn int(bytes: &[u8]) -> Vec<u8> {
        // DER INTEGER：去掉前导 0x00；若最高位为 1 则补 0x00（保持正数）。
        let mut v: Vec<u8> = bytes.to_vec();
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0x00);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend_from_slice(&v);
        out
    }
    let r = int(&sig[0..32]);
    let s = int(&sig[32..64]);
    let mut body = r;
    body.extend_from_slice(&s);
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

#[test]
#[ignore = "需要系统 openssl；用 `cargo test -- --ignored` 实跑"]
fn openssl_independently_verifies_the_es256_assertion_signature() {
    let Some(openssl) = openssl_bin() else {
        eprintln!("跳过：环境里没有可用的 openssl");
        return;
    };

    let pair = keypair::KeyPair::from_pkcs8(FIXED_PKCS8).unwrap();
    // 签名对象 = authData || SHA-256(clientDataJSON)。
    let rp_id_hash = keypair::rp_id_hash(FIXED_RP_ID);
    let cose_key = lengsuo_credential_crypto::cose::cose_key(&pair.x(), &pair.y());
    let auth = lengsuo_credential_crypto::authdata::build(
        &rp_id_hash,
        lengsuo_credential_crypto::flags::MANAGED_DEFAULT,
        1,
        &FIXED_CREDENTIAL_ID,
        &cose_key,
    )
    .unwrap();
    let client_data =
        br#"{"type":"webauthn.get","challenge":"AAA","origin":"https://example.test"}"#;
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(client_data));

    let sig = keypair::sign(&pair, &signed).unwrap();
    assert_eq!(sig.len(), 64, "ES256 必须是 64 字节 r‖s");

    let dir = std::env::temp_dir().join("lengsuo-cred-w1-openssl");
    std::fs::create_dir_all(&dir).unwrap();
    let pub_path = dir.join("pub.pem");
    let msg_path = dir.join("msg.bin");
    let sig_path = dir.join("sig.der");
    std::fs::write(&pub_path, public_key_pem(pair.public_point())).unwrap();
    std::fs::write(&msg_path, &signed).unwrap();
    std::fs::write(&sig_path, sig_to_der(&sig)).unwrap();

    // openssl 用 SHA-256 摘要 + 显式 P-256 曲线验证 DER 签名。
    let out = Command::new(&openssl)
        .args(["dgst", "-sha256", "-verify"])
        .arg(&pub_path)
        .arg("-signature")
        .arg(&sig_path)
        .arg(&msg_path)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 把独立验签路径的**真实输出**打出来（交付报告要贴这段）。
    eprintln!("openssl 版本：{}", openssl_version(&openssl));
    eprintln!(
        "openssl dgst -sha256 -verify 退出码：{:?}",
        out.status.code()
    );
    eprintln!("openssl stdout: {}", stdout.trim());
    eprintln!("openssl stderr: {}", stderr.trim());
    assert!(
        out.status.success(),
        "openssl 验签失败：status={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Verified OK"),
        "openssl 未报告 Verified OK：stdout={} stderr={}",
        stdout,
        stderr
    );

    // 反向：篡改消息 ⇒ openssl 必须拒绝。
    let mut tampered = signed.clone();
    tampered[0] ^= 0x01;
    let bad_path = dir.join("msg_bad.bin");
    std::fs::write(&bad_path, &tampered).unwrap();
    let out = Command::new(&openssl)
        .args(["dgst", "-sha256", "-verify"])
        .arg(&pub_path)
        .arg("-signature")
        .arg(&sig_path)
        .arg(&bad_path)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "openssl 不得接受被篡改的消息：stdout={} stderr={}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "openssl 对篡改消息的退出码：{:?}（非 0 = 正确拒绝）",
        out.status.code()
    );
    eprintln!(
        "openssl 对篡改消息的 stderr: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );

    // 清理临时目录。
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::io::stdout().flush();
}
