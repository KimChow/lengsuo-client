//! VMess 声明式向量与集成断言（消费 src/testvector.rs 的用例表）。
//!
//! 参考的 Go 测试不含固定向量（只有随机 roundtrip），因此这里验证三类事实：
//! ① 公共密码学原语的标准向量（HMAC-SHA256 RFC 4231、AES-128 FIPS-197 C.1、
//!   FNV-1a 规范值）；② KDF/AuthID/头部封装/数据段分帧的确定性 roundtrip；
//! ③ 请求头明文布局与 FNV 尾。与 Xray 运行时的握手互通**未验证**，
//! 不在本测试范围内（见 docs/vmess-status.md）。

use lengsuo_vmess::testvector;

#[test]
fn kdf_cases_structural_and_rfc4231_anchor() {
    testvector::assert_kdf_cases();
}

#[test]
fn authid_cases_roundtrip_and_window() {
    testvector::assert_auth_id_cases(1_700_000_000);
}

#[test]
fn aead_seal_cases_roundtrip() {
    testvector::assert_aead_seal_cases();
}

#[tokio::test]
async fn shake_size_cases_roundtrip() {
    testvector::assert_shake_size_cases().await;
}

#[test]
fn request_plaintext_cases_layout() {
    testvector::assert_request_plaintext_cases();
}

/// 端到端小循环：请求头明文 → AEAD 封装 → 解封装逐字节一致
/// （KeySource/输入全部自造假值）。
#[test]
fn header_plan_then_seal_open_roundtrip() {
    use lengsuo_vmess::request::{
        Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption,
    };
    use ss_core::target::TargetAddr;

    let planner = HeaderPlanner::new(KeySource {
        body_key: [0x11u8; 16],
        body_iv: [0x22u8; 16],
        response_header: 0x33,
    });
    let header = RequestHeader {
        target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
        command: Command::Tcp,
        security: SecurityOption::Aes128Gcm,
        option: 0x05,
        padding_len: 4,
    };
    let plain = planner
        .plan_with(&header, &[0u8; 4])
        .expect("请求头明文可编码");
    assert_eq!(plain[0], 1);

    let cmd_key = *b"b831381d-6324-4d";
    let auth_id = [0x5Au8; 16];
    let nonce = [0x08u8; 8];
    let wire = lengsuo_vmess::aead::seal_header_with(&cmd_key, &auth_id, &nonce, &plain);
    assert_eq!(&wire[..16], &auth_id[..]);
    let opened =
        lengsuo_vmess::aead::open_vmess_aead_header(&cmd_key, &auth_id, &wire[16..]).expect("可解");
    assert_eq!(opened, plain, "封装→解封装必须逐字节一致");
}

/// 错误路径：篡改头部密文必须 fail-closed（AuthFailed）且不 panic。
#[test]
fn tampered_header_fails_closed() {
    use lengsuo_vmess::aead;
    let cmd_key = *b"b831381d-6324-4d";
    let auth_id = [0xA5u8; 16];
    let nonce = [0x01u8; 8];
    let mut wire = aead::seal_header_with(&cmd_key, &auth_id, &nonce, b"payload");
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    assert!(matches!(
        aead::open_vmess_aead_header(&cmd_key, &auth_id, &wire[16..]),
        Err(lengsuo_vmess::Error::AuthFailed)
    ));
}
