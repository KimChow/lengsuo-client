//! VMess 声明式向量与集成断言（消费 src/testvector.rs 的用例表）。
//!
//! 参考的 Go 测试不含固定向量（只有随机 roundtrip），因此这里验证三类事实：
//! ① 公共密码学原语的标准向量（HMAC-SHA256 RFC 4231、AES-128 FIPS-197 C.1、
//!   FNV-1a 规范值）；② KDF/AuthID/头部封装/数据段分帧的确定性 roundtrip；
//! ③ 请求头明文布局与 FNV 尾。与 Xray 运行时的握手互通**未验证**，
//! 不在本测试范围内（见 docs/vmess-status.md）。

use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use lengsuo_vmess::testvector;
use ss_core::target::TargetAddr;

/// 固定会话假值下的请求头明文（padding_len=0，杜绝随机项）。
fn plan(target: &TargetAddr) -> Vec<u8> {
    let planner = HeaderPlanner::new(KeySource {
        body_key: [0x11u8; 16],
        body_iv: [0x22u8; 16],
        response_header: 0x33,
    });
    let header = RequestHeader {
        target: Some(target.clone()),
        command: Command::Tcp,
        security: SecurityOption::Aes128Gcm,
        option: 0x05,
        padding_len: 0,
    };
    planner.plan_with(&header, &[]).expect("请求头明文可编码")
}

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

/// 请求头明文固定字节向量（逐字节比对，锁定 VMess addrParser 写法）。
///
/// 语义来源：`proxy/vmess/encoding/encoding.go` 的 `addrParser` =
/// `AddressFamilyByte(AddressTypeIPv4=1)` / `AddressFamilyByte(AddressTypeDomain=2)` /
/// `AddressFamilyByte(AddressTypeIPv6=3)` + **`PortThenAddress()`**，即
/// `Port(BE16) | AddrType(1) | ADDR`，与 SOCKS5 的 `ATYP | ADDR | Port` 完全不同。
/// 期望字节由 Python 独立复算（前缀 38B + 地址段 + FNV-1a32 尾），非本实现产物：
/// 会话假值 `body_iv=0x22*16`、`body_key=0x11*16`、`response_header=0x33`、
/// `option=0x05`、`security=(0<<4)|AES-128-GCM=0x03`、`reserved=0x00`、`command=TCP=0x01`、
/// `padding_len=0`。security 字节固定在 `0x03`：与 `common/protocol/headers.pb.go`
/// `SecurityType_AES128_GCM=3` 一致（旧向量 0x01 是自造的枚举，属互通性 bug）。
#[test]
fn request_plaintext_ipv4_is_port_then_type1_then_addr() {
    let expected = hex::decode("012222222222222222222222222222222211111111111111111111111111111111330503000101bb01c00002017276f710").unwrap();
    assert_eq!(
        plan(&TargetAddr::V4([192, 0, 2, 1], 443)),
        expected,
        "IPv4 必须写 Port(BE16)|1|ADDR"
    );
}

#[test]
fn request_plaintext_ipv6_is_port_then_type3_then_addr() {
    let expected = hex::decode("01222222222222222222222222222222221111111111111111111111111111111133050300011f900320202020202020202020202020202020000a8cd6").unwrap();
    assert_eq!(
        plan(&TargetAddr::V6([0x20; 16], 8080)),
        expected,
        "IPv6 必须写 Port(BE16)|3|ADDR（不是 SOCKS5 的 0x04）"
    );
}

#[test]
fn request_plaintext_domain_is_port_then_type2_len_addr() {
    let expected = hex::decode("012222222222222222222222222222222211111111111111111111111111111111330503000120fb020f6578616d706c652e696e76616c69645f25e467").unwrap();
    assert_eq!(
        plan(&TargetAddr::Domain("example.invalid".into(), 8443)),
        expected,
        "域名必须写 Port(BE16)|2|Len|DOMAIN"
    );
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
