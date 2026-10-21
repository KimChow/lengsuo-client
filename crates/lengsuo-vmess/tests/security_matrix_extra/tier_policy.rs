//! 档位策略：弱档的**显式区分**、档位枚举**越界拒绝**、AUTO 哨兵 fail-closed。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! 参考事实：
//! - `common/protocol/headers.pb.go:37-44` 的 `SecurityType_name` 表：
//!   `0=UNKNOWN, 2=AUTO, 3=AES128_GCM, 4=CHACHA20_POLY1305, 5=NONE, 6=ZERO`。
//! - `proxy/vmess/encoding/server.go:114-124` 的 `parseSecurityType`：
//!   **表里的值都认**（含 0 与 2 的兼容回退），表外的值 ⇒ `UNKNOWN`。
//! - `proxy/vmess/encoding/server.go:242-243`：`UNKNOWN` / `AUTO` ⇒ 头阶段
//!   拒（`unknown security type`）。
//! - `proxy/vmess/encoding/server.go:264-323`：`switch request.Security`，
//!   `NONE` / `AES128_GCM` / `CHACHA20_POLY1305` 三档有实现，**其余落到
//!   `default:` ⇒ `invalid option: Security`（体阶段拒绝）**。
//! - `proxy/vmess/outbound/outbound.go:116-119`：`ZERO` 在**出口**被改写成
//!   `NONE` 并清掉 `ChunkStream` / `ChunkMasking`（出站降级为无掩码明文）。
//! - `common/protocol/headers.go:83-90` 的 `GetSecurityType()`：`AUTO` 在
//!   有 AES-GCM 硬件支持时解析成 `AES128_GCM`，否则 `CHACHA20_POLY1305`。
//! - `infra/conf/vmess.go:28-40`：`security` 配置项取值
//!   `aes-128-gcm` / `chacha20-poly1305` / `auto` / `none` / `zero`。
//!
//! **本仓的对应实现**：
//! - `crates/lengsuo-vmess/src/request.rs:82-97`（`SecurityOption` 枚举：
//!   `None` / `Aes128Gcm` / `ChaCha20Poly1305` / `AutoCipher` 哨兵）。
//! - `crates/lengsuo-vmess/src/bodyframe.rs:75-84`
//!   （`BodySuite::from_security_byte`：只认 3/4/5，其余 `Unsupported`）。
//! - `crates/lengsuo-vmess/src/server/decode.rs:78-86`
//!   （`HeaderSecurity::from_nibble`：认 3/4/5/6，0/2/表外 ⇒ `None`）。

use super::common::{
    accept_session, plan_header_with_security_nibble, seal_plain_header, CMD_KEY, NOW, TIERS,
};
use lengsuo_vmess::bodyframe::BodySuite;
use lengsuo_vmess::request::SecurityOption;
use lengsuo_vmess::server::{decode_request_header, HeaderDecodeError, HeaderSecurity};

/// 参考 `SecurityType_name` 表（`common/protocol/headers.pb.go:37-44`）。
const REF_SECURITY_TYPE_NAME: [(u8, &str); 6] = [
    (0, "UNKNOWN"),
    (2, "AUTO"),
    (3, "AES128_GCM"),
    (4, "CHACHA20_POLY1305"),
    (5, "NONE"),
    (6, "ZERO"),
];

// ---- 弱档的显式区分 ----

/// `none` 档：**可用但无认证**——必须显式区分于 AES/ChaCha，不得被误当成
/// 「解析失败」而静默变 AES。
///
/// 参考依据：`proxy/vmess/encoding/server.go:265-283` 的 `SecurityType_NONE`
/// 分支用 `NoOpAuthenticator` / `buf.NewReader` ⇒ 载荷明文、无 tag。
#[test]
fn none_tier_is_available_and_explicitly_unauthenticated() {
    let none = TIERS
        .iter()
        .find(|t| t.suite == BodySuite::None)
        .expect("none 档在表内");
    assert_eq!(none.wire, 5, "参考 SecurityType_NONE = 5");
    assert!(!none.suite.is_aead(), "none 档不得带 AEAD");
    assert_eq!(none.suite.overhead(), 0, "none 档无 tag 开销");

    // 载荷确实是明文（无 tag）：封出来的长度 = 明文长度。
    let mut cipher = lengsuo_vmess::bodyframe::BodyCipher::from_suite(
        none.suite,
        &super::common::BODY_KEY,
        &super::common::BODY_IV,
    );
    let ct = cipher.seal_payload(b"plain").expect("可封");
    assert_eq!(
        ct, b"plain",
        "none 档载荷必须是明文（参考 server.go:265-283）"
    );

    // 头阶段：`NONE` 被**认出**（不是 UnknownSecurity）。
    let mut session = accept_session();
    let mut cursor = &seal_plain_header(&plan_header_with_security_nibble(
        SecurityOption::Aes128Gcm,
        5,
    ))[..];
    let decoded = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session)
        .expect("none 档头必须被接受");
    assert_eq!(decoded.security, HeaderSecurity::None);
}

/// `zero` 档：参考**头阶段放行、体阶段拒绝**。本仓必须同样区分它，不得
/// 当成「未知档」提前拒，也不得当成 `none` 放行。
///
/// 参考依据：
/// - 头阶段：`proxy/vmess/encoding/server.go:114-124` 的 `parseSecurityType`
///   认得 6 ⇒ `SecurityType_ZERO`（不被 `server.go:242-243` 的
///   `UNKNOWN`/`AUTO` 判定拦下）。
/// - 体阶段：`server.go:264-323` 的 `switch` 无 `ZERO` 分支 ⇒ 落 `default:`
///   ⇒ `invalid option: Security`。
/// - 出口侧改写：`proxy/vmess/outbound/outbound.go:116-119`。
#[test]
fn zero_tier_is_rejected_at_body_stage_not_at_header_stage() {
    // 本仓头阶段：`from_nibble(6)` 必须认出 `Zero`（不是 None）。
    assert_eq!(HeaderSecurity::from_nibble(6), Some(HeaderSecurity::Zero));
    assert_eq!(HeaderSecurity::Zero.to_byte(), 6);

    // 头阶段放行：解出来必须是 `Zero`，且**不是** UnknownSecurity。
    let mut session = accept_session();
    let mut cursor = &seal_plain_header(&plan_header_with_security_nibble(
        SecurityOption::Aes128Gcm,
        6,
    ))[..];
    let decoded = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session)
        .expect("zero 档头阶段必须放行（对齐参考 server.go:114-124）");
    assert_eq!(
        decoded.security,
        HeaderSecurity::Zero,
        "zero 档必须被显式区分于 none / AES"
    );

    // 体阶段：数据段套件解析必须**显式拒绝** `ZERO`（对齐参考 server.go:323
    // 的 `invalid option: Security`），不得退化成 none 或 AES。
    let err = BodySuite::from_security_byte(6).expect_err("zero 档体阶段必须拒绝");
    assert!(
        matches!(err, lengsuo_vmess::Error::Unsupported { .. }),
        "zero 档体阶段必须 Unsupported，实际 {err:?}"
    );
    // 数据段上下文构造（走 `BodyCipher::new`）同样必须拒。
    // `BodyCipher` 不实现 `Debug`（刻意，避免密钥泄漏）⇒ 用 `match` 取错误。
    let err = match lengsuo_vmess::bodyframe::BodyCipher::new(
        6,
        &super::common::BODY_KEY,
        &super::common::BODY_IV,
    ) {
        Ok(_) => panic!("zero 档不得构造出数据段上下文"),
        Err(error) => error,
    };
    assert!(matches!(err, lengsuo_vmess::Error::Unsupported { .. }));
}

/// `zero` 档**不得**被静默降级成 `none`（参考出口明确改写，本仓服务端不许）。
#[test]
fn zero_tier_is_never_silently_downgraded_to_none() {
    // 数据段：zero 不可用 ⇒ 不存在「解出来是明文」的路径。
    assert!(BodySuite::from_security_byte(6).is_err());
    // 但 `none`（5）可用且是明文——两者行为必须不同。
    let none = BodySuite::from_security_byte(5).expect("none 档可用");
    assert_ne!(none.security_byte(), 6);
    assert!(!none.is_aead());
}

// ---- 档位枚举越界 ----

/// 档位枚举**越界**（不在参考 `SecurityType_name` 表里的编号）⇒ 必须**显式拒绝**。
///
/// 参考依据：
/// - `proxy/vmess/encoding/server.go:114-124`：`parseSecurityType` 对表外值
///   返回 `UNKNOWN`；`server.go:242-243` 对 `UNKNOWN` 报 `unknown security type`
///   ⇒ 表外值在**头阶段**即被拒。
#[test]
fn out_of_range_security_nibbles_are_rejected_explicitly() {
    // 参考表里没有的编号（1、7..15）。
    for nibble in [1u8, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        // 头阶段：解析必须返回 None（⇒ 拒绝）。
        assert_eq!(
            HeaderSecurity::from_nibble(nibble),
            None,
            "security={nibble} 不在参考 SecurityType_name 表内，必须拒"
        );
        // 端到端：一条带该 security 字节的合法请求（校验和已重算）必须被拒。
        let mut session = accept_session();
        let mut cursor = &seal_plain_header(&plan_header_with_security_nibble(
            SecurityOption::Aes128Gcm,
            nibble,
        ))[..];
        let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
        assert!(
            matches!(result, Err(HeaderDecodeError::UnknownSecurity)),
            "security={nibble} 必须 UnknownSecurity，实际 {:?}",
            result.map(|_| ())
        );
    }
}

/// 参考表内的**哨兵**档（`UNKNOWN`=0 / `AUTO`=2）⇒ 头阶段显式拒绝。
///
/// 参考依据：
/// - `proxy/vmess/encoding/server.go:114-124`：`0` 被兼容回退成 `AUTO`
///   （`st == UNKNOWN ⇒ st = AUTO`），`2` 本就是 `AUTO`；
/// - `server.go:242-243`：`UNKNOWN` / `AUTO` ⇒ `unknown security type`。
#[test]
fn unknown_and_auto_security_nibbles_are_rejected_explicitly() {
    for (nibble, label) in [(0u8, "UNKNOWN"), (2u8, "AUTO")] {
        assert_eq!(
            HeaderSecurity::from_nibble(nibble),
            None,
            "{label} 必须头阶段拒绝"
        );
        let mut session = accept_session();
        let mut cursor = &seal_plain_header(&plan_header_with_security_nibble(
            SecurityOption::Aes128Gcm,
            nibble,
        ))[..];
        let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
        assert!(
            matches!(result, Err(HeaderDecodeError::UnknownSecurity)),
            "{label} 必须 UnknownSecurity，实际 {:?}",
            result.map(|_| ())
        );
    }
}

/// 数据段：越界档位字节 ⇒ `BodySuite` / `BodyCipher` 显式 `Unsupported`，
/// 绝不退化成明文或 AES。
#[test]
fn out_of_range_security_bytes_fail_closed_in_body_segment() {
    for byte in [0u8, 1, 2, 6, 7, 8, 9, 0x0F, 0xFF] {
        let err = BodySuite::from_security_byte(byte).expect_err("越界档位必须拒绝");
        assert!(
            matches!(err, lengsuo_vmess::Error::Unsupported { .. }),
            "security byte={byte} 必须 Unsupported，实际 {err:?}"
        );
        let err = match lengsuo_vmess::bodyframe::BodyCipher::new(
            byte,
            &super::common::BODY_KEY,
            &super::common::BODY_IV,
        ) {
            Ok(_) => panic!("越界档位不得构造出数据段上下文"),
            Err(error) => error,
        };
        assert!(matches!(err, lengsuo_vmess::Error::Unsupported { .. }));
    }
}

/// `AutoCipher` 哨兵：本仓**刻意不代参考解析**（参考 `GetSecurityType()` 会
/// 按硬件支持解析成 AES 或 ChaCha），原语层必须 fail-closed。
///
/// 参考依据：`common/protocol/headers.go:83-90`。
#[test]
fn autocipher_sentinel_fails_closed_at_primitive_layer() {
    // 头规划器直接拒。
    let planner = lengsuo_vmess::request::HeaderPlanner::new(lengsuo_vmess::request::KeySource {
        body_key: super::common::BODY_KEY,
        body_iv: super::common::BODY_IV,
        response_header: 0x33,
    });
    let header = lengsuo_vmess::request::RequestHeader {
        target: Some(ss_core::target::TargetAddr::Domain(
            "example.invalid".into(),
            443,
        )),
        command: lengsuo_vmess::request::Command::Tcp,
        security: SecurityOption::AutoCipher,
        option: 0,
        padding_len: 0,
    };
    let result = planner.plan_with(&header, &[]);
    assert!(
        matches!(result, Err(lengsuo_vmess::Error::Unsupported { .. })),
        "AutoCipher 必须被拒，实际 {result:?}"
    );
    // `resolve()` 对哨兵返回 None（调用方自己决定），且**不默认 AES**。
    assert_eq!(SecurityOption::AutoCipher.resolve(), None);
}

/// 本仓的档位表与参考 `SecurityType_name` 表**逐项对齐**（防漂移）。
#[test]
fn local_tier_table_matches_reference_security_type_names() {
    // 本仓三个受支持档 ⇒ 参考表里的对应名。
    let expected: [(u8, &str); 3] = [(5, "NONE"), (3, "AES128_GCM"), (4, "CHACHA20_POLY1305")];
    for (byte, name) in expected {
        let found = REF_SECURITY_TYPE_NAME
            .iter()
            .find(|(b, _)| *b == byte)
            .map(|(_, n)| *n)
            .expect("参考表里必须有该档");
        assert_eq!(found, name, "档位 {byte} 的参考名必须是 {name}");
    }
    // 本仓三个受支持档恰好是参考表里「服务端有实现」的三档
    // （`server.go:264-323` 的 switch 分支）。
    let mut local: Vec<u8> = TIERS.iter().map(|t| t.wire).collect();
    local.sort_unstable();
    assert_eq!(
        local,
        vec![3, 4, 5],
        "本仓受支持档必须是 AES/ChaCha/NONE 三档"
    );
}

/// `SecurityOption` 的线上字节与参考枚举值逐项对齐。
#[test]
fn security_option_wire_bytes_match_reference_enum() {
    assert_eq!(SecurityOption::None.to_byte(), 5);
    assert_eq!(SecurityOption::Aes128Gcm.to_byte(), 3);
    assert_eq!(SecurityOption::ChaCha20Poly1305.to_byte(), 4);
    assert_eq!(SecurityOption::AutoCipher.to_byte(), 2);
    // 往返解析。
    for tier in TIERS {
        assert_eq!(
            SecurityOption::from_byte(tier.wire),
            Some(tier.option),
            "档位 {} 的字节往返必须自洽",
            tier.name
        );
    }
    assert_eq!(SecurityOption::from_byte(0), None);
    assert_eq!(
        SecurityOption::from_byte(6),
        None,
        "zero 不在客户端档位表内"
    );
}

/// `Tier` 表里的名字与档位必须一一对应（防测试自身写错档）。
#[test]
fn tier_table_entries_are_self_consistent() {
    for tier in TIERS {
        assert_eq!(tier.option.to_byte(), tier.wire);
        assert_eq!(tier.option.resolve(), Some(tier.suite));
        assert_eq!(tier.suite.security_byte(), tier.wire);
    }
    // 三个档名互不相同（防复制粘贴写错）。
    let mut names: Vec<&str> = TIERS.iter().map(|t| t.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), TIERS.len(), "档名必须互不相同");
}
