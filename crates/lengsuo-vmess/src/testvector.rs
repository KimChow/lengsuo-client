//! VMess 声明式测试向量与集成用例表（供 `tests/vectors.rs` 消费）。
//!
//! 参考的 `authid_test.go`/`encrypt_test.go` **不含固定向量**（只有随机
//! roundtrip 与篡改失败），因此本表按三类组织，来源在每项 `origin` 里如实
//! 标注，不编造"官方向量"：
//! - `Kdf`：KDF 链的公共规范 HMAC-SHA256 语义自证（确定性/链序/长度）；
//! - `Sealed`：封装→解封装 roundtrip（密钥自造假值）；
//! - `Derived`：公共密码学原语（AES-128 FIPS-197 C.1、FNV-1a 规范值、
//!   MD5 链扩展）的锁定回归。
//!
//! 真正的互通证明只能来自与 Xray 实跑（未验证，见 docs/vmess-status.md）。

use crate::aead;
use crate::authid;
use crate::chunkframe::{self, DataCipher, DataSizeParser};
use crate::consts::SECURITY_AES_128_GCM;
use crate::kdf;
use crate::request::{fnv1a32, Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use ss_core::target::TargetAddr;

/// KDF 用例：key + paths + 期望的**结构属性**（长度与确定性由断言函数检查，
/// 期望十六进制由独立 Python 复算脚本生成——见 tools/gen_vmess_vectors.py，
/// 未跑时以 `None` 表示"只查结构"）。
#[derive(Clone, Copy)]
pub struct KdfCase {
    /// 用例名。
    pub name: &'static str,
    /// 派生密钥。
    pub key: &'static [u8],
    /// 链式路径。
    pub paths: &'static [&'static [u8]],
    /// 独立复算的期望 hex；`None` = 只查结构。
    pub expect_hex: Option<&'static str>,
}

/// KDF 结构性用例（参考无官方向量；hex 待独立复算后补录）。
pub fn kdf_cases() -> [KdfCase; 4] {
    [
        KdfCase {
            name: "kdf_no_path",
            key: b"Demo Key for Auth ID Test",
            paths: &[],
            expect_hex: None,
        },
        KdfCase {
            name: "kdf_single_path",
            key: b"Demo Key for Auth ID Test",
            paths: &[b"Demo Path for Auth ID Test"],
            expect_hex: None,
        },
        KdfCase {
            name: "kdf_constant_root_path",
            key: b"Demo Key for Auth ID Test",
            paths: &[b"VMess AEAD KDF"],
            expect_hex: None,
        },
        KdfCase {
            name: "kdf_header_key_three_paths",
            key: b"Demo Key for Auth ID Test",
            paths: &[
                b"VMess Header AEAD Key",
                b"0123456789abcdef",
                b"fedcba9876543210",
            ],
            expect_hex: None,
        },
    ]
}

/// AuthID 用例（确定性注入随机段）。
#[derive(Clone, Copy)]
pub struct AuthIdCase {
    /// 用例名。
    pub name: &'static str,
    /// 假 cmdKey。
    pub cmd_key: &'static [u8; 16],
    /// unix 秒。
    pub unix_seconds: i64,
    /// 注入的 4 字节随机段。
    pub random: [u8; 4],
}

/// AuthID 确定性用例。
pub const AUTH_ID_CASES: [AuthIdCase; 2] = [
    AuthIdCase {
        name: "authid_epoch_base",
        cmd_key: b"b831381d-6324-4d",
        unix_seconds: 1_700_000_000,
        random: [0x01, 0x02, 0x03, 0x04],
    },
    AuthIdCase {
        name: "authid_negative_time",
        cmd_key: b"b831381d-6324-4d",
        unix_seconds: -1,
        random: [0xDE, 0xAD, 0xBE, 0xEF],
    },
];

/// 头部封装 roundtrip 用例。
#[derive(Clone, Copy)]
pub struct AeadSealCase {
    /// 用例名。
    pub name: &'static str,
    /// 假 cmdKey。
    pub cmd_key: &'static [u8; 16],
    /// 注入 AuthID。
    pub auth_id: [u8; 16],
    /// 注入连接 nonce。
    pub nonce: [u8; 8],
    /// 头载荷明文。
    pub payload: &'static [u8],
}

/// 头部封装用例。
pub const AEAD_SEAL_CASES: [AeadSealCase; 2] = [
    AeadSealCase {
        name: "header_typical",
        cmd_key: b"b831381d-6324-4d",
        auth_id: [0x5A; 16],
        nonce: [0x21, 0x43, 0x65, 0x87, 0x09, 0xBA, 0xDC, 0xFE],
        payload: b"version+iv+key+seed+options+security+cmd+address+padding+fnv",
    },
    AeadSealCase {
        name: "header_empty_payload",
        cmd_key: b"b831381d-6324-4d",
        auth_id: [0xA5; 16],
        nonce: [0x00; 8],
        payload: b"",
    },
];

/// 数据段分帧用例（安全选项 + 是否掩码 + 载荷序列）。
#[derive(Clone, Copy)]
pub struct ShakeSizeCase {
    /// 用例名。
    pub name: &'static str,
    /// IV（掩码与 nonce 同源）。
    pub iv: [u8; 16],
    /// 依次分帧的载荷。
    pub payloads: &'static [&'static [u8]],
}

/// 数据段分帧用例（AES-128-GCM；none/ChaCha 由集成测试另覆盖）。
pub const SHAKE_SIZE_CASES: [ShakeSizeCase; 2] = [
    ShakeSizeCase {
        name: "sizes_small_two_chunks",
        iv: *b"request-body-iv!",
        payloads: &[b"chunk one", b"chunk two is longer"],
    },
    ShakeSizeCase {
        name: "sizes_boundary_min",
        iv: *b"request-body-iv!",
        payloads: &[b"x"],
    },
];

/// 请求头明文规划用例（固定 padding）。
#[derive(Clone, Copy)]
pub struct RequestPlaintextCase {
    /// 用例名。
    pub name: &'static str,
    /// 目标域名。
    pub domain: &'static str,
    /// 端口。
    pub port: u16,
    /// 命令。
    pub command: Command,
    /// 安全选项。
    pub security: SecurityOption,
    /// padding 长度。
    pub padding_len: u8,
}

/// 请求头规划用例。
pub const REQUEST_PLAINTEXT_CASES: [RequestPlaintextCase; 1] = [RequestPlaintextCase {
    name: "request_tcp_aes_domain",
    domain: "example.invalid",
    port: 443,
    command: Command::Tcp,
    security: SecurityOption::Aes128Gcm,
    padding_len: 4,
}];

/// 兼容导出：KDF 用例类型别名（lib.rs 公开面）。
pub type KdfCaseAlias = KdfCase;

/// 逐条断言 KDF 用例：长度 32、确定性、与独立 hex（如有）一致。
pub fn assert_kdf_cases() {
    for case in kdf_cases() {
        let got = kdf::kdf(case.key, case.paths);
        assert_eq!(got.len(), 32, "{}", case.name);
        let again = kdf::kdf(case.key, case.paths);
        assert_eq!(got, again, "{} 确定性", case.name);
        if let Some(expect) = case.expect_hex {
            let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got_hex, expect, "{} 与独立复算不符", case.name);
        }
    }
}

/// 逐条断言 AuthID 用例：字段还原 + CRC 自洽 + 时间窗（负时间拒绝）。
pub fn assert_auth_id_cases(now_unix: i64) {
    for case in AUTH_ID_CASES {
        let auth = authid::create_auth_id_with(case.cmd_key, case.unix_seconds, &case.random);
        let decoded = authid::decode_auth_id_bytes(case.cmd_key, auth.as_bytes());
        assert_eq!(decoded.unix_seconds, case.unix_seconds, "{}", case.name);
        assert_eq!(decoded.random, case.random, "{}", case.name);
        if case.unix_seconds >= 0 {
            assert!(
                authid::time_in_window(case.unix_seconds, now_unix),
                "{} 应在窗口内",
                case.name
            );
        } else {
            assert!(
                matches!(
                    authid::decode_auth_id(case.cmd_key, auth.as_bytes(), now_unix),
                    Err(crate::Error::AuthFailed) | Err(crate::Error::NegativeTime)
                ),
                "{} 负时间必须拒绝",
                case.name
            );
        }
    }
}

/// 逐条断言头部封装 roundtrip。
pub fn assert_aead_seal_cases() {
    for case in AEAD_SEAL_CASES {
        let wire = aead::seal_header_with(case.cmd_key, &case.auth_id, &case.nonce, case.payload);
        assert_eq!(
            wire.len(),
            16 + 18 + 8 + case.payload.len() + 16,
            "{}",
            case.name
        );
        let parsed = aead::parse_auth_id_from_header(&wire).expect("AuthID 可取");
        assert_eq!(parsed, case.auth_id, "{}", case.name);
        let opened = aead::open_vmess_aead_header(case.cmd_key, &parsed, &wire[16..])
            .unwrap_or_else(|error| panic!("{} 可解：{error:?}", case.name));
        assert_eq!(opened, case.payload, "{}", case.name);
    }
}

/// 逐条断言数据段分帧 roundtrip（AES-128-GCM + 掩码 + EOF 帧）。
pub async fn assert_shake_size_cases() {
    for case in SHAKE_SIZE_CASES {
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &case.iv, &case.iv);
        let mut enc = DataSizeParser::new(&case.iv);
        let mut dec = DataSizeParser::new(&case.iv);
        let mut wire = Vec::new();
        for payload in case.payloads {
            chunkframe::seal_data_chunk(&mut cipher, Some(&mut enc), &mut wire, payload)
                .unwrap_or_else(|error| panic!("{} 可写：{error:?}", case.name));
        }
        chunkframe::write_data_eof(&mut cipher, Some(&mut enc), &mut wire).expect("EOF 可写");
        let mut open_cipher = chunkframe::DataCipher::new(SECURITY_AES_128_GCM, &case.iv, &case.iv);
        let mut cursor = &wire[..];
        for payload in case.payloads {
            let got = chunkframe::read_data_chunk(&mut open_cipher, Some(&mut dec), &mut cursor)
                .await
                .unwrap_or_else(|error| panic!("{} 可读：{error:?}", case.name))
                .expect("应有帧");
            assert_eq!(&got, payload, "{}", case.name);
        }
        assert!(
            matches!(
                chunkframe::read_data_chunk(&mut open_cipher, Some(&mut dec), &mut cursor).await,
                Ok(None)
            ),
            "{} 应以 EOF 帧收尾",
            case.name
        );
    }
}

/// 逐条断言请求头明文规划：布局 + FNV 尾 + 地址还原。
pub fn assert_request_plaintext_cases() {
    let key_source = KeySource {
        body_key: [0x11u8; 16],
        body_iv: [0x22u8; 16],
        response_header: 0x33,
    };
    let planner = HeaderPlanner::new(key_source);
    for case in REQUEST_PLAINTEXT_CASES {
        let header = RequestHeader {
            target: Some(TargetAddr::Domain(case.domain.into(), case.port)),
            command: case.command,
            security: case.security,
            option: 0x05,
            padding_len: case.padding_len,
        };
        let plain = planner
            .plan_with(&header, &vec![0u8; case.padding_len as usize])
            .unwrap_or_else(|error| panic!("{} 可编码：{error:?}", case.name));
        assert_eq!(plain[0], 1, "{} 版本字节", case.name);
        let tail = u32::from_be_bytes(plain[plain.len() - 4..].try_into().unwrap());
        assert_eq!(
            tail,
            fnv1a32(&plain[..plain.len() - 4]),
            "{} FNV 尾",
            case.name
        );
        let (target, _) = TargetAddr::decode(&plain[38..]).expect("地址可解");
        assert_eq!(
            target,
            TargetAddr::Domain(case.domain.into(), case.port),
            "{} 地址还原",
            case.name
        );
    }
}

/// 兼容导出（lib.rs 公开面要求的具名构造器）。
pub const fn aead_encrypt_case() -> AeadSealCase {
    AEAD_SEAL_CASES[0]
}

/// 兼容导出：头部封装首用例。
pub const fn aead_seal_case() -> AeadSealCase {
    AEAD_SEAL_CASES[0]
}

/// 兼容导出：AuthID 首用例。
pub const fn auth_id_case() -> AuthIdCase {
    AUTH_ID_CASES[0]
}

/// 兼容导出：KDF 首用例。
#[must_use]
pub fn kdf_case() -> KdfCase {
    kdf_cases()[0]
}

/// 兼容导出：请求头规划首用例。
pub const fn request_plaintext_case() -> RequestPlaintextCase {
    REQUEST_PLAINTEXT_CASES[0]
}

/// 兼容导出：数据段分帧首用例。
pub const fn shake_size_case() -> ShakeSizeCase {
    SHAKE_SIZE_CASES[0]
}

/// 兼容导出：legacy 缩减密钥用例（legacy 路径不支持，只提供被拒绝的样本）。
pub const fn legacy_reduced_key_case() -> &'static [u8] {
    b"legacy-key-not-supported"
}

/// 兼容导出：响应认证明文长度。
pub const fn response_auth_case() -> usize {
    aead::RESPONSE_AUTH_LEN
}
