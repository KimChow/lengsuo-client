//! 错误路径向量：**确定性输入 → 稳定标签**的映射。
//!
//! # 为什么要「稳定标签」而不是 Rust `Debug` 文本
//!
//! `Display` / `Debug` 的措辞会随实现改动而变，把它当跨端契约 ⇒ 移动端
//! 一升级就误判。本卡给每个错误类别一个**稳定的 kebab-case 标签**
//! （见 [`super::frame_label`] / [`super::session_label`]），
//! 移动端按标签判断失败原因。
//!
//! # 覆盖的场景
//!
//! | 场景 | 输入 | 稳定标签 |
//! |---|---|---|
//! | 帧魔数错误 | 改坏头 1 字节 | `frame.bad_magic` |
//! | 帧 CRC 不符 | 改坏头内校验位 | `frame.header_crc_mismatch` |
//! | 载荷超上限 | `MAX_FRAME_PAYLOAD_LEN + 1` | `frame.payload_too_long` |
//! | 会话角色不符 | 发起方调 `consume_initiation` | `session.role_mismatch` |
//! | 世代号不匹配 | 两侧世代号不同 | `session.generation_mismatch` |
//! | 认证失败 | 用错误密钥解封 | `session.auth_failed` |
//! | 截断输入 | 帧被截短 | `frame.incomplete` |
//!
//! ⛔ 错误向量里的密钥**全部是测试专用假值**。

use lengsuo_link_core::frame::{seal_frame, FrameType, MAX_FRAME_PAYLOAD_LEN, MAX_PLAIN_LEN};
use lengsuo_link_core::session::SessionRole;
use lengsuo_wireguard::transport::{Sender, TransportKey};

use super::{num_field, object_entries, session_error_label, session_label, str_field};

pub use super::scenarios::{run_scenario, run_scenario_with_state};

/// 错误向量 JSON 的**格式标识**。
pub const FORMAT: &str = "lengsuo-link-error-vectors";
/// 错误向量 JSON 的**版本号**。
pub const VERSION: u64 = 1;
/// 错误向量 JSON 指向的规范文档。
pub const SPEC: &str = "docs/link-vectors-spec.md";

/// 错误向量 JSON（**纯 JSON 文本**，无注释无尾逗号）。
pub const ERROR_VECTORS_JSON: &str = r##"{
  "format": "lengsuo-link-error-vectors",
  "version": 1,
  "spec": "docs/link-vectors-spec.md",
  "vectors": [
    {
      "name": "frame-bad-magic",
      "scenario": "帧头魔数被改坏（不是 0x4C53）",
      "operation": "decode_frame",
      "expected_label": "frame.bad_magic",
      "expect_no_plaintext": true,
      "expect_session_invalidated": false,
      "input_hex": "4d53010100000000000000010014000000000000",
      "parameters": {}
    },
    {
      "name": "frame-header-crc-mismatch",
      "scenario": "帧头前 16 字节被改坏，CRC 与声明不符",
      "operation": "decode_frame",
      "expected_label": "frame.header_crc_mismatch",
      "expect_no_plaintext": true,
      "expect_session_invalidated": false,
      "input_hex": "4c530101000000000000000100140000deadbeef",
      "parameters": {}
    },
    {
      "name": "frame-incomplete",
      "scenario": "帧被截短，不足以切出一帧",
      "operation": "decode_frame",
      "expected_label": "frame.incomplete",
      "expect_no_plaintext": true,
      "expect_session_invalidated": false,
      "input_hex": "4c53010100000000000000",
      "parameters": {}
    },
    {
      "name": "frame-payload-too-long",
      "scenario": "明文长度超过上限（1401 字节 > 1368）",
      "operation": "seal_frame_oversize",
      "expected_label": "frame.payload_too_long",
      "expect_no_plaintext": true,
      "expect_session_invalidated": false,
      "input_hex": "",
      "parameters": {
        "plain_len": "1401"
      }
    },
    {
      "name": "session-auth-failed",
      "scenario": "用另一条链路的密钥封出的帧，在本链路解封",
      "operation": "session_open_frame",
      "expected_label": "session.auth_failed",
      "expect_no_plaintext": true,
      "expect_session_invalidated": true,
      "input_hex": "63726f73732d6c696e6b",
      "parameters": {}
    }
  ]
}
"##;

/// 一条错误向量。
#[derive(Debug, Clone)]
pub struct ErrorVector {
    /// 场景名（唯一）。
    pub name: String,
    /// 场景说明。
    pub scenario: String,
    /// 触发错误的**操作**。
    pub operation: String,
    /// 期望的**稳定标签**。
    pub expected_label: String,
    /// 期望「**不回退明文**」时为 `true`。
    pub expect_no_plaintext: bool,
    /// 期望会话就此**失效**时为 `true`。
    pub expect_session_invalidated: bool,
    /// 触发用的输入字节（十六进制）。
    pub input_hex: String,
    /// 附加参数（键值对，按操作解释）。
    pub parameters: Vec<(String, String)>,
}

impl ErrorVector {
    /// 取一个附加参数。
    pub fn parameter(&self, key: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

/// 解析错误向量 JSON。
pub fn parse_error_vectors() -> Vec<ErrorVector> {
    assert_eq!(
        str_field(ERROR_VECTORS_JSON, "format"),
        FORMAT,
        "向量格式标识不符"
    );
    assert_eq!(
        num_field(ERROR_VECTORS_JSON, "version"),
        VERSION,
        "向量版本号不符"
    );
    assert_eq!(
        str_field(ERROR_VECTORS_JSON, "spec"),
        SPEC,
        "向量规范文档路径不符"
    );
    super::array_items(ERROR_VECTORS_JSON, "vectors")
        .iter()
        .map(|item| {
            // 布尔字段用**真正的 JSON 解析**读（而不是 `contains("\"k\": true")`）：
            // 后者会被字符串值里的同名字面量误命中。
            // `array_items` 返回的是对象的**内部**文本（不含最外层花括号）
            // ⇒ 解析前要补回花括号。
            let parsed = super::json::parse(&format!("{{{item}}}"));
            ErrorVector {
                name: str_field(item, "name"),
                scenario: str_field(item, "scenario"),
                operation: str_field(item, "operation"),
                expected_label: str_field(item, "expected_label"),
                expect_no_plaintext: parsed.field("expect_no_plaintext").as_bool(),
                expect_session_invalidated: parsed.field("expect_session_invalidated").as_bool(),
                input_hex: str_field(item, "input_hex"),
                parameters: object_entries(item, "parameters"),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- 测试用假密钥

/// 测试专用静态私钥（发起方）。
pub const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
/// 测试专用静态公钥（发起方）。
pub const INITIATOR_PUBLIC: [u8; 32] = [
    0x7b, 0x4e, 0x90, 0x9b, 0xbe, 0x7f, 0xfe, 0x44, 0xc4, 0x65, 0xa2, 0x20, 0x03, 0x7d, 0x60, 0x8e,
    0xe3, 0x58, 0x97, 0xd3, 0x1e, 0xf9, 0x72, 0xf0, 0x7f, 0x74, 0x89, 0x2c, 0xb0, 0xf7, 0x3f, 0x13,
];
/// 测试专用静态私钥（响应方）。
pub const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
/// 「另一条链路」发起方的静态私钥（测试专用，0x99 模式字节）。
/// ⇒ 与 `INITIATOR_STATIC` 不同 ⇒ 派生出的传输密钥不同 ⇒ 跨链路解封必然认证失败。
pub const OTHER_INITIATOR_STATIC: [u8; 32] = [0x99; 32];
/// 「另一条链路」发起方的静态公钥（私钥 = 0x99 × 32；仓外独立算出）。
pub const OTHER_INITIATOR_PUBLIC: [u8; 32] = [
    0xba, 0x19, 0x38, 0x36, 0xcf, 0xf1, 0xf4, 0xe8, 0x66, 0xc1, 0x39, 0x71, 0x5d, 0x30, 0x64, 0x08,
    0xd2, 0x6a, 0x76, 0xf7, 0x6d, 0x63, 0x8a, 0x39, 0xaf, 0xc1, 0x00, 0x10, 0x84, 0xd2, 0x54, 0x11,
];
/// 测试专用静态公钥（响应方）。
pub const RESPONDER_PUBLIC: [u8; 32] = [
    0x0f, 0xaa, 0x68, 0x4e, 0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce,
    0x97, 0x4e, 0x76, 0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20,
];
/// 测试专用「错误密钥」（全 `0x5A`），**不得**用于任何真实会话。
pub const WRONG_KEY: [u8; 32] = [0x5A; 32];

// ---------------------------------------------------------------- 场景重算

/// 构造一条**合法**的密文帧（用测试密钥与固定计数器）。
///
/// ⚠️ 接收者标识必须与**会话层的 local_index** 一致（发起方是 10），
/// 否则接收方会先在「接收者标识不匹配」处拒掉 ⇒ **到不了** AEAD 认证失败那一步。
pub fn valid_frame() -> Vec<u8> {
    let key = TransportKey::new(&WRONG_KEY).expect("测试密钥长度固定为 32 字节");
    let mut sender = Sender::new(key, SESSION_LOCAL_INDEX, 0);
    seal_frame(&mut sender, FrameType::Data, 7, b"ACP").expect("合法帧可封出")
}

/// 会话层的**本端 index**（发起方 10 / 响应方 11）——与 `session_pair` 里的取值一致。
pub const SESSION_LOCAL_INDEX: u32 = 10;

/// 用**错误密钥**在**会话层**解封 ⇒ `session.auth_failed`，会话立即失效。
pub fn session_wrong_key_open_frame(frame: &[u8]) -> (String, bool) {
    let (mut initiator, _responder) = super::session_pair(
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    );
    let error = initiator.open_frame(frame).expect_err("错误密钥必须解不开");
    let label = session_error_label(&error).to_string();
    (label, initiator.is_invalidated())
}

/// 发起方调 `consume_initiation` ⇒ `session.role_mismatch`。
pub fn initiator_consumes_initiation() -> (String, bool) {
    let (mut initiator, _responder) = super::session_pair(
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    );
    let error = initiator
        .consume_initiation(&[0u8; 148], std::time::Instant::now())
        .expect_err("角色不符必须被拒绝");
    (
        session_error_label(&error).to_string(),
        initiator.is_invalidated(),
    )
}

/// 两侧世代号不同 ⇒ 显式的世代号不匹配判定。
///
/// L4（通道协商）尚未交付 ⇒ 这里用**显式的世代号值不等检查**表达
/// （会话号段对齐由 L4 负责）。
pub fn generation_mismatch(initiator_generation: u64, responder_generation: u64) -> Option<String> {
    if initiator_generation != responder_generation {
        Some(session_label::GENERATION_MISMATCH.to_string())
    } else {
        None
    }
}

/// 会话层未握手就收发 ⇒ `session.invalid_state`。
///
/// ⚠️ 这里要的是**未握手**的会话（`session_pair` 返回的是**已建立**的）⇒
/// 单独构造。
pub fn session_send_before_handshake() -> (String, bool) {
    let (mut initiator, _responder) = super::unhandshaked_pair(
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    );
    let error = initiator
        .seal_frame(FrameType::Data, 0, b"x")
        .expect_err("未握手不得可发");
    (
        session_error_label(&error).to_string(),
        initiator.is_invalidated(),
    )
}

/// 明文超上限（会话层）⇒ 明确错误、**不截断**、不消耗计数器。
pub fn session_oversize_plaintext() -> (String, bool) {
    let (mut initiator, _responder) = super::session_pair(
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    );
    let plain = vec![0x41u8; MAX_PLAIN_LEN + 1];
    let error = initiator
        .seal_frame(FrameType::Data, 0, &plain)
        .expect_err("超长明文必须被拒绝");
    (
        session_error_label(&error).to_string(),
        initiator.is_invalidated(),
    )
}

/// 响应方调 `create_initiation` ⇒ `session.role_mismatch`（角色不可越权）。
pub fn responder_creates_initiation() -> (String, bool) {
    let (_initiator, mut responder) = super::session_pair(
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    );
    let error = responder
        .create_initiation([0x01; 32], 1, std::time::Instant::now())
        .expect_err("响应方不得产出 initiation");
    (
        session_error_label(&error).to_string(),
        responder.is_invalidated(),
    )
}

/// 角色名（跨端契约：移动端按同一套名字显示）。
pub fn role_name(role: SessionRole) -> &'static str {
    role.as_str()
}

/// 帧层错误标签表（供移动端对照）。
pub fn known_frame_labels() -> Vec<&'static str> {
    vec![
        super::frame_label::BAD_MAGIC,
        super::frame_label::HEADER_CRC_MISMATCH,
        super::frame_label::PAYLOAD_TOO_LONG,
        super::frame_label::INCOMPLETE,
        super::frame_label::LENGTH_MISMATCH,
        super::frame_label::UNKNOWN_FRAME_TYPE,
        super::frame_label::RESERVED_FLAGS,
        super::frame_label::UNSUPPORTED_VERSION,
    ]
}

/// 会话层错误标签表（供移动端对照）。
pub fn known_session_labels() -> Vec<&'static str> {
    vec![
        session_label::ROLE_MISMATCH,
        session_label::AUTH_FAILED,
        session_label::INVALIDATED,
        session_label::INVALID_STATE,
        session_label::FRAME,
        session_label::GENERATION_MISMATCH,
    ]
}

/// 载荷上限（供移动端对照）。
pub fn payload_limits() -> (usize, usize) {
    (MAX_FRAME_PAYLOAD_LEN, MAX_PLAIN_LEN)
}
