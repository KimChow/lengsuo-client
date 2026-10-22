//! 固定向量回放的共享夹具：读向量文件、按名字取条目、逐条断言。

use lengsuo_browser_extension::error::FrameError;
use lengsuo_browser_extension::frame::{decode, decode_exact, Frame, FRAME_HEADER_LEN};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;

/// 向量文件路径。
pub fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("credential-wire-v1.json")
}

/// 读向量文件（只读一次）。
///
/// ⛔ 文件缺失或解析失败 ⇒ **测试失败**，绝不 skip。
pub fn load() -> &'static Value {
    static CACHE: OnceLock<Value> = OnceLock::new();
    CACHE.get_or_init(|| {
        let path = vector_path();
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读不到向量文件 {}：{}", path.display(), e));
        serde_json::from_str(&text).expect("向量文件必须是合法 JSON")
    })
}

/// 按名字取某一段里的条目。
pub fn entry(section: &str, name: &str) -> &'static Value {
    let array = load()
        .get(section)
        .unwrap_or_else(|| panic!("向量文件缺段 {}", section))
        .as_array()
        .unwrap_or_else(|| panic!("向量文件段 {} 必须是数组", section));
    array
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("向量文件段 {} 里没有名为 {} 的条目", section, name))
}

/// 断言一条**合法**向量：实现的编码结果**逐字节**等于向量里的期望字节。
pub fn assert_legal(name: &str) {
    let item = entry("legal_frames", name);
    let type_byte = item["type"].as_u64().expect("type 必须是数字") as u8;
    let payload_len = item["payload_len"]
        .as_u64()
        .expect("payload_len 必须是数字") as usize;
    let expected_frame = hex::decode(item["frame_hex"].as_str().expect("frame_hex 必须是字符串"))
        .expect("frame_hex 必须是合法 hex");
    let expected_header = hex::decode(
        item["header_hex"]
            .as_str()
            .expect("header_hex 必须是字符串"),
    )
    .expect("header_hex 必须是合法 hex");
    let expected_frame_len = item["frame_len"].as_u64().expect("frame_len 必须是数字") as usize;
    let payload = hex::decode(
        item["payload_hex"]
            .as_str()
            .expect("payload_hex 必须是字符串"),
    )
    .expect("payload_hex 必须是合法 hex");

    // 向量自身必须自洽。
    assert_eq!(
        payload.len(),
        payload_len,
        "{}：payload 长度与 payload_len 不符",
        name
    );
    assert_eq!(
        expected_header.len(),
        FRAME_HEADER_LEN,
        "{}：帧头必须是 8 字节",
        name
    );
    assert_eq!(
        expected_frame_len,
        FRAME_HEADER_LEN + payload_len,
        "{}：整帧长度必须是 8 + len",
        name
    );
    assert_eq!(
        expected_frame.len(),
        expected_frame_len,
        "{}：frame_hex 长度与 frame_len 不符",
        name
    );

    // ⭐ 核心断言：与**独立算出的期望字节**比对，不是自家往返。
    let frame = Frame::new(type_byte, payload.clone());
    let encoded = frame.encode().expect("合法向量必须能编码");
    assert_eq!(
        encoded, expected_frame,
        "{}：编码结果与向量期望字节不一致",
        name
    );
    assert_eq!(
        &encoded[..FRAME_HEADER_LEN],
        &expected_header[..],
        "{}：帧头与向量不一致",
        name
    );

    // 解码必须还原出同样的字节，且已消费长度 = 整帧长度。
    let (decoded, consumed) = decode(&encoded).expect("合法向量必须能解码");
    assert_eq!(
        consumed,
        encoded.len(),
        "{}：已消费字节数必须是整帧长度",
        name
    );
    assert_eq!(decoded.frame_type, type_byte, "{}：解出的类型不符", name);
    assert_eq!(decoded.payload, payload, "{}：解出的载荷不符", name);
    assert_eq!(
        decode_exact(&encoded).expect("合法向量必须能精确解码"),
        decoded,
        "{}：decode_exact 与 decode 不一致",
        name
    );
}

/// 断言一条**非法**向量：实现的失败类别与定位信息都等于向量里的期望值。
pub fn assert_illegal(name: &str) {
    let item = entry("illegal_frames", name);
    let category = item["category"].as_str().expect("category 必须是字符串");
    let input = hex::decode(item["input_hex"].as_str().expect("input_hex 必须是字符串"))
        .expect("input_hex 必须是合法 hex");
    let expected = &item["error"];

    let error = match item["fn"].as_str().unwrap_or("decode") {
        "decode" => decode(&input).expect_err("非法向量必须解码失败"),
        "decode_exact" => decode_exact(&input).expect_err("非法向量必须解码失败"),
        other => panic!("{}：未知调用目标 {}", name, other),
    };

    match category {
        "payload_too_long" => match error {
            FrameError::PayloadTooLong { declared, limit } => {
                assert_eq!(declared, expected["declared"].as_u64().unwrap(), "{}", name);
                assert_eq!(
                    limit as u64,
                    expected["limit"].as_u64().unwrap(),
                    "{}",
                    name
                );
            }
            other => panic!("{}：期望 payload_too_long，实际 {:?}", name, other),
        },
        "reserved_not_zero" => match error {
            FrameError::ReservedNotZero { got } => {
                let want: Vec<u8> = expected["reserved"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect();
                assert_eq!(got.as_slice(), want.as_slice(), "{}", name);
            }
            other => panic!("{}：期望 reserved_not_zero，实际 {:?}", name, other),
        },
        "unknown_message_type" => match error {
            FrameError::UnknownMessageType { got } => {
                assert_eq!(
                    u64::from(got),
                    expected["type"].as_u64().unwrap(),
                    "{}",
                    name
                );
            }
            other => panic!("{}：期望 unknown_message_type，实际 {:?}", name, other),
        },
        "truncated_header" => match error {
            FrameError::TruncatedHeader { needed, available } => {
                assert_eq!(
                    needed as u64,
                    expected["needed"].as_u64().unwrap(),
                    "{}",
                    name
                );
                assert_eq!(
                    available as u64,
                    expected["available"].as_u64().unwrap(),
                    "{}",
                    name
                );
            }
            other => panic!("{}：期望 truncated_header，实际 {:?}", name, other),
        },
        "truncated_payload" => match error {
            FrameError::TruncatedPayload {
                declared,
                available,
            } => {
                assert_eq!(
                    declared as u64,
                    expected["declared"].as_u64().unwrap(),
                    "{}",
                    name
                );
                assert_eq!(
                    available as u64,
                    expected["available"].as_u64().unwrap(),
                    "{}",
                    name
                );
            }
            other => panic!("{}：期望 truncated_payload，实际 {:?}", name, other),
        },
        "trailing_bytes" => match error {
            FrameError::TrailingBytes {
                expected: want_expected,
                actual,
            } => {
                assert_eq!(
                    want_expected as u64,
                    expected["expected"].as_u64().unwrap(),
                    "{}",
                    name
                );
                assert_eq!(
                    actual as u64,
                    expected["actual"].as_u64().unwrap(),
                    "{}",
                    name
                );
            }
            other => panic!("{}：期望 trailing_bytes，实际 {:?}", name, other),
        },
        other => panic!("{}：未知失败类别 {}", name, other),
    }
}
