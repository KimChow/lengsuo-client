//! base64 与 JSON 信封的固定向量回放 + 跨层集成。
//!
//! `tests/vectors/nm-envelope-v1.json` 里的每个 base64 与信封文本都是
//! **独立手算的期望值**（RFC 4648 §4 / 契约 §5.2.1），
//! 不是「先编码再解码回来」的自证往返。
//!
//! 另有一组硬编码锚点（[`independent_hand_computed_anchors`]），
//! 不依赖向量文件，供离线复核。

use lengsuo_browser_extension::base64::{self, Base64Error};
use lengsuo_browser_extension::envelope::{
    decode_frame_b64, encode_frame_b64, EnvelopeError, MAX_ENVELOPE_LEN,
};
use lengsuo_browser_extension::frame::{decode_exact, Frame};
use serde_json::Value;
use std::path::PathBuf;

/// 读向量文件；文件缺失或不是合法 JSON ⇒ 测试失败，绝不 skip。
fn load() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("nm-envelope-v1.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("读不到向量文件 {}：{}", path.display(), error));
    serde_json::from_str(&text).expect("向量文件必须是合法 JSON")
}

fn entries<'a>(root: &'a Value, section: &str) -> &'a Vec<Value> {
    root.get(section)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("向量文件缺数组段 {section}"))
}

/// 条目的输入字节：`input`（ASCII 文本）/ `input_hex` / `input_fill`（0..=255）。
fn input_bytes(item: &Value) -> Vec<u8> {
    if let Some(text) = item.get("input").and_then(Value::as_str) {
        return text.as_bytes().to_vec();
    }
    if let Some(text) = item.get("input_hex").and_then(Value::as_str) {
        return hex::decode(text).expect("input_hex 必须是合法 hex");
    }
    let fill = item.get("input_fill").expect("条目缺少输入");
    let first = u8::try_from(fill["first"].as_u64().expect("first 必须是数字")).unwrap();
    let last = u8::try_from(fill["last"].as_u64().expect("last 必须是数字")).unwrap();
    (first..=last).collect()
}

#[test]
fn base64_legal_vectors() {
    let root = load();
    for item in entries(&root, "base64_legal") {
        let name = item["name"].as_str().expect("name 必须是字符串");
        let input = input_bytes(item);
        let expected = item["expected"].as_str().expect("expected 必须是字符串");

        assert_eq!(base64::encode(&input), expected, "{name}：编码不符");
        assert!(
            !expected.contains('='),
            "{name}：canonical 编码不得含 padding"
        );
        assert_eq!(
            base64::decode(expected).expect("合法 base64 必须能解码"),
            input,
            "{name}：解码不符"
        );
        // 解码端对带 padding 的输入同样宽容。
        if let Some(padded) = item.get("padded").and_then(Value::as_str) {
            assert_eq!(
                base64::decode(padded).expect("带 padding 的合法输入必须能解码"),
                input,
                "{name}：带 padding 的解码不符"
            );
        }
    }
}

#[test]
fn base64_illegal_vectors() {
    let root = load();
    for item in entries(&root, "base64_illegal") {
        let name = item["name"].as_str().expect("name 必须是字符串");
        let input = item["input"].as_str().expect("input 必须是字符串");
        let expected = item["error"].as_str().expect("error 必须是字符串");
        let error = base64::decode(input).expect_err(&format!("{name}：非法输入必须解码失败"));
        match (expected, &error) {
            ("invalid_length", Base64Error::InvalidLength(len)) => {
                assert_eq!(*len, input.len(), "{name}：长度定位不符");
            }
            ("invalid_char", Base64Error::InvalidChar(_, _)) => {}
            ("misplaced_padding", Base64Error::MisplacedPadding(_)) => {}
            _ => panic!("{name}：期望 {expected}，实际 {error:?}"),
        }
    }
}

#[test]
fn envelope_legal_vectors() {
    let root = load();
    for item in entries(&root, "envelope_legal") {
        let name = item["name"].as_str().expect("name 必须是字符串");

        // 「len 较大的填充帧」用生成描述（不贴长 hex），其余条目给完整字面量。
        if let Some(prefix) = item.get("frame_hex_prefix").and_then(Value::as_str) {
            let mut frame = hex::decode(prefix).expect("frame_hex_prefix 必须是合法 hex");
            let fill = &item["payload_fill"];
            let byte = u8::try_from(fill["byte"].as_u64().expect("byte 必须是数字")).unwrap();
            let len = usize::try_from(fill["len"].as_u64().expect("len 必须是数字")).unwrap();
            frame.resize(frame.len() + len, byte);

            let expected_b64 = format!(
                "{}{}",
                item["frame_b64_prefix"]
                    .as_str()
                    .expect("frame_b64_prefix 必须是字符串"),
                item["frame_b64_repeat"]
                    .as_str()
                    .expect("frame_b64_repeat 必须是字符串")
                    .repeat(
                        usize::try_from(
                            item["frame_b64_len"]
                                .as_u64()
                                .expect("frame_b64_len 必须是数字")
                        )
                        .unwrap()
                            - item["frame_b64_prefix"].as_str().unwrap().len()
                    )
            );
            assert_eq!(
                expected_b64.len(),
                item["frame_b64_len"].as_u64().unwrap() as usize
            );
            let json = format!("{{\"frame_b64\":\"{expected_b64}\"}}");
            assert_eq!(
                json.len(),
                item["json_len"].as_u64().unwrap() as usize,
                "{name}：信封长度必须与独立算出的期望一致"
            );
            assert_eq!(
                encode_frame_b64(&frame).expect("填充帧必须能装进信封"),
                json,
                "{name}：填充帧的信封文本不符"
            );
            assert_eq!(
                decode_frame_b64(&json).expect("填充帧信封必须能解码"),
                frame,
                "{name}：填充帧解出的字节不符"
            );
            continue;
        }

        let json = item["json"].as_str().expect("json 必须是字符串");
        let frame = hex::decode(item["frame_hex"].as_str().expect("frame_hex 必须是字符串"))
            .expect("frame_hex 必须是合法 hex");

        // ⛔ 信封层只搬字节：即使内容不是合法业务帧也照样返回（此处是合法帧）。
        assert_eq!(
            decode_frame_b64(json).expect("合法信封必须能解码"),
            frame,
            "{name}：解出的业务帧字节不符"
        );
        // 编码方向：canonical 条目的信封文本必须逐字一致。
        if item
            .get("canonical")
            .and_then(Value::as_bool)
            .unwrap_or(true)
        {
            assert_eq!(
                encode_frame_b64(&frame).expect("合法业务帧必须能装进信封"),
                json,
                "{name}：信封文本必须逐字一致"
            );
        }
    }
}

#[test]
fn envelope_illegal_vectors() {
    let root = load();
    for item in entries(&root, "envelope_illegal") {
        let name = item["name"].as_str().expect("name 必须是字符串");
        let json = item["json"].as_str().expect("json 必须是字符串");
        let expected = item["error"].as_str().expect("error 必须是字符串");
        let error = decode_frame_b64(json).expect_err(&format!("{name}：非法信封必须失败"));
        match (expected, &error) {
            ("missing_field", EnvelopeError::MissingField) => {}
            ("unexpected_field", EnvelopeError::UnexpectedField { .. }) => {}
            ("value_not_string", EnvelopeError::ValueNotString) => {}
            ("invalid_json", EnvelopeError::InvalidJson { .. }) => {}
            ("duplicate_key", EnvelopeError::DuplicateKey { .. }) => {}
            ("invalid_base64", EnvelopeError::InvalidBase64(_)) => {}
            ("envelope_too_long", EnvelopeError::EnvelopeTooLong { .. }) => {}
            _ => panic!("{name}：期望 {expected}，实际 {error:?}"),
        }
    }
}

/// 独立手算锚点：不读向量文件，期望值直接写在断言里。
#[test]
fn independent_hand_computed_anchors() {
    // RFC 4648 §10 官方向量（无 padding 编码）。
    for (input, expected) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(
            base64::encode(input.as_bytes()),
            expected,
            "编码锚点 {input:?}"
        );
        assert_eq!(
            base64::decode(expected).expect("无 padding 的 legal 输入必须能解码"),
            input.as_bytes(),
            "解码锚点 {expected:?}（无 padding）"
        );
    }

    // `"A"`（0x41）→ `QQ`。
    assert_eq!(base64::encode(b"A"), "QQ");
    assert_eq!(base64::decode("QQ").expect("QQ 必须能解码"), b"A");
    assert_eq!(base64::decode("QQ==").expect("QQ== 必须能解码"), b"A");

    // 业务帧 `00 00 00 04 | 00 | 00 00 00 | 00 00 00 00`（len=4, type=0）：
    // 按 RFC 4648 §4 逐位手算（并用独立实现复核）为 `AAAABAAAAAAAAAAA`。
    // ⚠️ 任务书 §2 的锚点 `AAAAAAQAAAAA` 与该 12 字节帧不符（它只能解出 9 字节），
    //    属任务书笔误；以 RFC 4648 为准，详见仓外报告。
    let len4_frame = [
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(base64::encode(&len4_frame), "AAAABAAAAAAAAAAA");
    assert_eq!(
        base64::decode("AAAABAAAAAAAAAAA").expect("len=4 帧的 base64 必须能解码"),
        len4_frame
    );

    // W3a：Frame::new(1, b"payload").encode() = `00000007 01 000000 payload`，
    // base64 手算为 `AAAABwEAAABwYXlsb2Fk`。
    let frame = Frame::new(1, b"payload".to_vec())
        .encode()
        .expect("合法帧必须能编码");
    assert_eq!(base64::encode(&frame), "AAAABwEAAABwYXlsb2Fk");
    assert_eq!(
        encode_frame_b64(&frame).expect("合法帧必须能装进信封"),
        "{\"frame_b64\":\"AAAABwEAAABwYXlsb2Fk\"}"
    );
}

/// 所有 256 个单字节值的往返（不依赖向量文件，也不依赖文本方向）。
#[test]
fn every_byte_value_roundtrips() {
    for value in 0u8..=255 {
        let encoded = base64::encode(&[value]);
        assert!(
            (2..=3).contains(&encoded.len()),
            "单字节值 {value} 的编码长度异常：{encoded:?}"
        );
        assert!(!encoded.contains('='), "canonical 编码不得含 padding");
        assert_eq!(
            base64::decode(&encoded).expect("自家编码必须能解回"),
            vec![value],
            "单字节值 {value} 往返不符"
        );
    }
}

/// 信封大小边界：1 MiB 文本上限与 base64 膨胀后的有效业务帧上限。
#[test]
fn envelope_size_boundaries() {
    let root = load();
    let limits = &root["envelope_limits"];
    assert_eq!(
        limits["max_envelope_len"].as_u64().unwrap() as usize,
        MAX_ENVELOPE_LEN
    );
    let fits = limits["fits_frame_len"].as_u64().unwrap() as usize;
    let fits_json_len = limits["fits_envelope_len"].as_u64().unwrap() as usize;
    let too_long = limits["too_long_frame_len"].as_u64().unwrap() as usize;
    let too_long_json_len = limits["too_long_envelope_len"].as_u64().unwrap() as usize;

    // 恰好顶到 1 MiB 的帧：成功，且长度逐字节可核对。
    let json = encode_frame_b64(&vec![0u8; fits]).expect("边界内的帧必须能装进信封");
    assert_eq!(json.len(), fits_json_len);
    assert_eq!(json.len(), MAX_ENVELOPE_LEN);

    // 多 1 字节：拒绝，不截断。
    assert_eq!(
        encode_frame_b64(&vec![0u8; too_long]),
        Err(EnvelopeError::EnvelopeTooLong {
            limit: MAX_ENVELOPE_LEN,
            actual: too_long_json_len,
        })
    );

    // 解码方向：信封文本自身超限时，解析前就失败。
    let overlong = "A".repeat(MAX_ENVELOPE_LEN + 1);
    assert_eq!(
        decode_frame_b64(&overlong),
        Err(EnvelopeError::EnvelopeTooLong {
            limit: MAX_ENVELOPE_LEN,
            actual: MAX_ENVELOPE_LEN + 1,
        })
    );
}

/// ⭐ 跨层集成：W3a 编码的业务帧 → 信封 → 解出字节 → W3a 精确解码。
///
/// 帧字节由 W3a 的 `Frame::encode` 产出（不是手写常量），
/// 信封层不得改动其中任何一个字节。
#[test]
fn frames_survive_the_envelope_roundtrip() {
    let cases = [
        Frame::new(0, Vec::new()),
        Frame::new(1, b"payload".to_vec()),
        Frame::new(3, "凭据测试".as_bytes().to_vec()),
        Frame::new(10, Vec::new()),
        Frame::new(4, vec![0xff; 1024]),
    ];
    for frame in cases {
        let wire = frame.encode().expect("合法帧必须能编码");
        let json = encode_frame_b64(&wire).expect("合法帧必须能装进信封");
        let unpacked = decode_frame_b64(&json).expect("信封必须能解出业务帧");
        assert_eq!(unpacked, wire, "信封往返改动了帧字节");

        let decoded = decode_exact(&unpacked).expect("解出的字节必须是合法帧");
        assert_eq!(decoded.frame_type, frame.frame_type);
        assert_eq!(decoded.payload, frame.payload);
    }
}

/// 信封层**不校验**帧头：任意字节都原样搬进搬出。
#[test]
fn envelope_does_not_validate_frame_header() {
    let arbitrary = [0xde, 0xad, 0xbe, 0xef];
    let json = encode_frame_b64(&arbitrary).expect("任意字节都能装进信封");
    assert_eq!(json, "{\"frame_b64\":\"3q2+7w\"}");
    assert_eq!(decode_frame_b64(&json).expect("必须原样解出"), arbitrary);
}
