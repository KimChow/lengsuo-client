//! 生产入口接线后的端到端用例：管道帧 → W3b-2a 信封 → 业务帧 → 分派 → 回帧。
//!
//! ⛔ 全程用内存 [`Cursor`]，不碰进程真实 stdin/stdout。
//! 期望字节一律取自 `tests/vectors/wired-envelope-v1.json` 里**独立手算**的字面量
//! （管道帧 hex 按小端记录，大端主机由 [`pipe_from_hex`] 换序）。

use std::io::Cursor;

use lengsuo_native_host::io_loop::{
    run, run_with, Dispatch, EnvelopeCodec, LoopOutcome, MessageDispatch, UnwiredEnvelope,
    ENVELOPE_PENDING,
};
use lengsuo_native_host::{LoopError, WiredEnvelope};

fn vector() -> &'static serde_json::Value {
    static CACHE: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    CACHE.get_or_init(load_vector)
}

fn load_vector() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/wired-envelope-v1.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("读不到向量文件"))
        .expect("向量文件必须是合法 JSON")
}

/// 按本机字节序套上管道帧的 4 字节长度头（Chromium 写侧就是 `memcpy(uint32_t)`）。
fn pipe_with(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_ne_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// 向量里按小端记录的管道帧 → 本机字节序。
fn pipe_from_hex(text: &str) -> Vec<u8> {
    let mut bytes = hex::decode(text).expect("向量里的管道帧 hex 必须合法");
    if cfg!(target_endian = "big") {
        bytes[..4].reverse();
    }
    bytes
}

fn hex_bytes(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("向量字段必须是字符串")).expect("向量里的 hex 必须合法")
}

fn str_field<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value[key].as_str().expect("向量字段必须是字符串")
}

/// 测试替身：记录分派调用，可选地回一条固定业务帧。
struct RecordingDispatch {
    calls: Vec<(u8, Vec<u8>)>,
    reply: Option<Vec<u8>>,
}

impl RecordingDispatch {
    fn no_reply() -> Self {
        Self {
            calls: Vec::new(),
            reply: None,
        }
    }

    fn replying(frame: Vec<u8>) -> Self {
        Self {
            calls: Vec::new(),
            reply: Some(frame),
        }
    }
}

impl MessageDispatch for RecordingDispatch {
    fn dispatch(&mut self, frame_type: u8, payload: &[u8]) -> Dispatch {
        self.calls.push((frame_type, payload.to_vec()));
        match &self.reply {
            Some(frame) => Dispatch::Reply(frame.clone()),
            None => Dispatch::NoReply,
        }
    }
}

/// 三段锚点：业务帧 → base64 → 信封 → 管道帧，逐段与手写字面量比对。
#[test]
fn wired_envelope_matches_hand_written_anchors() {
    let vector = vector();
    let wired = WiredEnvelope;
    let mut cases = vec![
        (
            hex_bytes(&vector["anchors"]["business_frame_hex"]),
            &vector["anchors"],
        ),
        (
            hex_bytes(&vector["save_password"]["business_frame_hex"]),
            &vector["save_password"],
        ),
    ];
    cases.extend(
        vector["bad_business_frames"]
            .as_array()
            .expect("bad_business_frames 必须是数组")
            .iter()
            .map(|case| (hex_bytes(&case["frame_hex"]), case)),
    );
    for (business, case) in cases {
        assert_eq!(
            wired.encode(&business).expect("合法业务帧必须能套信封"),
            str_field(case, "envelope"),
            "编码结果必须等于手写信封"
        );
        assert_eq!(
            wired
                .decode(str_field(case, "envelope"))
                .expect("手写信封必须能解"),
            business,
            "解码结果必须等于手写业务帧"
        );
    }

    // 中间那一段也单独钉住：base64 是手算字面量，不是实现的输出。
    let anchors = &vector["anchors"];
    assert_eq!(
        wired
            .encode(&hex_bytes(&anchors["business_frame_hex"]))
            .unwrap(),
        anchors["envelope"].as_str().unwrap()
    );
    assert_eq!(
        anchors["base64"].as_str().unwrap().len(),
        16,
        "12 字节无 padding 的 base64 必须是 16 字符"
    );
    assert_eq!(
        anchors["envelope"].as_str().unwrap().len(),
        anchors["envelope_len"].as_u64().unwrap() as usize
    );
}

/// 生产入口 `run()` 端到端：合法信封 → 分派 → 回包换行逐字节等于手算管道帧。
#[test]
fn run_wires_envelope_layer_end_to_end() {
    let vector = vector();
    let anchors = &vector["anchors"];
    let input = pipe_with(str_field(anchors, "envelope").as_bytes());
    let business = hex_bytes(&anchors["business_frame_hex"]);
    let expected = pipe_from_hex(str_field(anchors, "pipe_frame_hex"));

    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::replying(business);
    let outcome = run(&mut Cursor::new(input), &mut out, &mut dispatch).expect("合法信封必须跑通");

    assert_eq!(outcome, LoopOutcome::Closed);
    assert_eq!(
        dispatch.calls,
        vec![(0u8, vec![0u8; 4])],
        "业务帧 type=0、载荷 4 字节零必须原样交给分派"
    );
    assert_eq!(out, expected, "回帧必须是信封 + 管道帧的手算字节");
}

/// `Dispatch::NoReply` 不往 stdout 写任何字节（含信封层的空包）。
#[test]
fn run_no_reply_writes_nothing() {
    let vector = vector();
    let save = &vector["save_password"];
    let input = pipe_with(str_field(save, "envelope").as_bytes());

    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::no_reply();
    let outcome = run(&mut Cursor::new(input), &mut out, &mut dispatch).expect("合法信封必须跑通");

    assert_eq!(outcome, LoopOutcome::Closed);
    assert_eq!(dispatch.calls, vec![(5u8, b"pw-hint".to_vec())]);
    assert!(out.is_empty(), "NoReply 不得写 stdout");
}

/// 坏信封 ⇒ `LoopError::Envelope`，不进分派、不写字节。
#[test]
fn run_rejects_invalid_envelopes() {
    let vector = vector();
    for case in vector["invalid_envelopes"]
        .as_array()
        .expect("invalid_envelopes 必须是数组")
    {
        let name = str_field(case, "name");
        let input = pipe_with(str_field(case, "text").as_bytes());
        let mut out = Vec::new();
        let mut dispatch = RecordingDispatch::replying(vec![0u8; 8]);

        let error = run(&mut Cursor::new(input), &mut out, &mut dispatch)
            .expect_err(&format!("{name}: 坏信封必须失败"));

        assert!(
            matches!(error, LoopError::Envelope(_)),
            "{name}: 应为 Envelope，实际 {error:?}"
        );
        assert!(dispatch.calls.is_empty(), "{name}: 坏信封不得进分派");
        assert!(out.is_empty(), "{name}: 坏信封不得写出字节");
    }
}

/// 信封合法但业务帧帧头坏 ⇒ `LoopError::BadBusinessFrame`，不进分派。
#[test]
fn run_rejects_bad_business_frames() {
    let vector = vector();
    for case in vector["bad_business_frames"]
        .as_array()
        .expect("bad_business_frames 必须是数组")
    {
        let name = str_field(case, "name");
        let input = pipe_with(str_field(case, "envelope").as_bytes());
        let mut out = Vec::new();
        let mut dispatch = RecordingDispatch::replying(vec![0u8; 8]);

        let error = run(&mut Cursor::new(input), &mut out, &mut dispatch)
            .expect_err(&format!("{name}: 坏业务帧必须失败"));

        match error {
            LoopError::BadBusinessFrame(reason) => {
                assert_eq!(reason, str_field(case, "reason"), "{name}");
            }
            other => panic!("{name}: 应为 BadBusinessFrame，实际 {other:?}"),
        }
        assert!(dispatch.calls.is_empty(), "{name}: 坏业务帧不得进分派");
        assert!(out.is_empty(), "{name}: 坏业务帧不得写出字节");
    }
}

/// 注入自定义编解码器时 `run_with` 走注入实现，不走生产实现。
struct CustomCodec;

impl EnvelopeCodec for CustomCodec {
    fn decode(&self, text: &str) -> Result<Vec<u8>, String> {
        if text == "CUSTOM-IN" {
            Ok(vec![0u8; 8])
        } else {
            Err("custom: 未预期的输入".into())
        }
    }

    fn encode(&self, _frame: &[u8]) -> Result<String, String> {
        Ok("CUSTOM-OUT".into())
    }
}

#[test]
fn run_with_uses_injected_codec() {
    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::replying(vec![0u8; 8]);
    let outcome = run_with(
        &mut Cursor::new(pipe_with(b"CUSTOM-IN")),
        &mut out,
        &mut dispatch,
        &CustomCodec,
    )
    .expect("注入编解码器必须被使用");

    assert_eq!(outcome, LoopOutcome::Closed);
    assert_eq!(dispatch.calls, vec![(0u8, Vec::new())]);
    assert_eq!(out, pipe_with(b"CUSTOM-OUT"));
}

/// `UnwiredEnvelope` 仍在、仍显式拒绝：`run_with` 原样返回 `ENVELOPE_PENDING`。
#[test]
fn unwired_envelope_is_still_exported_and_rejects() {
    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::replying(vec![0u8; 8]);
    let error = run_with(
        &mut Cursor::new(pipe_with(b"whatever")),
        &mut out,
        &mut dispatch,
        &UnwiredEnvelope,
    )
    .expect_err("未接线编解码器必须拒绝");

    assert_eq!(error, LoopError::Envelope(ENVELOPE_PENDING.to_owned()));
    assert!(dispatch.calls.is_empty());
    assert!(out.is_empty());
    assert!(UnwiredEnvelope.decode("x").is_err());
    assert!(UnwiredEnvelope.encode(&[]).is_err());
}
