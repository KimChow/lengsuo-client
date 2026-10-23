//! stdin/stdout 主循环：单帧 / 多帧 / 分片 / 上限 / 分派接口。
//! ⛔ 全程用内存 [`Cursor`] / 自写分片 reader，不碰进程真实 stdin/stdout；
//! 期望字节一律取自向量文件里的独立字面量（管道帧 hex 按小端记录）。

use std::io::{Cursor, Read};

use lengsuo_native_host::io_loop::{
    run_with, Dispatch, EnvelopeCodec, LoopOutcome, MessageDispatch, UnwiredDispatch,
    UnwiredEnvelope, ENVELOPE_PENDING,
};
use lengsuo_native_host::LoopError;

fn vector() -> &'static serde_json::Value {
    static CACHE: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    CACHE.get_or_init(load_vector)
}

fn load_vector() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/native-host-io-v1.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("读不到向量文件"))
        .expect("向量文件必须是合法 JSON")
}

/// 测试替身：按契约 §5.2.1 / RFC 4648 **独立手写**的最小信封编解码器。
/// 生产路径本该复用 W3b-2a，但本卡边界不含 `Cargo.toml` ⇒ 只能用替身证明
/// 主循环按契约字节搬运；回包仍与向量里的手写 hex 逐字节比，替身错了同样会红。
struct VectorCodec;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for ch in text.bytes() {
        let value = match ch {
            b'=' => break,
            _ => B64.iter().position(|&c| c == ch)? as u32,
        };
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for shift in [18, 12, 6, 0] {
            out.push(B64[((n >> shift) & 0x3f) as usize] as char);
        }
    }
    out.truncate((bytes.len() * 4).div_ceil(3));
    out
}

impl EnvelopeCodec for VectorCodec {
    fn decode(&self, text: &str) -> Result<Vec<u8>, String> {
        let value = text
            .strip_prefix("{\"frame_b64\":\"")
            .and_then(|rest| rest.strip_suffix("\"}"))
            .ok_or_else(|| "信封形状不对".to_owned())?;
        b64_decode(value).ok_or_else(|| "base64 非法".to_owned())
    }

    fn encode(&self, frame: &[u8]) -> Result<String, String> {
        Ok(format!("{{\"frame_b64\":\"{}\"}}", b64_encode(frame)))
    }
}

/// 主循环入口（测试用编解码器）。
fn run_loop<R: Read, W: std::io::Write, D: MessageDispatch>(
    input: &mut R,
    output: &mut W,
    dispatch: &mut D,
) -> Result<LoopOutcome, LoopError> {
    run_with(input, output, dispatch, &VectorCodec)
}

/// 取向量里的一条管道帧 hex（文件按小端记录长度头）。
fn pipe_hex(name: &str) -> Vec<u8> {
    let text = vector()["frames"][name].as_str().unwrap();
    let mut bytes = hex::decode(text).unwrap();
    if cfg!(target_endian = "big") {
        bytes[..4].reverse();
    }
    bytes
}

/// 记录分派调用并固定回一条帧。
struct RecordingDispatch {
    calls: Vec<(u8, Vec<u8>)>,
    reply: Option<Vec<u8>>,
}

impl RecordingDispatch {
    fn replying(reply: Vec<u8>) -> Self {
        Self {
            calls: Vec::new(),
            reply: Some(reply),
        }
    }
}

impl MessageDispatch for RecordingDispatch {
    fn dispatch(&mut self, frame_type: u8, payload: &[u8]) -> Dispatch {
        self.calls.push((frame_type, payload.to_vec()));
        match &self.reply {
            Some(reply) => Dispatch::Reply(reply.clone()),
            None => Dispatch::NoReply,
        }
    }
}

/// 空业务帧（type 0，len 0）：用作固定回包。
fn empty_business_frame() -> Vec<u8> {
    vec![0u8; 8]
}

/// 用 `[u32 本机序 len]` + 给定字节拼一条入站管道帧。
fn pipe_with(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_ne_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// 按给定段长逐段交付的 reader（模拟 Chromium 任意切分）。
struct ChunkReader {
    data: Vec<u8>,
    pos: usize,
    sizes: Vec<usize>,
    next: usize,
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos == self.data.len() {
            return Ok(0);
        }
        let want = self.sizes[self.next % self.sizes.len()].max(1);
        self.next += 1;
        let n = want.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn single_frame_round_trip() {
    let input = pipe_hex("save_password_pipe_frame_hex");
    let mut reader = Cursor::new(input);
    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::replying(empty_business_frame());

    let outcome = run_loop(&mut reader, &mut out, &mut dispatch).unwrap();

    assert_eq!(outcome, LoopOutcome::Closed);
    assert_eq!(dispatch.calls.len(), 1);
    assert_eq!(dispatch.calls[0].0, 5, "SAVE_PASSWORD");
    assert_eq!(dispatch.calls[0].1, b"pw-hint");
    // 回包 = 空业务帧 → 信封 → 管道帧，逐字节等于手写锚点。
    assert_eq!(out, pipe_hex("list_credentials_pipe_frame_hex"));
}

#[test]
fn multiple_frames_in_one_read() {
    let mut input = pipe_hex("save_password_pipe_frame_hex");
    input.extend_from_slice(&pipe_hex("get_password_pipe_frame_hex"));
    let mut reader = Cursor::new(input);
    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::replying(empty_business_frame());

    assert_eq!(
        run_loop(&mut reader, &mut out, &mut dispatch).unwrap(),
        LoopOutcome::Closed
    );
    assert_eq!(dispatch.calls.len(), 2);
    assert_eq!(dispatch.calls[0].0, 5);
    assert_eq!(dispatch.calls[1].0, 1, "GET_PASSWORD");
    assert_eq!(dispatch.calls[1].1, b"user=alice");

    let mut expected = pipe_hex("list_credentials_pipe_frame_hex");
    expected.extend_from_slice(&expected.clone());
    assert_eq!(out, expected, "两帧必须产生两条完整回帧");
}

#[test]
fn fragmented_frame_is_reassembled() {
    let whole = pipe_hex("save_password_pipe_frame_hex");
    for sizes in [vec![1], vec![2], vec![3], vec![7, 1, 5]] {
        let mut reader = ChunkReader {
            data: whole.clone(),
            pos: 0,
            sizes: sizes.clone(),
            next: 0,
        };
        let mut out = Vec::new();
        let mut dispatch = RecordingDispatch::replying(empty_business_frame());
        assert_eq!(
            run_loop(&mut reader, &mut out, &mut dispatch).unwrap(),
            LoopOutcome::Closed,
            "段长 {:?}",
            sizes
        );
        assert_eq!(
            dispatch.calls,
            vec![(5, b"pw-hint".to_vec())],
            "段长 {:?}",
            sizes
        );
        assert_eq!(out, pipe_hex("list_credentials_pipe_frame_hex"));
    }
}

#[test]
fn half_frame_eof_is_an_error_not_a_frame() {
    let whole = pipe_hex("save_password_pipe_frame_hex");
    let mut reader = Cursor::new(whole[..whole.len() - 1].to_vec());
    let mut out = Vec::new();
    let mut dispatch = UnwiredDispatch;
    match run_loop(&mut reader, &mut out, &mut dispatch) {
        Err(LoopError::Read(message)) => assert!(message.contains("EOF"), "{message}"),
        other => panic!("半帧 EOF 必须报读错误，实际 {:?}", other),
    }
    assert!(out.is_empty(), "半帧不得产生任何输出");
}

#[test]
fn over_limit_length_header_closes_without_reading_payload() {
    // 只给 4 字节头（声明 1 MiB + 1），后面没有载荷：
    // 实现必须立刻因超限失败，而不是等载荷。
    let header = (1_048_577u32).to_ne_bytes().to_vec();
    let expected_header = vector()["limits"]["over_limit_prefix_hex"]
        .as_str()
        .unwrap();
    let mut reference = hex::decode(expected_header).unwrap();
    if cfg!(target_endian = "big") {
        reference.reverse();
    }
    assert_eq!(header, reference, "向量里的超限长度头必须与手算一致");

    let expected_err = LoopError::TooLong {
        declared: 1_048_577,
        limit: 1_048_576,
    };
    // 只给头 ⇒ 必须立刻失败，而不是等载荷；头后真跟了数据 ⇒ 也不截断成交付。
    for input in [header.clone(), [header, vec![b'x'; 16]].concat()] {
        let mut out = Vec::new();
        let mut dispatch = RecordingDispatch::replying(empty_business_frame());
        assert_eq!(
            run_loop(&mut Cursor::new(input), &mut out, &mut dispatch),
            Err(expected_err.clone())
        );
        assert!(out.is_empty(), "超限时不得写出任何字节");
        assert!(dispatch.calls.is_empty());
    }
}

#[test]
fn length_header_must_be_native_endian() {
    // ⭐ 把长度头写成**相反字节序**：x86 上即大端。
    // 1 MiB 以内的小帧在这个错误下会变成一个巨大的声明长度 ⇒ 必须解不出来。
    let envelope = vector()["frames"]["save_password_envelope"]
        .as_str()
        .unwrap();
    let len = envelope.len() as u32;
    let header = if cfg!(target_endian = "big") {
        len.to_le_bytes()
    } else {
        len.to_be_bytes()
    };
    let bytes = [header.as_slice(), envelope.as_bytes()].concat();

    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::replying(empty_business_frame());
    match run_loop(&mut Cursor::new(bytes), &mut out, &mut dispatch) {
        Err(LoopError::TooLong { .. }) => {}
        other => panic!("反字节序长度头必须解不出来，实际 {:?}", other),
    }
    assert!(dispatch.calls.is_empty());
    assert!(out.is_empty());
}

#[test]
fn malformed_payloads_are_rejected() {
    // 空载荷：信封解析失败。
    let empty = pipe_with(&[]);
    assert!(matches!(
        run_loop(
            &mut Cursor::new(empty),
            &mut Vec::new(),
            &mut UnwiredDispatch
        ),
        Err(LoopError::Envelope(_))
    ));
    // 非 UTF-8：载荷是 JSON 文本，先于信封层失败。
    let bad = pipe_with(&[0xff, 0xfe]);
    assert_eq!(
        run_loop(&mut Cursor::new(bad), &mut Vec::new(), &mut UnwiredDispatch),
        Err(LoopError::NotUtf8)
    );
}

#[test]
fn unwired_dispatch_sends_nothing() {
    let mut out = Vec::new();
    let mut dispatch = UnwiredDispatch;
    assert_eq!(
        run_loop(
            &mut Cursor::new(pipe_hex("save_password_pipe_frame_hex")),
            &mut out,
            &mut dispatch
        )
        .unwrap(),
        LoopOutcome::Closed
    );
    assert!(out.is_empty(), "未接线时不得伪造任何回包");
}

#[test]
fn bad_business_frames_are_rejected() {
    let cases: [(&str, Vec<u8>); 4] = [
        ("未知类型", vec![0, 0, 0, 0, 11, 0, 0, 0]),
        ("保留位非零", vec![0, 0, 0, 0, 0, 1, 0, 0]),
        ("载荷截断", vec![0, 0, 0, 4, 0, 0, 0, 0, 1]),
        ("帧后多余字节", vec![0, 0, 0, 0, 0, 0, 0, 0, 9]),
    ];
    for (name, business) in cases {
        let envelope = VectorCodec.encode(&business).unwrap();
        let input = pipe_with(envelope.as_bytes());
        let mut dispatch = RecordingDispatch::replying(empty_business_frame());
        match run_loop(&mut Cursor::new(input), &mut Vec::new(), &mut dispatch) {
            Err(LoopError::BadBusinessFrame(_)) => {}
            other => panic!("{}：应为 BadBusinessFrame，实际 {:?}", name, other),
        }
        assert!(dispatch.calls.is_empty(), "{}：坏帧不得进分派", name);
    }
}

#[test]
fn oversized_reply_is_refused() {
    // 业务帧载荷恰好 1 MiB（合法），但装进信封会 > 1 MiB ⇒ 回包编不出来。
    let mut business = 1_048_576u32.to_be_bytes().to_vec();
    business.push(0);
    business.extend_from_slice(&[0u8; 1_048_579]);
    let mut dispatch = RecordingDispatch::replying(business);
    let mut out = Vec::new();
    let err = run_loop(
        &mut Cursor::new(pipe_hex("list_credentials_pipe_frame_hex")),
        &mut out,
        &mut dispatch,
    )
    .unwrap_err();
    assert!(matches!(err, LoopError::ReplyTooLong(_)), "{err:?}");
    assert!(out.is_empty(), "编不出来的回包不得写出半条");
}

#[test]
fn unwired_envelope_is_still_rejected_via_run_with() {
    // run_with 注入 UnwiredEnvelope：任何信封都返回 ENVELOPE_PENDING，分派不进，stdout 无输出。
    let mut out = Vec::new();
    let mut dispatch = RecordingDispatch::replying(empty_business_frame());
    let err = run_with(
        &mut Cursor::new(pipe_hex("save_password_pipe_frame_hex")),
        &mut out,
        &mut dispatch,
        &UnwiredEnvelope,
    )
    .unwrap_err();
    assert_eq!(err, LoopError::Envelope(ENVELOPE_PENDING.to_owned()));
    assert!(dispatch.calls.is_empty(), "显式拒绝的信封不得进分派");
    assert!(out.is_empty());
    // 未接线编解码器对编码侧同样显式拒绝。
    assert!(UnwiredEnvelope.encode(&[]).is_err());
}

#[test]
fn test_codec_matches_hand_written_anchors() {
    // 测试替身本身也要对锚点：编解码沿用向量里独立算出的信封/base64 字面量。
    let frames = &vector()["frames"];
    for key in ["save_password", "get_password", "list_credentials"] {
        let envelope = frames[format!("{key}_envelope")].as_str().unwrap();
        let business = VectorCodec.decode(envelope).unwrap();
        assert_eq!(VectorCodec.encode(&business).unwrap(), envelope, "{key}");
        let frame_hex = frames[format!("{key}_frame_hex")].as_str().unwrap();
        assert_eq!(hex::encode(&business), frame_hex, "{key}");
    }
}
