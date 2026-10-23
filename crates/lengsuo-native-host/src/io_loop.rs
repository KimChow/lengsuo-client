//! stdin/stdout **主循环框架**：管道帧 → 信封 → 业务帧 → 分派接口。
//!
//! # 一条消息走的路
//!
//! ```text
//! stdin: [u32 本机序 len][JSON 信封]
//!    │  frame::FrameDecoder（本 crate，W3b-1）—— 半帧攒齐才交付
//!    ▼
//! JSON 信封 {"frame_b64":"<base64(整条业务帧)>"}
//!    │  W3b-2a 的 decode_frame_b64（经 WiredEnvelope，见 [`crate::wired_envelope`]）
//!    ▼
//! 业务帧 8B 头 + 载荷（契约 §5.2）
//!    │  trait MessageDispatch —— 业务处理器
//!    ▼
//! stdout: [u32 本机序 len][JSON 信封]
//! ```
//!
//! # 信封层：生产入口已接 W3b-2a
//!
//! 信封文本的编解码属于 W3b-2a（`lengsuo-browser-extension` 的
//! `decode_frame_b64` / `encode_frame_b64`），⛔ 本 crate 不复制 base64 / JSON 解析。
//!
//! - [`run`] 使用生产编解码器 [`WiredEnvelope`]（转发 W3b-2a）⇒
//!   管道帧 → 信封 → 业务帧 → 分派 → 回帧 → 信封 → 管道帧**端到端打通**；
//!   合法信封不再返回 [`LoopError::Envelope`]。
//! - [`run_with`] 由调用方注入 [`EnvelopeCodec`]，供测试与回退使用；
//!   [`UnwiredEnvelope`] 仍然保留，且仍然显式返回 [`ENVELOPE_PENDING`]。
//!
//! 编解码器返回的错误映射为 [`LoopError::Envelope`]；⛔ 错误文本不含载荷字节。
//!
//! # 分派目标待 W4/W5
//!
//! ⛔ **业务实现在本卡之外**。本模块只定义 [`MessageDispatch`] 接口，
//! 并提供 [`UnwiredDispatch`]：它对所有 11 种类型都回答「未接线」
//! （[`Dispatch::NoReply`]），因此宿主不会替业务层编造响应。
//! W4 落地后替换成一个真正实现该 trait 的处理器即可，
//! [`run`] 的字节语义不用改。
//!
//! # IO 可测
//!
//! [`run`] 对 `Read` / `Write` 泛型 ⇒ 单测用内存 [`Cursor`](std::io::Cursor)，
//! ⛔ 不碰进程真实 stdin/stdout、不起进程、不开线程。
//!
//! # 失败即关通道
//!
//! 长度头超限（> 1 MiB）时**立刻**返回错误：载荷一个字节都不读，
//! ⛔ 不截断、不「读到上限就交付」。其它非法帧同样终止循环。

use std::io::{Read, Write};

use crate::error::LoopError;
use crate::frame::{encode_frame, FrameDecoder};
use crate::wired_envelope::WiredEnvelope;

/// 业务分派接口：主循环把解出来的业务帧交给它。
///
/// ⛔ 这是**接口**，不是业务实现：真正处理 11 种消息类型的是 W4 的业务层。
pub trait EnvelopeCodec {
    /// 信封 JSON 文本 → 整条业务帧字节。
    fn decode(&self, text: &str) -> Result<Vec<u8>, String>;

    /// 业务帧 → 信封 JSON 文本。
    fn encode(&self, frame: &[u8]) -> Result<String, String>;
}

/// 显式拒绝的信封编解码器：供 [`run_with`] 的回退与测试使用。
///
/// 生产入口 [`run`] **不再**使用它；保留它是为了向后兼容，
/// 并让调用方能显式表达「本路径不解析信封」。
#[derive(Debug, Default, Clone, Copy)]
pub struct UnwiredEnvelope;

/// [`UnwiredEnvelope`] 的错误文本（显式拒绝，不解析任何信封）。
pub const ENVELOPE_PENDING: &str =
    "信封层未接线：需给 crates/lengsuo-native-host 增加 lengsuo-browser-extension 依赖";

impl EnvelopeCodec for UnwiredEnvelope {
    fn decode(&self, _text: &str) -> Result<Vec<u8>, String> {
        Err(ENVELOPE_PENDING.into())
    }

    fn encode(&self, _frame: &[u8]) -> Result<String, String> {
        Err(ENVELOPE_PENDING.into())
    }
}

/// 业务分派接口：主循环把解出来的业务帧交给它。
pub trait MessageDispatch {
    /// 处理一条业务帧。
    ///
    /// `frame_type` 已经过白名单校验（契约 §5.3 的 0..=10；未知编号在交给业务层前失败）；
    /// `payload` 是业务帧载荷原始字节。
    fn dispatch(&mut self, frame_type: u8, payload: &[u8]) -> Dispatch;
}

/// 分派结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch {
    /// 有响应：回一条业务帧（整帧 8B 头 + 载荷），主循环负责套信封 + 管道帧。
    Reply(Vec<u8>),
    /// 无响应（含「未接线」）：不往 stdout 写任何字节。
    NoReply,
}

/// 未接线的分派器：所有类型一律不作答。
///
/// W4 的业务处理器落地前的占位实现；它**不会**伪造成功响应，
/// 因此扩展侧会看到「无回复」而不是被误导的假数据。
#[derive(Debug, Default, Clone, Copy)]
pub struct UnwiredDispatch;

impl MessageDispatch for UnwiredDispatch {
    fn dispatch(&mut self, _frame_type: u8, _payload: &[u8]) -> Dispatch {
        Dispatch::NoReply
    }
}

/// 主循环结束的原因（`Err` 之外的正常终止）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopOutcome {
    /// stdin 在帧边界上 EOF：Chromium 关掉了通道，宿主正常退出。
    Closed,
}

/// 跑主循环直到 stdin 在帧边界上 EOF。生产入口使用 [`WiredEnvelope`]。
///
/// # Errors
/// - 读失败（含半帧 EOF）⇒ [`LoopError::Read`]。
/// - 长度头超限 ⇒ [`LoopError::TooLong`]（**关通道，不截断**）。
/// - 载荷非 UTF-8 ⇒ [`LoopError::NotUtf8`]。
/// - 信封坏（JSON / base64 / 字段形状）⇒ [`LoopError::Envelope`]。
/// - 业务帧帧头坏（类型 / 保留位 / 截断 / 多余字节）⇒ [`LoopError::BadBusinessFrame`]。
/// - 写失败或回帧超限 ⇒ [`LoopError::Write`] / [`LoopError::ReplyTooLong`]。
pub fn run<R: Read, W: Write, D: MessageDispatch>(
    input: &mut R,
    output: &mut W,
    dispatch: &mut D,
) -> Result<LoopOutcome, LoopError> {
    run_with(input, output, dispatch, &WiredEnvelope)
}

/// 同 [`run`]，但由调用方提供信封编解码器（测试与回退用）。
///
/// `run()` 传入的是生产编解码器 [`WiredEnvelope`]；调用方可以注入自己的实现
/// （例如测试夹具，或显式拒绝的 [`UnwiredEnvelope`]）。
///
/// # Errors
/// 同 [`run`]。
pub fn run_with<R: Read, W: Write, D: MessageDispatch, E: EnvelopeCodec>(
    input: &mut R,
    output: &mut W,
    dispatch: &mut D,
    codec: &E,
) -> Result<LoopOutcome, LoopError> {
    let mut decoder = FrameDecoder::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = read_some(input, &mut buf)?;
        if read == 0 {
            if decoder.pending() != 0 {
                // 半帧 EOF：不把残片当完整帧，也不静默丢弃。
                return Err(LoopError::Read("EOF 落在帧中间".into()));
            }
            return Ok(LoopOutcome::Closed);
        }
        handle_bytes(&buf[..read], &mut decoder, output, dispatch, codec)?;
    }
}

/// 读一段字节；`Ok(0)` 表示 EOF。
///
/// `read` 允许返回 `Interrupted` / `WouldBlock` 之外的错误；前者重试。
fn read_some<R: Read>(input: &mut R, buf: &mut [u8]) -> Result<usize, LoopError> {
    loop {
        match input.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LoopError::Read(e.to_string())),
        }
    }
}

/// 把一段字节喂给解码器，处理本次切出的所有完整帧。
fn handle_bytes<W: Write, D: MessageDispatch, E: EnvelopeCodec>(
    bytes: &[u8],
    decoder: &mut FrameDecoder,
    output: &mut W,
    dispatch: &mut D,
    codec: &E,
) -> Result<(), LoopError> {
    let frames = decoder.feed(bytes).map_err(|e| match e {
        // 长度头超限 ⇒ 关通道（映射到具名的 TooLong，而不是笼统读错误）。
        crate::error::FrameError::FrameTooLong { declared, limit } => {
            LoopError::TooLong { declared, limit }
        }
        other => LoopError::Read(other.to_string()),
    })?;
    for envelope_bytes in frames {
        let text = std::str::from_utf8(&envelope_bytes).map_err(|_| LoopError::NotUtf8)?;
        let business = codec.decode(text).map_err(LoopError::Envelope)?;
        let (frame_type, payload) = split_business_frame(&business)?;
        if let Dispatch::Reply(frame) = dispatch.dispatch(frame_type, &payload) {
            write_reply(output, &frame, codec)?;
        }
    }
    Ok(())
}

/// 校验业务帧帧头，返回 `(type, payload)` —— 契约 §5.2。
///
/// 只拷贝一次载荷；超限 / 保留位非零 / type 未知 / 截断一律失败。
fn split_business_frame(frame: &[u8]) -> Result<(u8, Vec<u8>), LoopError> {
    // 业务帧头来自 W3a（契约 §5.2 / §5.3）：8 字节头 + 载荷上限 1 MiB。
    // ⚠️ 本 crate 的**管道帧**另有自己的 4 字节头 / 1 MiB（见 frame 模块），两者勿混。
    const HEADER: usize = lengsuo_browser_extension::FRAME_HEADER_LEN;
    const MAX_PAYLOAD: usize = lengsuo_browser_extension::MAX_PAYLOAD_LEN;
    if frame.len() < HEADER {
        return Err(LoopError::BadBusinessFrame("帧头不足 8 字节".into()));
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(LoopError::BadBusinessFrame("载荷超过 1 MiB".into()));
    }
    if frame[5..8] != [0, 0, 0] {
        return Err(LoopError::BadBusinessFrame("保留位非零".into()));
    }
    if len + HEADER > frame.len() {
        return Err(LoopError::BadBusinessFrame("载荷被截断".into()));
    }
    if len + HEADER < frame.len() {
        return Err(LoopError::BadBusinessFrame("帧后有多余字节".into()));
    }
    // 未知消息类型：⛔ 绝不当已知类型交给业务层（契约 §5.3 共 11 种，0..=10）。
    if lengsuo_browser_extension::MessageType::from_u8(frame[4]).is_none() {
        return Err(LoopError::BadBusinessFrame("未知消息类型".into()));
    }
    Ok((frame[4], frame[HEADER..].to_vec()))
}

/// 回帧：业务帧 → 信封 → 管道帧 → stdout。
fn write_reply<W: Write, E: EnvelopeCodec>(
    output: &mut W,
    frame: &[u8],
    codec: &E,
) -> Result<(), LoopError> {
    let envelope = codec.encode(frame).map_err(LoopError::ReplyTooLong)?;
    let pipe =
        encode_frame(envelope.as_bytes()).map_err(|e| LoopError::ReplyTooLong(e.to_string()))?;
    output
        .write_all(&pipe)
        .and_then(|()| output.flush())
        .map_err(|e| LoopError::Write(e.to_string()))
}
