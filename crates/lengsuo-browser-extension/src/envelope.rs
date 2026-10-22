//! JSON 信封 ⇄ 业务帧（契约 §5.2.1）。
//!
//! # 信封形状（冻结）
//!
//! ```text
//! {"frame_b64":"<base64(整条业务帧)>"}
//! ```
//!
//! - 字段名逐字 `frame_b64`（⛔ 不是 `frameB64` / `FRAME_B64` / `payload_b64`）；
//! - 值装的是**整条业务帧**（8 字节帧头 + 载荷），
//!   不是单独载荷 ⇒ ⛔ 消息类型**不**提到 JSON 层；
//! - 对象里**只允许**这一个键；
//! - 值必须是字符串，且**不允许任何转义序列**（`\` 即失败）。
//!
//! # 两层关系
//!
//! ```text
//! 业务帧字节（W3a frame::encode）
//!   → base64 无 padding（本 crate base64::encode）
//!   → 信封 JSON 文本 {"frame_b64":"…"}（本模块）
//!   → Chromium 管道帧：4B 长度头 + 上述 JSON 文本（W3b-1 / 后续接线层）
//! ```
//!
//! 本模块只做中间那一步：**纯函数、无 IO**，不改动业务帧的任何字节定义。
//!
//! # 上限
//!
//! 信封 JSON 文本 ≤ 1 MiB（1 048 576 字节）。这来自 Chromium 管道帧上限
//! （`kMaximumNativeMessageSize` = 1024 × 1024）减去 4 字节长度头后的
//! 工程预算；base64 膨胀 4/3 ⇒ 可装下的整条业务帧约 786 KB。
//! 信封一超限即 [`EnvelopeError::EnvelopeTooLong`]，⛔ 不截断、不分片。
//!
//! # 严格性
//!
//! 解析器是**只为这一种形状**写的最小 JSON 解析器：非对象、顶层多余内容、
//! 转义、控制字符、重复键、未知键一律拒绝。
//! ⛔ 不用 `serde_json`（那是 dev-dependency，不是运行时依赖）。

use crate::base64::{self, Base64Error};

/// 信封 JSON 文本的字节数上限：1 MiB。
///
/// 依据：Chromium Native Messaging 管道帧上限
/// `kMaximumNativeMessageSize` = 1024 × 1024 字节，
/// 减去每个管道帧的 4 字节长度头 **之后**，JSON 载荷最多这么多字节。
/// base64 膨胀 4/3 ⇒ 可装下的整条业务帧 ≈ 786 KB（工程决定，非 Chromium 规定）。
pub const MAX_ENVELOPE_LEN: usize = 1024 * 1024;

/// 信封里唯一的字段名（契约 §5.2.1）。
pub const FRAME_B64_FIELD: &str = "frame_b64";

/// 信封 JSON 文本除 base64 正文之外的固定开销：
/// `{"frame_b64":"` （14 字节）+ 结尾 `"` 与 `}`（2 字节）。
const ENVELOPE_FIXED_OVERHEAD: usize = 16;

/// 把业务帧装进信封：返回完整的 JSON 文本 `{"frame_b64":"<base64>"}`。
///
/// 传入的是**整条业务帧字节**（含 8 字节帧头）；本函数不解析、不改写帧内容。
///
/// # Errors
/// - 结果 JSON 文本超过 [`MAX_ENVELOPE_LEN`] ⇒
///   [`EnvelopeError::EnvelopeTooLong`]（⛔ 不截断）。
pub fn encode_frame_b64(frame: &[u8]) -> Result<String, EnvelopeError> {
    // 先按长度预算判断，避免为超限输入构造超大字符串。
    let encoded_len = base64::encoded_len(frame.len());
    let total = ENVELOPE_FIXED_OVERHEAD.saturating_add(encoded_len);
    if total > MAX_ENVELOPE_LEN {
        return Err(EnvelopeError::EnvelopeTooLong {
            limit: MAX_ENVELOPE_LEN,
            actual: total,
        });
    }
    let mut out = String::with_capacity(total);
    out.push_str("{\"");
    out.push_str(FRAME_B64_FIELD);
    out.push_str("\":\"");
    out.push_str(&base64::encode(frame));
    out.push_str("\"}");
    if out.len() > MAX_ENVELOPE_LEN {
        return Err(EnvelopeError::EnvelopeTooLong {
            limit: MAX_ENVELOPE_LEN,
            actual: out.len(),
        });
    }
    Ok(out)
}

/// 从信封 JSON 文本里取出业务帧原始字节。
///
/// 严格按契约 §5.2.1 解析：恰好一个对象、恰好一个键 `frame_b64`、
/// 值是字符串、无转义。**返回的是业务帧字节本身**——不校验帧头、
/// 不解析载荷语义（那些属于 [`crate::frame`]）。
///
/// # Errors
/// - 文本超过 [`MAX_ENVELOPE_LEN`] ⇒ [`EnvelopeError::EnvelopeTooLong`]。
/// - 不是单个对象 / 多余内容 / 转义 / 控制字符 ⇒ [`EnvelopeError::InvalidJson`]。
/// - 对象里没有 `frame_b64` ⇒ [`EnvelopeError::MissingField`]。
/// - 出现其它键 ⇒ [`EnvelopeError::UnexpectedField`]。
/// - `frame_b64` 的值不是字符串 ⇒ [`EnvelopeError::ValueNotString`]。
/// - 同一键出现两次 ⇒ [`EnvelopeError::DuplicateKey`]。
/// - 值不是合法 base64 ⇒ [`EnvelopeError::InvalidBase64`]。
pub fn decode_frame_b64(json: &str) -> Result<Vec<u8>, EnvelopeError> {
    if json.len() > MAX_ENVELOPE_LEN {
        return Err(EnvelopeError::EnvelopeTooLong {
            limit: MAX_ENVELOPE_LEN,
            actual: json.len(),
        });
    }
    let value = parse_envelope(json)?;
    base64::decode(&value).map_err(EnvelopeError::InvalidBase64)
}

/// 信封编解码失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// 对象里缺少 `frame_b64` 字段。
    #[error("信封缺少字段 frame_b64")]
    MissingField,

    /// 对象里出现了 `frame_b64` 之外的键。
    #[error("信封出现未知字段 {key:?}：只允许 frame_b64")]
    UnexpectedField {
        /// 实际出现的键名。
        key: String,
    },

    /// `frame_b64` 的值不是字符串。
    #[error("信封字段 frame_b64 的值不是字符串")]
    ValueNotString,

    /// 不是合法的信封 JSON 文本（非对象 / 多余内容 / 转义 / 控制字符）。
    #[error("信封 JSON 非法（字节偏移 {at}）：{reason}")]
    InvalidJson {
        /// 出问题的字节偏移。
        at: usize,
        /// 人读的原因。
        reason: &'static str,
    },

    /// `frame_b64` 的值不是合法 base64。
    #[error("信封 base64 非法：{0}")]
    InvalidBase64(Base64Error),

    /// 信封 JSON 文本超过 1 MiB 上限。
    #[error("信封文本 {actual} 字节超过上限 {limit} 字节：拒绝，不截断")]
    EnvelopeTooLong {
        /// 允许的上限（[`MAX_ENVELOPE_LEN`]）。
        limit: usize,
        /// 实际的（或将会是）字节数。
        actual: usize,
    },

    /// 同一个键在对象里出现两次。
    #[error("信封重复键 {key:?}")]
    DuplicateKey {
        /// 重复出现的键名。
        key: String,
    },
}

/// 最小 JSON 解析：只接受 `{"frame_b64":"<无转义字符串>"}` 这一形状。
///
/// 返回 `frame_b64` 的字符串值。
fn parse_envelope(text: &str) -> Result<String, EnvelopeError> {
    let mut parser = Parser {
        text: text.as_bytes(),
        pos: 0,
    };
    parser.skip_whitespace();
    parser.expect(b'{', "信封必须是 JSON 对象")?;
    let mut frame_b64: Option<String> = None;
    parser.skip_whitespace();
    loop {
        if parser.peek() == Some(b'}') {
            parser.pos += 1;
            break;
        }
        let key = parser.parse_string()?;
        if key != FRAME_B64_FIELD {
            return Err(EnvelopeError::UnexpectedField { key });
        }
        if frame_b64.is_some() {
            return Err(EnvelopeError::DuplicateKey { key });
        }
        parser.skip_whitespace();
        parser.expect(b':', "字段名后必须是冒号")?;
        parser.skip_whitespace();
        if parser.peek() != Some(b'"') {
            return Err(EnvelopeError::ValueNotString);
        }
        frame_b64 = Some(parser.parse_string()?);
        parser.skip_whitespace();
        match parser.peek() {
            Some(b',') => {
                parser.pos += 1;
                parser.skip_whitespace();
            }
            Some(b'}') => {
                parser.pos += 1;
                break;
            }
            _ => return Err(parser.error("对象内只允许一个字段")),
        }
    }
    parser.skip_whitespace();
    if parser.pos != parser.text.len() {
        return Err(parser.error("对象之后有多余内容"));
    }
    // 重复键已在上面被 DuplicateKey 拦下；这里只剩「有 frame_b64」或「没有」。
    frame_b64.ok_or(EnvelopeError::MissingField)
}

/// 只为信封形状服务的字节级解析器。
struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8, reason: &'static str) -> Result<(), EnvelopeError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(reason))
        }
    }

    fn error(&self, reason: &'static str) -> EnvelopeError {
        EnvelopeError::InvalidJson {
            at: self.pos,
            reason,
        }
    }

    /// 解析一个字符串值/键名：⛔ 任何 `\` 转义、任何控制字符都直接拒绝。
    fn parse_string(&mut self) -> Result<String, EnvelopeError> {
        self.expect(b'"', "字段名与字段值必须是 JSON 字符串")?;
        let start = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.error("字符串未闭合")),
                Some(b'"') => {
                    let raw = &self.text[start..self.pos];
                    self.pos += 1;
                    // 只含 ASCII 时走快路径；信封里的 base64 必然全 ASCII。
                    return core::str::from_utf8(raw)
                        .map(str::to_owned)
                        .map_err(|_| self.error("字符串不是合法 UTF-8"));
                }
                Some(b'\\') => return Err(self.error("信封不允许转义序列")),
                Some(byte) if byte < 0x20 => {
                    return Err(self.error("字符串内含未转义的控制字符"));
                }
                Some(_) => self.pos += 1,
            }
        }
    }
}
