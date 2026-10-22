//! 标准 base64（RFC 4648 §4）的最小实现。
//!
//! 这一层只做**字节 ⇄ 文本**，不涉及 JSON，也不涉及业务帧语义。
//!
//! # 编码（canonical，不带 padding）
//!
//! 使用标准字母表 `A–Z a–z 0–9 + /`，**不带 `=` 尾部填充**：
//! 空输入 → 空字符串；`"f"` → `"Zg"`；`"foo"` → `"Zm9v"`。
//! 不带 padding 是为了让信封文本最短，同时解码端对带 padding 的输入宽容。
//!
//! # 解码（宽容）
//!
//! 接受 0/1/2 个结尾 `=`（RFC 4648 §3.2 允许带填充的输入），但拒绝：
//! - 字母表之外的字符（含非 ASCII）⇒ [`Base64Error::InvalidChar`]；
//! - `=` 出现在中间或数量超过 2 ⇒ [`Base64Error::MisplacedPadding`]；
//! - 数据长度 ≡ 1 (mod 4) ⇒ [`Base64Error::InvalidLength`]
//!   （这种长度不可能解出整字节）。
//!
//! ⛔ 不使用 URL-safe 字母表（`-` / `_`），也不使用 Crockford 变体。
//!
//! # 为什么手写
//!
//! 本 crate 的运行时依赖只有 `thiserror`（零新依赖纪律）；
//! 算法按 RFC 4648 逐位实现，不引入第三方 base64 库。

/// 标准 base64 字母表（RFC 4648 §4）。
const ALPHABET: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64 编解码失败。
///
/// 每个变体对应一类可区分的失败，不合并成笼统的字符串错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    /// 出现字母表之外的字符。
    ///
    /// 第一个字段是实际字符，第二个字段是它在输入里的**字节偏移**。
    #[error("非法 base64 字符 {0:?}（字节偏移 {1}）")]
    InvalidChar(char, usize),

    /// 长度非法：数据长度 ≡ 1 (mod 4)，不可能解出整字节。
    #[error("base64 长度 {0} 非法（≡ 1 mod 4）")]
    InvalidLength(usize),

    /// `=` 的位置非法：出现在中间、或结尾 `=` 超过 2 个。
    ///
    /// 字段是出问题的 `=` 的字节偏移。
    #[error("base64 padding 位置非法（字节偏移 {0}）")]
    MisplacedPadding(usize),
}

/// 编码 `input` 所需的 base64 字符数（**不含 padding**）。
///
/// 用于在真正分配字符串之前判断信封长度上限。
#[must_use]
pub const fn encoded_len(input_len: usize) -> usize {
    let full = (input_len / 3) * 4;
    match input_len % 3 {
        0 => full,
        1 => full + 2,
        _ => full + 3,
    }
}

/// 标准 base64 编码：使用 RFC 4648 §4 字母表，**不追加 `=` padding**。
///
/// 空输入返回空字符串。
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(input.len()));
    for chunk in input.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        let bits = (first << 16) | (second << 8) | third;
        out.push(char::from(ALPHABET[((bits >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((bits >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((bits >> 6) & 0x3f) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(bits & 0x3f) as usize]));
        }
    }
    out
}

/// 标准 base64 解码：宽容接受尾部 0/1/2 个 `=`。
///
/// 返回解码后的原始字节。⛔ 本函数不校验这些字节是不是合法业务帧
/// （帧头校验属于 [`crate::frame`]）。
///
/// # Errors
/// - 字母表之外的字符 ⇒ [`Base64Error::InvalidChar`]（含字节偏移）。
/// - `=` 出现在数据中间、或结尾 `=` 超过 2 个 ⇒
///   [`Base64Error::MisplacedPadding`]。
/// - 数据长度 ≡ 1 (mod 4) ⇒ [`Base64Error::InvalidLength`]。
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let mut values = Vec::with_capacity(encoded_len(input.len()));
    let mut padding = 0usize;
    let mut first_padding = None;
    for (offset, character) in input.char_indices() {
        if character == '=' {
            if first_padding.is_none() {
                first_padding = Some(offset);
            }
            padding += 1;
            continue;
        }
        if first_padding.is_some() {
            // `=` 之后又出现数据字符 ⇒ padding 不在尾部。
            return Err(Base64Error::MisplacedPadding(offset));
        }
        let Some(value) = decode_char(character) else {
            return Err(Base64Error::InvalidChar(character, offset));
        };
        values.push(value);
    }
    if let Some(offset) = first_padding {
        if padding > 2 {
            return Err(Base64Error::MisplacedPadding(offset));
        }
    }
    if values.len() % 4 == 1 {
        return Err(Base64Error::InvalidLength(input.len()));
    }
    let mut out = Vec::with_capacity(values.len() / 4 * 3 + 1);
    for chunk in values.chunks(4) {
        match chunk {
            [a, b, c, d] => {
                let bits = (a << 18) | (b << 12) | (c << 6) | d;
                out.push((bits >> 16) as u8);
                out.push((bits >> 8) as u8);
                out.push(bits as u8);
            }
            [a, b, c] => {
                let bits = (a << 18) | (b << 12) | (c << 6);
                out.push((bits >> 16) as u8);
                out.push((bits >> 8) as u8);
            }
            [a, b] => {
                let bits = (a << 18) | (b << 12);
                out.push((bits >> 16) as u8);
            }
            // values.len() % 4 == 1 已在上面拒绝；空分组不会出现。
            _ => return Err(Base64Error::InvalidLength(input.len())),
        }
    }
    Ok(out)
}

/// 把单个字符映射到 6 位值；字母表之外返回 `None`。
const fn decode_char(character: char) -> Option<u32> {
    match character {
        'A'..='Z' => Some(character as u32 - 'A' as u32),
        'a'..='z' => Some(character as u32 - 'a' as u32 + 26),
        '0'..='9' => Some(character as u32 - '0' as u32 + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    }
}
