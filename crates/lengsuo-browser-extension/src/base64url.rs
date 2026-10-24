//! base64url（RFC 4648 §5，**无 padding**）：契约 §5.3.1 的**载荷内**二进制编码。
//!
//! # 与 [`crate::base64`] 是两层，⛔ 不要混用
//!
//! | 层 | 模块 | 字母表 | padding | 用在 |
//! |---|---|---|---|---|
//! | **信封层** | [`crate::base64`] | 标准 `+` / `/` | 编码无、解码宽容 | `{"frame_b64":"…"}` |
//! | **载荷层** | 本模块 | `-` / `_` | **两侧都无** | §5.3.1 的 `challenge` / `allow_ids` / `*_b64` |
//!
//! 契约 §5.3.1 原话：「载荷内二进制编码 = **base64url（无 padding）**；
//! ⚠️ 与 §5.2.1 信封层的**标准 base64**（`+`/`/`）是**两层**，⛔ 不要混用」。
//!
//! 两个模块**模块不同、类型不同、错误类型不同**：[`crate::Base64Error`] 与
//! [`Base64UrlError`] 是互不相关的类型，交叉解码**必然报错**（见向量文件里
//! 那条「同一段字节，两种编码产出不同字符串」的锚点）。
//!
//! # 严格性
//!
//! 解码**拒绝** `=` / `+` / `/` 与非 ASCII，各报具名错误：
//! - `=` ⇒ [`Base64UrlError::PaddingNotAllowed`]（契约规定无 padding）；
//! - `+` / `/` / 其它字母表外字符 ⇒ [`Base64UrlError::InvalidChar`]；
//! - 数据长度 ≡ 1 (mod 4) ⇒ [`Base64UrlError::InvalidLength`]。
//!
//! # 为什么手写
//!
//! 本 crate 的运行时依赖只有 `thiserror`（零新依赖纪律）；
//! 算法按 RFC 4648 §5 逐位实现，不引入第三方 base64 库。

/// base64url 字母表（RFC 4648 §5）：`A–Z a–z 0–9 - _`。
const ALPHABET: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url 编解码失败。
///
/// 每个变体对应一类可区分的失败，与 [`crate::Base64Error`] 刻意不共享。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base64UrlError {
    /// 出现字母表之外的字符（含 `+` / `/` / 非 ASCII）。
    ///
    /// 第一个字段是实际字符，第二个字段是它在输入里的**字节偏移**。
    #[error("非法 base64url 字符 {0:?}（字节偏移 {1}）")]
    InvalidChar(char, usize),

    /// 出现 `=` padding（契约 §5.3.1 规定载荷层**无 padding**）。
    #[error("base64url 不允许 padding `=`（字节偏移 {0}）")]
    PaddingNotAllowed(usize),

    /// 长度非法：数据长度 ≡ 1 (mod 4)，不可能解出整字节。
    #[error("base64url 长度 {0} 非法（≡ 1 mod 4）")]
    InvalidLength(usize),
}

/// base64url 编码（RFC 4648 §5 字母表，**不追加 `=` padding**）。
///
/// 空输入返回空字符串。
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
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

/// base64url 解码：**只接受无 padding 的规范输入**。
///
/// ⛔ 不接受 `=`（哪怕在尾部）、`+`、`/`；非法输入一律具名错误，
/// 绝**不**「尽力解析」（例如把 `+` 当 `-` 收下）。
///
/// # Errors
/// - 字母表之外的字符（含 `+` / `/` / 非 ASCII）⇒ [`Base64UrlError::InvalidChar`]。
/// - `=` ⇒ [`Base64UrlError::PaddingNotAllowed`]。
/// - 数据长度 ≡ 1 (mod 4) ⇒ [`Base64UrlError::InvalidLength`]。
pub fn decode(input: &str) -> Result<Vec<u8>, Base64UrlError> {
    let mut values = Vec::with_capacity(input.len().div_ceil(4) * 3);
    for (offset, character) in input.char_indices() {
        if character == '=' {
            return Err(Base64UrlError::PaddingNotAllowed(offset));
        }
        let Some(value) = decode_char(character) else {
            return Err(Base64UrlError::InvalidChar(character, offset));
        };
        values.push(value);
    }
    if values.len() % 4 == 1 {
        return Err(Base64UrlError::InvalidLength(input.len()));
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
            _ => return Err(Base64UrlError::InvalidLength(input.len())),
        }
    }
    Ok(out)
}

/// 把单个字符映射到 6 位值；base64url 字母表之外返回 `None`。
const fn decode_char(character: char) -> Option<u32> {
    match character {
        'A'..='Z' => Some(character as u32 - 'A' as u32),
        'a'..='z' => Some(character as u32 - 'a' as u32 + 26),
        '0'..='9' => Some(character as u32 - '0' as u32 + 52),
        '-' => Some(62),
        '_' => Some(63),
        _ => None,
    }
}
