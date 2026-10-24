//! 最小 JSON：只覆盖契约 §5.3.1 载荷所需的子集（手写，零新依赖）。
//!
//! 契约 §5.3.1 把业务帧载荷定成 **UTF-8 JSON**：数字只允许十进制整数
//! （`nonce` 是十进制整数，无科学计数法），载荷内二进制走 base64url
//! （[`crate::base64url`]），且 `clientDataJSON` 模板要求键顺序**固定**
//! ⇒ 本模块的对象/数组一律**保序**（`Vec<(String, Value)>`），编码可逐字节复现。
//!
//! 支持：对象、数组、字符串（`\" \\ \/ \b \f \n \r \t` + `\uXXXX` 含**代理对**）、
//! 非负十进制整数、`true`/`false`/`null`。
//! ⛔ 拒绝：`-1`、`1.0`、`1e3`、`+1`、前导零、非法转义、缺引号、尾随字节、
//! 重复键、未转义控制字符、非 UTF-8、超深嵌套、超大输入 —— 各报具名错误。
//!
//! [`crate::envelope`] 里另有一个信封专用的极小解析器（只认扁平对象 + 一个
//! 字符串字段、**禁止任何转义**）；两者刻意不共用：信封的严格性是安全属性，
//! 载荷的表达能力是功能属性。
//!
//! 自设工程决定：输入上限 [`MAX_JSON_BYTES`]（只挡超大输入、⛔ 不截断）、
//! 嵌套上限 [`MAX_JSON_DEPTH`]。编码口径：`"` `\` 与控制字符必须转义
//! （`< 0x20`：短式 `\b \f \n \r \t`，其余 `\u00xx`），**非 ASCII 原样 UTF-8**。

use core::fmt::Write as _;

/// 解析输入字节数上限：1 MiB（与 [`crate::frame::MAX_PAYLOAD_LEN`] 同值，
/// 对合法载荷永不触发；一超限即 [`JsonError::InputTooLong`]）。
pub const MAX_JSON_BYTES: usize = 1024 * 1024;

/// 容器嵌套层数上限：16（自设工程决定；一超限即 [`JsonError::DepthExceeded`]）。
pub const MAX_JSON_DEPTH: usize = 16;

/// JSON 值（**保序**：对象用 `Vec<(String, Value)>` 而非 map）。
///
/// `Debug` 是手写的：只打形状（键名与类型/长度），⛔ 绝不打字符串内容 ——
/// 载荷承载凭据数据（契约 §5.3.1：宿主侧日志只打类型与长度）。
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// 对象（保序键值对）。
    Object(Vec<(String, Value)>),
    /// 数组（保序）。
    Array(Vec<Value>),
    /// 字符串（转义已解码）。
    String(String),
    /// 非负十进制整数。
    Uint(u64),
    /// 布尔。
    Bool(bool),
    /// JSON `null`。
    Null,
}

impl Value {
    /// 若是对象，返回保序键值对切片。
    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }

    /// 若是数组，返回元素切片。
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// 若是字符串，返回其内容。
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// 若是非负整数，返回其值。
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(number) => Some(*number),
            _ => None,
        }
    }

    /// 若是布尔，返回其值。
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(flag) => Some(*flag),
            _ => None,
        }
    }
}

impl core::fmt::Debug for Value {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Object(entries) => {
                formatter.write_str("Object{")?;
                for (index, (key, value)) in entries.iter().enumerate() {
                    formatter.write_str(if index == 0 { "" } else { ", " })?;
                    write!(formatter, "{key}: {value:?}")?;
                }
                formatter.write_str("}")
            }
            Self::Array(items) => write!(formatter, "Array({} items)", items.len()),
            Self::String(text) => write!(formatter, "String({} chars)", text.chars().count()),
            Self::Uint(number) => write!(formatter, "Uint({number})"),
            Self::Bool(flag) => write!(formatter, "Bool({flag})"),
            Self::Null => formatter.write_str("Null"),
        }
    }
}

impl From<u64> for Value {
    fn from(number: u64) -> Self {
        Self::Uint(number)
    }
}

impl From<bool> for Value {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::String(text.to_owned())
    }
}

/// JSON 解析 / 编码失败。
///
/// 全部 fail-closed：任何分支都不返回部分结果、不猜测、不「尽力解析」；
/// 变体之间语义可区分，多数带**字节偏移**便于定位跨端不一致。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// 输入超过 [`MAX_JSON_BYTES`]。
    #[error("JSON 输入 {actual} 字节超过上限 {limit} 字节：拒绝，不截断")]
    InputTooLong { limit: usize, actual: usize },
    /// 输入不是合法 UTF-8。
    #[error("JSON 输入不是合法 UTF-8（首个非法字节偏移 {at}）")]
    NotUtf8 { at: usize },
    /// 嵌套超过 [`MAX_JSON_DEPTH`] 层。
    #[error("JSON 嵌套超过 {limit} 层（偏移 {at}）")]
    DepthExceeded { limit: usize, at: usize },
    /// 值还没读完，输入就结束了。
    #[error("JSON 输入意外结束（偏移 {at}）")]
    UnexpectedEnd { at: usize },
    /// 遇到了不该出现的字节。
    #[error("JSON 偏移 {at} 处期望{expected}，实际字节 {found:#04x}")]
    UnexpectedByte {
        at: usize,
        expected: &'static str,
        found: u8,
    },
    /// 顶层值之后还有多余字节。
    #[error("JSON 顶层值之后有多余字节（偏移 {at}）")]
    TrailingBytes { at: usize },
    /// 字符串没有闭合引号。
    #[error("JSON 字符串未闭合（偏移 {at}）")]
    UnterminatedString { at: usize },
    /// 字符串里有未转义的控制字符（`< 0x20`）。
    #[error("JSON 字符串含未转义控制字符（偏移 {at}）")]
    ControlCharInString { at: usize },
    /// 非法转义序列。
    #[error("JSON 非法转义 `\\{escape}`（偏移 {at}）")]
    InvalidEscape { at: usize, escape: char },
    /// `\uXXXX` 的十六进制位数非法。
    #[error("JSON `\\u` 转义的十六进制位数非法（偏移 {at}）")]
    InvalidUnicodeEscape { at: usize },
    /// 代理对不成立（孤立代理，或高代理后不是低代理）。
    #[error("JSON `\\u` 代理对不成立（偏移 {at}）")]
    UnpairedSurrogate { at: usize },
    /// 对象里同一个键出现两次。
    #[error("JSON 对象重复键 {key:?}：拒绝（两个真值源）")]
    DuplicateKey { key: String },
    /// 数字带负号。
    #[error("JSON 数字不允许负号（偏移 {at}）")]
    NegativeNumber { at: usize },
    /// 数字带小数部分。
    #[error("JSON 数字不允许小数部分（偏移 {at}）")]
    FractionalNumber { at: usize },
    /// 数字带指数部分。
    #[error("JSON 数字不允许指数部分（偏移 {at}）")]
    ExponentNumber { at: usize },
    /// 数字有前导零（`01`）。
    #[error("JSON 数字不允许前导零（偏移 {at}）")]
    LeadingZero { at: usize },
    /// 数字带正号（`+1`）。
    #[error("JSON 数字不允许正号（偏移 {at}）")]
    LeadingPlus { at: usize },
    /// 整数超过 `u64::MAX`。
    #[error("JSON 整数超过 u64 上限（偏移 {at}）")]
    NumberOutOfRange { at: usize },
    /// 对象缺少必填字段。
    #[error("JSON 对象缺少必填字段 {field:?}")]
    MissingField { field: &'static str },
    /// 字段存在但类型不符。
    #[error("JSON 字段 {field:?} 期望{expected}")]
    FieldTypeMismatch {
        field: &'static str,
        expected: &'static str,
    },
}

/// 解析 UTF-8 JSON 字节（契约 §5.3.1：载荷是 UTF-8 JSON、数字是整数）。
///
/// # Errors
/// [`JsonError`] 的每个变体对应一类可区分的失败（见变体文档）。
pub fn parse(bytes: &[u8]) -> Result<Value, JsonError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(JsonError::InputTooLong {
            limit: MAX_JSON_BYTES,
            actual: bytes.len(),
        });
    }
    let text = core::str::from_utf8(bytes).map_err(|error| JsonError::NotUtf8 {
        at: error.valid_up_to(),
    })?;
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_whitespace();
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.pos != text.len() {
        return Err(JsonError::TrailingBytes { at: parser.pos });
    }
    Ok(value)
}

/// 编码成 JSON 文本（保序、无多余空白、非 ASCII 原样 UTF-8）。
#[must_use]
pub fn encode(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Object(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::String(text) => write_string(out, text),
        Value::Uint(number) => out.push_str(&number.to_string()),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth > MAX_JSON_DEPTH {
            return Err(JsonError::DepthExceeded {
                limit: MAX_JSON_DEPTH,
                at: self.pos,
            });
        }
        match self.peek() {
            None => Err(JsonError::UnexpectedEnd { at: self.pos }),
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => self.parse_string().map(Value::String),
            Some(b't') => self.parse_literal(b"true", Value::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", Value::Bool(false)),
            Some(b'n') => self.parse_literal(b"null", Value::Null),
            Some(b'-') => Err(JsonError::NegativeNumber { at: self.pos }),
            Some(b'+') => Err(JsonError::LeadingPlus { at: self.pos }),
            Some(byte) if byte.is_ascii_digit() => self.parse_number(),
            Some(byte) => Err(unexpected_byte(self.pos, "JSON 值", byte)),
        }
    }

    fn parse_literal(&mut self, literal: &[u8], value: Value) -> Result<Value, JsonError> {
        for wanted in literal {
            match self.bump() {
                Some(byte) if byte == *wanted => {}
                Some(byte) => return Err(unexpected_byte(self.pos - 1, "字面量", byte)),
                None => return Err(JsonError::UnexpectedEnd { at: self.pos }),
            }
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        if self.bytes[self.pos] == b'0' {
            self.pos += 1;
            if matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                return Err(JsonError::LeadingZero { at: start });
            }
        }
        let mut value: u64 = 0;
        while let Some(byte) = self.peek() {
            if !byte.is_ascii_digit() {
                break;
            }
            self.pos += 1;
            let digit = u64::from(byte - b'0');
            value = value
                .checked_mul(10)
                .and_then(|partial| partial.checked_add(digit))
                .ok_or(JsonError::NumberOutOfRange { at: start })?;
        }
        match self.peek() {
            Some(b'.') => Err(JsonError::FractionalNumber { at: self.pos }),
            Some(b'e' | b'E') => Err(JsonError::ExponentNumber { at: self.pos }),
            _ => Ok(Value::Uint(value)),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.pos += 1; // 跳过 '{'
        let mut entries: Vec<(String, Value)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(entries));
        }
        loop {
            self.skip_whitespace();
            let Some(byte) = self.peek() else {
                return Err(JsonError::UnexpectedEnd { at: self.pos });
            };
            if byte != b'"' {
                return Err(unexpected_byte(self.pos, "键名（JSON 字符串）", byte));
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(existing, _)| *existing == key) {
                return Err(JsonError::DuplicateKey { key });
            }
            self.skip_whitespace();
            self.expect_byte(b':', "冒号")?;
            self.skip_whitespace();
            let value = self.parse_value(depth + 1)?;
            entries.push((key, value));
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Value::Object(entries)),
                Some(byte) => return Err(unexpected_byte(self.pos - 1, "逗号或右花括号", byte)),
                None => return Err(JsonError::UnexpectedEnd { at: self.pos }),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.pos += 1; // 跳过 '['
        let mut items: Vec<Value> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value(depth + 1)?);
            self.skip_whitespace();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(items)),
                Some(byte) => return Err(unexpected_byte(self.pos - 1, "逗号或右方括号", byte)),
                None => return Err(JsonError::UnexpectedEnd { at: self.pos }),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        let start = self.pos;
        self.pos += 1; // 跳过开引号
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            match self.bump() {
                None => return Err(JsonError::UnterminatedString { at: start }),
                Some(b'"') => {
                    return String::from_utf8(bytes).map_err(|error| JsonError::NotUtf8 {
                        at: start + error.utf8_error().valid_up_to(),
                    })
                }
                Some(b'\\') => self.parse_escape(&mut bytes)?,
                Some(byte) if byte < 0x20 => {
                    return Err(JsonError::ControlCharInString { at: self.pos - 1 })
                }
                Some(byte) => bytes.push(byte),
            }
        }
    }

    /// 解析 `\` 后面的一个转义（反斜杠已被消费）。
    fn parse_escape(&mut self, out: &mut Vec<u8>) -> Result<(), JsonError> {
        let at = self.pos - 1;
        let Some(escaped) = self.bump() else {
            return Err(JsonError::UnexpectedEnd { at: self.pos });
        };
        match escaped {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'u' => return self.parse_unicode_escape(out, at),
            other => {
                return Err(JsonError::InvalidEscape {
                    at,
                    escape: char::from(other),
                })
            }
        }
        Ok(())
    }

    /// 解析 `\u` 后 4 个十六进制位，并处理**代理对**（astral 平面）。
    fn parse_unicode_escape(&mut self, out: &mut Vec<u8>, at: usize) -> Result<(), JsonError> {
        let code = self.parse_hex4()?;
        match code {
            0xD800..=0xDBFF => {
                // 高代理：后面必须紧跟 `\uXXXX` 形式的低代理。
                if self.peek() != Some(b'\\') || self.bytes.get(self.pos + 1) != Some(&b'u') {
                    return Err(JsonError::UnpairedSurrogate { at });
                }
                self.pos += 2;
                let low = self.parse_hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(JsonError::UnpairedSurrogate { at });
                }
                let combined = 0x1_0000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                let Some(character) = char::from_u32(combined) else {
                    return Err(JsonError::UnpairedSurrogate { at });
                };
                let mut buffer = [0u8; 4];
                out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
            0xDC00..=0xDFFF => return Err(JsonError::UnpairedSurrogate { at }),
            _ => {
                let Some(character) = char::from_u32(code) else {
                    return Err(JsonError::UnpairedSurrogate { at });
                };
                let mut buffer = [0u8; 4];
                out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
        Ok(())
    }

    fn parse_hex4(&mut self) -> Result<u32, JsonError> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let Some(byte) = self.bump() else {
                return Err(JsonError::UnexpectedEnd { at: self.pos });
            };
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(JsonError::InvalidUnicodeEscape { at: self.pos - 1 }),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn expect_byte(&mut self, wanted: u8, expected: &'static str) -> Result<(), JsonError> {
        match self.bump() {
            Some(byte) if byte == wanted => Ok(()),
            Some(byte) => Err(unexpected_byte(self.pos - 1, expected, byte)),
            None => Err(JsonError::UnexpectedEnd { at: self.pos }),
        }
    }
}

/// 保序 JSON 对象构建器（按调用顺序落键；`clientDataJSON` 模板依赖这一点）。
#[derive(Default)]
pub(crate) struct ObjectBuilder(Vec<(String, Value)>);

impl ObjectBuilder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 追加字段；`impl Into<Value>` 收 `u64` / `bool` / `&str` / `Value`。
    pub(crate) fn push(mut self, field: &str, value: impl Into<Value>) -> Self {
        self.0.push((field.to_owned(), value.into()));
        self
    }

    /// 仅在 `value` 非 `None` 时追加（契约里带 `?` 的可选字段）。
    pub(crate) fn opt(mut self, field: &str, value: &Option<String>) -> Self {
        if let Some(text) = value {
            self.0.push((field.to_owned(), Value::String(text.clone())));
        }
        self
    }

    pub(crate) fn build(self) -> Value {
        Value::Object(self.0)
    }
}

/// 字段类型不符错误的构造器（省去各处重复写全字段名）。
fn mismatch(field: &'static str, expected: &'static str) -> JsonError {
    JsonError::FieldTypeMismatch { field, expected }
}

/// 「期望 X，实际字节 Y」错误的构造器；`at` 由调用方给出
/// （字节已被消费后的报错传 `pos - 1`）。
fn unexpected_byte(at: usize, expected: &'static str, found: u8) -> JsonError {
    JsonError::UnexpectedByte {
        at,
        expected,
        found,
    }
}

/// 保序 JSON 对象的带类型读取器：只按契约已知字段取值 ⇒ **未知字段自动忽略**
/// （前向兼容）；缺必填 / 类型不符各报具名错误。
pub(crate) struct Fields<'a> {
    entries: &'a [(String, Value)],
}

impl<'a> Fields<'a> {
    /// 包住必须是对象的 [`Value`]；`field` 只用于错误描述。
    pub(crate) fn new(value: &'a Value, field: &'static str) -> Result<Self, JsonError> {
        value
            .as_object()
            .map(|entries| Self { entries })
            .ok_or(mismatch(field, "对象"))
    }

    /// 按键取**第一个**出现的值（重复键在解析期已被拒）。
    pub(crate) fn raw(&self, field: &str) -> Option<&'a Value> {
        self.entries
            .iter()
            .find(|(key, _)| key == field)
            .map(|(_, value)| value)
    }

    pub(crate) fn required(&self, field: &'static str) -> Result<&'a Value, JsonError> {
        self.raw(field).ok_or(JsonError::MissingField { field })
    }

    pub(crate) fn uint(&self, field: &'static str) -> Result<u64, JsonError> {
        self.required(field)?
            .as_u64()
            .ok_or(mismatch(field, "非负整数"))
    }

    /// 必填的 u32 字段（超出 u32 范围也报错）。
    pub(crate) fn u32(&self, field: &'static str) -> Result<u32, JsonError> {
        let value = self.uint(field)?;
        u32::try_from(value).map_err(|_| mismatch(field, "u32 范围内的整数"))
    }

    pub(crate) fn string(&self, field: &'static str) -> Result<String, JsonError> {
        self.required(field)?
            .as_str()
            .map(str::to_owned)
            .ok_or(mismatch(field, "字符串"))
    }

    /// 可选字符串字段：缺席与 `null` 都算「没有」。
    pub(crate) fn opt_string(&self, field: &'static str) -> Result<Option<String>, JsonError> {
        match self.raw(field) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_str()
                .map(|text| Some(text.to_owned()))
                .ok_or(mismatch(field, "字符串")),
        }
    }

    pub(crate) fn bool(&self, field: &'static str) -> Result<bool, JsonError> {
        self.required(field)?
            .as_bool()
            .ok_or(mismatch(field, "布尔"))
    }

    /// 必填的数组字段。
    pub(crate) fn array(&self, field: &'static str) -> Result<&'a [Value], JsonError> {
        self.required(field)?
            .as_array()
            .ok_or(mismatch(field, "数组"))
    }

    /// 必填的**字符串数组**字段（逐元素校验）。
    pub(crate) fn strings(&self, field: &'static str) -> Result<Vec<String>, JsonError> {
        self.array(field)?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or(mismatch(field, "字符串数组"))
            })
            .collect()
    }

    /// 必填的**对象**字段。
    pub(crate) fn object(&self, field: &'static str) -> Result<Self, JsonError> {
        Self::new(self.required(field)?, field)
    }

    /// 必填的**对象数组**字段，逐元素返回读取器。
    pub(crate) fn objects(&self, field: &'static str) -> Result<Vec<Self>, JsonError> {
        self.array(field)?
            .iter()
            .map(|item| Self::new(item, field))
            .collect()
    }
}
