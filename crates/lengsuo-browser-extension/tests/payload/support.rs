//! 载荷向量回放的共享夹具：读向量文件、按名字取条目、错误变体命名。

use lengsuo_browser_extension::base64url::Base64UrlError;
use lengsuo_browser_extension::json::JsonError;
use lengsuo_browser_extension::payload::PayloadError;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;

/// 向量文件路径（`tests/vectors/payload-v1.json`，本卡专用，
/// ⛔ 不碰跨仓共享的 `credential-wire-v1.json`）。
pub fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("payload-v1.json")
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

/// 取某一段（必须是数组）。
pub fn section(name: &str) -> &'static [Value] {
    load()
        .get(name)
        .unwrap_or_else(|| panic!("向量文件缺段 {name}"))
        .as_array()
        .unwrap_or_else(|| panic!("段 {name} 必须是数组"))
        .as_slice()
}

/// 按名字取段内条目。
pub fn entry(section_name: &str, name: &str) -> &'static Value {
    section(section_name)
        .iter()
        .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("段 {section_name} 里没有 {name}"))
}

/// [`JsonError`] 的变体名（向量 `invalid` 段的 `error` 字段口径）。
pub fn json_error_name(error: &JsonError) -> &'static str {
    match error {
        JsonError::InputTooLong(..) => "InputTooLong",
        JsonError::NotUtf8(..) => "NotUtf8",
        JsonError::DepthExceeded(..) => "DepthExceeded",
        JsonError::UnexpectedEnd(..) => "UnexpectedEnd",
        JsonError::UnexpectedByte(..) => "UnexpectedByte",
        JsonError::TrailingBytes(..) => "TrailingBytes",
        JsonError::UnterminatedString(..) => "UnterminatedString",
        JsonError::ControlCharInString(..) => "ControlCharInString",
        JsonError::InvalidEscape(..) => "InvalidEscape",
        JsonError::InvalidUnicodeEscape(..) => "InvalidUnicodeEscape",
        JsonError::UnpairedSurrogate(..) => "UnpairedSurrogate",
        JsonError::DuplicateKey(..) => "DuplicateKey",
        JsonError::NegativeNumber(..) => "NegativeNumber",
        JsonError::FractionalNumber(..) => "FractionalNumber",
        JsonError::ExponentNumber(..) => "ExponentNumber",
        JsonError::LeadingZero(..) => "LeadingZero",
        JsonError::LeadingPlus(..) => "LeadingPlus",
        JsonError::NumberOutOfRange(..) => "NumberOutOfRange",
        JsonError::MissingField(..) => "MissingField",
        JsonError::FieldTypeMismatch(..) => "FieldTypeMismatch",
    }
}

/// [`PayloadError`] 的**根因**名：`Json` 变体下钻到具体 JSON 错误，
/// 其余三个是载荷层自己的名字（向量 `error` 字段统一指根因）。
pub fn payload_error_name(error: &PayloadError) -> String {
    match error {
        PayloadError::Json(inner) => json_error_name(inner).to_owned(),
        PayloadError::InvalidBinary { .. } => "InvalidBinary".to_owned(),
        PayloadError::InvalidValue { .. } => "InvalidValue".to_owned(),
        PayloadError::NonceMismatch { .. } => "NonceMismatch".to_owned(),
    }
}

/// [`Base64UrlError`] 的变体名。
pub fn base64url_error_name(error: &Base64UrlError) -> &'static str {
    match error {
        Base64UrlError::InvalidChar(..) => "InvalidChar",
        Base64UrlError::PaddingNotAllowed(..) => "PaddingNotAllowed",
        Base64UrlError::InvalidLength(..) => "InvalidLength",
    }
}

/// 向量里的可选字符串（`null` / 缺席 ⇒ `None`）。
pub fn opt_str(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

/// 向量里的字符串数组。
pub fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("必须是数组")
        .iter()
        .map(|item| item.as_str().expect("元素必须是字符串").to_owned())
        .collect()
}
