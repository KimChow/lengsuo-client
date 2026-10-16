//! 输出脱敏过滤器（开工说明 §4：任何工具输出先过脱敏再进事件流）。
//!
//! 规则：键名族（password/pwd/pin/secret/token/*key/authorization/cookie/credential）
//! 紧跟分隔符与值时，只替换值部分，键名与周边文本保留以便排障；PEM 私钥块整体替换。
//! 凭据值不得进入模型上下文、事件流或日志。值短于 4 字符不替换，避免误伤普通词句。

use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// 脱敏后的值占位符。
const MASK: &str = "***";

/// 私钥块整体替换的占位。
const PEM_MASK: &str = r#"{"redacted":"private-key-block"}"#;

/// 键名族。
const KEY_NAMES: &str = r"(?:pass(?:word|wd)?|pwd|pin|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|authorization|cookie|credential|session[_-]?id)";

/// 分隔符：允许 JSON 引号形态与空白。
const SEP: &str = r#"["']?\s*[:=]\s*["']?"#;

/// 认证方案前缀：`Authorization: Bearer x` 里方案名保留，值替换。
const SCHEME: &str = r"(?:Bearer|Basic|Digest|Token)[ ]{1,}";

/// 值：到空白/引号/逗号/分号/星号为止（星号排除使已脱敏文本不再命中，保证幂等）。
const VALUE: &str = r#"[^\s\x22',;*]{4,}"#;

/// PEM 私钥块（含未闭合尾部的截断情形）。
const PEM_PATTERN: &str =
    r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)";

/// 脱敏器（无状态；规则编译一次并缓存）。
#[derive(Debug, Clone, Copy, Default)]
pub struct Redactor {
    _priv: (),
}

impl Redactor {
    /// v0 默认规则集。
    pub fn default_v0() -> Self {
        Self { _priv: () }
    }

    /// 对一段文本脱敏：私钥块优先，其次键值对的值部分。
    pub fn redact_str(&self, input: &str) -> String {
        if input.is_empty() {
            return String::new();
        }
        let rules = rules();
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        for m in rules.pem.find_iter(input) {
            edits.push((m.start(), m.end(), PEM_MASK.to_string()));
        }
        for cap in rules.key_value.captures_iter(input) {
            let (Some(all), Some(val)) = (cap.get(0), cap.get(1)) else {
                continue;
            };
            // 保留键名与分隔符，只替换值部分
            edits.push((
                all.start(),
                val.start(),
                input[all.start()..val.start()].to_string(),
            ));
            edits.push((val.start(), val.end(), MASK.to_string()));
        }
        edits.sort_by_key(|(start, _, _)| *start);
        let mut out = String::with_capacity(input.len());
        let mut cursor = 0usize;
        for (start, end, text) in edits {
            if start < cursor {
                continue; // 落在前一次替换区间内
            }
            out.push_str(&input[cursor..start]);
            out.push_str(&text);
            cursor = end;
        }
        out.push_str(&input[cursor..]);
        out
    }

    /// 递归对 JSON 值脱敏；敏感键名的值整体替换。
    pub fn redact_json(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.redact_str(text)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|i| self.redact_json(i)).collect())
            }
            Value::Object(map) => map
                .iter()
                .map(|(k, v)| {
                    let next = if is_sensitive_key(k) {
                        Value::String(MASK.to_string())
                    } else {
                        self.redact_json(v)
                    };
                    (k.clone(), next)
                })
                .collect(),
            other => other.clone(),
        }
    }

    /// 是否需要脱敏（审计打标用，不改内容）。
    pub fn needs_redaction(&self, input: &str) -> bool {
        let rules = rules();
        rules.key_value.is_match(input) || rules.pem.is_match(input)
    }

    /// 工具参数摘要：只保留键名与值类型，绝不回显值（审批事件与判定说明用）。
    pub fn summarize_args(&self, args: &Value) -> String {
        match args {
            Value::Object(map) => {
                let mut parts: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{k}:{}", kind_of(v)))
                    .collect();
                parts.sort();
                parts.join(", ")
            }
            other => kind_of(other).to_string(),
        }
    }
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

struct Rules {
    key_value: Regex,
    pem: Regex,
    key_name: Regex,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| Rules {
        key_value: Regex::new(&format!("(?i){KEY_NAMES}{SEP}(?:{SCHEME})?({VALUE})"))
            .expect("脱敏键值正则必须可编译"),
        pem: Regex::new(PEM_PATTERN).expect("私钥块正则必须可编译"),
        key_name: Regex::new(&format!("(?i)^{KEY_NAMES}$")).expect("键名正则必须可编译"),
    })
}

/// 独立键名判定（JSON 对象场景）。
fn is_sensitive_key(key: &str) -> bool {
    rules().key_name.is_match(key)
}
