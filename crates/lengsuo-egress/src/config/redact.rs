//! 凭据脱敏占位。

/// 脱敏占位：非空即输出 `<redacted>`，空串输出 `<empty>`（长度也不泄漏）。
pub(crate) fn redacted(value: &str) -> &'static str {
    if value.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}
