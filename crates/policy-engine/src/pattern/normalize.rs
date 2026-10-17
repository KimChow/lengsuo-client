//! URL 归一化（规格 §2.5「scheme 归一化（缺省 https）」）。
//!
//! 模式侧与 URL 侧共用同一比较面（host + path）：不存在「模式宽松、URL 严格」的错配。
//! 一切不认识的写法一律拒绝，不做「去掉脏字符继续跑」的宽松解释——
//! 静默修正是黑名单被绕过的头号来源。

use super::error::CompileError;
use super::{MAX_SEGMENT_LEN, MAX_URL_LEN};

/// 归一化后的 URL：只保留 `host` 与 `path` 两个比较面。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedUrl {
    host: String,
    path: String,
    normalized: String,
}

impl NormalizedUrl {
    /// 归一化输入 URL：scheme 缺省 `https`、query/fragment 剥离、userinfo 拒绝、
    /// host 校验（含端口与 IPv6 字面量）、空路径补 `/`。大小写不折叠（规格 §2.5）。
    pub fn parse(raw: &str) -> Result<Self, CompileError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CompileError::EmptyUrl);
        }
        if trimmed.len() > MAX_URL_LEN {
            return Err(CompileError::UrlTooLong {
                length: trimmed.len(),
                max: MAX_URL_LEN,
            });
        }
        // 控制字符/DEL 一律拒绝；空白也拒绝（`%20` 才是 URL 里的合法写法）。
        for ch in trimmed.chars() {
            if ch.is_control() || ch == '\u{7f}' {
                return Err(CompileError::ControlChar(ch as u32));
            }
            if ch.is_whitespace() {
                return Err(CompileError::UrlHasWhitespace);
            }
        }
        check_percent_escapes(trimmed)?;

        // 1. scheme：缺省 https；大小写不敏感；非 http/https 或写法残缺即拒绝。
        let rest = strip_scheme_url(trimmed)?;
        // 2. query / fragment 剥离：追加 `?q=` / `#frag` 不得绕过既有规则。
        let without_tail = match rest.find(['?', '#']) {
            Some(idx) => &rest[..idx],
            None => rest,
        };
        if without_tail.is_empty() {
            return Err(CompileError::EmptyHost);
        }
        // 3. 切分 host 与 path；userinfo 在比较面上没有落点，出现即拒绝。
        let host_end = without_tail.find('/').unwrap_or(without_tail.len());
        let (host_part, path_part) = without_tail.split_at(host_end);
        if host_part.contains('@') {
            return Err(CompileError::UserInfo);
        }
        if host_part.chars().any(char::is_whitespace) {
            return Err(CompileError::HostHasWhitespace);
        }
        // 4. host 校验（含端口与 IPv6 字面量）。
        let host = normalize_host(host_part)?;
        let path = if path_part.is_empty() {
            "/".to_string()
        } else {
            path_part.to_string()
        };
        Ok(NormalizedUrl {
            normalized: format!("{host}{path}"),
            host,
            path,
        })
    }

    /// `host + path` 的归一化文本（比较面）。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// 主机部分（含显式端口）。
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.host
    }

    /// 路径部分（复制自独立字段，始终以 `/` 开头，已剥离 query/fragment）。
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// 比较面文本里的路径切片：借用自 [`NormalizedUrl::as_str`] 这一块输入，零分配。
    /// 命中片段回传给上层写审计原因时用这个，确保借用来源与 `as_str()` 一致。
    #[must_use]
    pub fn path_slice(&self) -> &str {
        &self.normalized[self.host.len()..]
    }
}

/// 去掉 URL 的 scheme 与 `//`；缺省视为 https（规格 §2.5）。
fn strip_scheme_url(raw: &str) -> Result<&str, CompileError> {
    if let Some(idx) = raw.find("://") {
        check_scheme(&raw[..idx])?;
        return Ok(&raw[idx + 3..]);
    }
    if let Some(after) = raw.strip_prefix("//") {
        return Ok(after);
    }
    if let Some(idx) = raw.find(':') {
        let candidate = &raw[..idx];
        // `example.com:8443/a` 的冒号属于端口，`[::1]:8443/a` 的属于 IPv6 字面量。
        if !looks_like_scheme(candidate) {
            return Ok(raw);
        }
        check_scheme(candidate)?;
        // 到这里只剩两种写法：`http:example.com/a`（冒号后直接是 host）与
        // `https:/example.com/a`（单斜杠，authority 落点缺失）。后者是残缺写法，
        // 前者的 host 起始明确，可以按同一比较面归一化。
        let rest = &raw[idx + 1..];
        if rest.starts_with('/') {
            return Err(CompileError::BadScheme(candidate.to_string()));
        }
        return Ok(rest);
    }
    Ok(raw)
}

/// 冒号前的片段是否像 scheme（`example.com:8443` 含 `.`、`[::1]:8443` 含 `[`，都不像）。
fn looks_like_scheme(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && candidate
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '+' || c == '-')
}

fn check_scheme(scheme: &str) -> Result<(), CompileError> {
    let lowered = scheme.to_ascii_lowercase();
    if lowered != "https" && lowered != "http" {
        return Err(CompileError::BadScheme(scheme.to_string()));
    }
    Ok(())
}

/// 校验并原样保留 host（大小写敏感、端口与 IPv6 字面量保留）。
fn normalize_host(part: &str) -> Result<String, CompileError> {
    if part.is_empty() {
        return Err(CompileError::EmptyHost);
    }
    let (name, port) = if part.starts_with('[') {
        // IPv6 字面量：`]` 之后的 `:` 才是端口分隔符。
        let close = part
            .find(']')
            .ok_or_else(|| CompileError::BadIpv6Literal(part.to_string()))?;
        (&part[..close + 1], &part[close + 1..])
    } else if let Some(idx) = part.rfind(':') {
        part.split_at(idx)
    } else {
        (part, "")
    };
    let port = port.strip_prefix(':').unwrap_or(port);
    if !port.is_empty() && !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(CompileError::BadHostChar(
            port.chars().find(|c| !c.is_ascii_digit()).unwrap_or('?'),
        ));
    }
    if name.is_empty() {
        return Err(CompileError::EmptyHost);
    }
    if name.starts_with('[') {
        let inner = name
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| CompileError::BadIpv6Literal(part.to_string()))?;
        if inner.is_empty()
            || !inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return Err(CompileError::BadIpv6Literal(part.to_string()));
        }
        return Ok(part.to_string());
    }
    // 域名：字母数字与 `-`/`_`/`%` 组成标签，标签非空（`a..b`、`.a`、`a.` 一律拒绝）。
    for label in name.split('.') {
        if label.is_empty() {
            return Err(CompileError::EmptyLabel);
        }
        if label.len() > MAX_SEGMENT_LEN {
            return Err(CompileError::SegmentTooLong(label.to_string()));
        }
        for c in label.chars() {
            let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '%' || c > '\u{7f}';
            if !ok {
                return Err(CompileError::BadHostChar(c));
            }
        }
    }
    Ok(part.to_string())
}

/// 校验 `%` 转义合法（`%` 后必须两位十六进制），不解码。
/// 模式与 URL 以同一形态比较，避免二次解释：`%2F` 永远不等于 `/`。
fn check_percent_escapes(text: &str) -> Result<(), CompileError> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(CompileError::BadPercentEscape(
                    text[i..].chars().take(4).collect(),
                ));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}
