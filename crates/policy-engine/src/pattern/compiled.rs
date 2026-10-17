//! 已编译模式：构造面与对外查询面（规格 §2.5 的「编译期一次」）。

use super::lex::{
    compile_groups, cross_count, is_bare_host_wildcard, is_single_cross, literal_chars,
    split_tail_count, wildcard_count, Group,
};
use super::normalize::NormalizedUrl;
use super::specificity::Specificity;
use super::CompileError;
use super::MAX_PATTERN_LEN;

/// 已编译的通配符模式。编译一次，多次匹配；匹配期只借用模式与输入，不分配堆内存。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// 规则原文（规格 §1 冻结字段名 `url_pattern`）；字面量 token 借用它的字节区间。
    text: String,
    /// 与 [`NormalizedUrl::as_str`] 同一形态的比较面文本（host + path，空路径补 `/`）。
    normalized: String,
    /// host 段组；裸 `*`/`**` 写法时为「任意主机」的跨段通配。
    host: Vec<Group>,
    /// 路径段组；空列表表示「未写路径」，即只覆盖站点根。
    path: Vec<Group>,
    /// 主机部分写成裸 `*`/`**`：任意主机，可跨标签。
    host_bare_wildcard: bool,
    /// 「所有网页」通配（规格 §2.4：白名单/黑名单各自覆盖的兜底模式）。
    all_pages: bool,
    /// 字面量字符总数：同级精度之间「字面锚点更长者优先」的度量。
    literals: usize,
    /// 通配单元总数（段内 `*`/`?` + 跨段 `**` + 段数限定）。
    wildcards: usize,
    /// 跨段通配（`**`）数量。
    cross: usize,
}

impl Pattern {
    /// 编译模式文本。任何不认识的写法一律 `Err`，绝不放宽成「匹配一切」。
    pub fn compile(pattern: &str) -> Result<Self, CompileError> {
        if pattern.trim().is_empty() {
            return Err(CompileError::EmptyPattern);
        }
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(CompileError::PatternTooLong {
                length: pattern.len(),
                max: MAX_PATTERN_LEN,
            });
        }
        // 隐形字符一律拒绝：规则文本不该有换行/制表/空白，也不做「去掉空白继续跑」的修复。
        for ch in pattern.chars() {
            if ch.is_control() || ch == '\u{7f}' {
                return Err(CompileError::ControlChar(ch as u32));
            }
            if ch.is_whitespace() {
                return Err(CompileError::PatternHasWhitespace);
            }
        }
        // 比较面不含 fragment/query/scheme：写了这类模式永远不会命中，
        // 编译期就拒绝，而不是留一条静默失效的黑名单规则。
        if pattern.contains('#') {
            return Err(CompileError::FragmentInPattern);
        }
        if pattern.contains('=') {
            return Err(CompileError::QueryInPattern);
        }
        if scheme_of_pattern(pattern).is_some() {
            return Err(CompileError::SchemeInPattern);
        }
        check_percent_escapes(pattern)?;

        let (body, tail_count) = split_tail_count(pattern)?;
        // `body` 是 `pattern` 的前缀，因此下面算出的字节偏移对整条模式仍然有效。
        let (host_text, path_raw) = split_host_path(body);
        // 模式写出的前导 `/` 只是分隔符；路径按段匹配，不作为字面量。
        let path_text = path_raw.strip_prefix('/').unwrap_or(path_raw);
        if host_text.is_empty() {
            return Err(CompileError::EmptyHost);
        }

        // 整个 host 只写 `*`/`**` ⇒ 「任意主机」（可跨标签），所有网页通配的写法。
        let host_bare_wildcard = is_bare_host_wildcard(host_text);
        let host = if host_bare_wildcard {
            // 至少要有一个标签（`a.b.c.test` 与单标签内网名 `intranet` 都算）。
            vec![Group::Cross { min: 1 }]
        } else {
            compile_groups(host_text, '.', true, 0)?
        };
        if host.is_empty() {
            return Err(CompileError::EmptyHost);
        }
        // 路径段在整条模式里的字节起点：`/` + host 文本长度。
        let path_base = host_text.len() + 1;
        let mut path = compile_groups(path_text, '/', false, path_base)?;
        if let Some((min, max)) = tail_count {
            // `example.com/{1}` 这种「只有段数限定」的写法是合法的：
            // 限定直接作用于剩余段数，段内容不作要求。
            path.push(Group::Count { min, max });
        }

        let literals = literal_chars(&host) + literal_chars(&path);
        let wildcards = wildcard_count(&host) + wildcard_count(&path);
        let cross = cross_count(&host) + cross_count(&path);
        // 「所有网页」= 主机是裸通配 + 没有任何字面量锚点 + 路径未写或整体是 `**`。
        // `*/*` 只覆盖单段路径、`*.example.com` 有域锚点，都不算兜底（规格 §2.4）。
        let path_unbounded = path_text.is_empty() && tail_count.is_none();
        let all_pages =
            host_bare_wildcard && literals == 0 && (path_unbounded || is_single_cross(&path));
        let normalized = format!("{host_text}/{path_text}");
        Ok(Pattern {
            text: pattern.to_string(),
            normalized,
            host,
            path,
            host_bare_wildcard,
            all_pages,
            literals,
            wildcards,
            cross,
        })
    }

    /// 规则原文（规格 §1 冻结字段名 `url_pattern`）。
    #[must_use]
    pub fn url_pattern(&self) -> &str {
        &self.text
    }

    /// 模式原文。与 [`Pattern::url_pattern`] 同值，保留给审计原因与同精度 tie-break。
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// 模式侧的归一化比较面形态：与 [`NormalizedUrl::as_str`] 同一套写法（空路径补 `/`）。
    /// 规格 §2.5 要求模式侧与 URL 侧共用同一套归一化，不存在「模式宽松、URL 严格」。
    #[must_use]
    pub fn normalized_form(&self) -> &str {
        &self.normalized
    }

    /// 是否「所有网页」通配（规格 §2.4：白名单与黑名单各自覆盖的兜底模式）。
    #[must_use]
    pub fn is_all_pages(&self) -> bool {
        self.all_pages
    }

    /// 是否纯字面量模式（无任何通配单元）：匹配只走逐字节比较，零回溯。
    #[must_use]
    pub fn is_literal(&self) -> bool {
        self.wildcards == 0
    }

    /// 通配单元数量（`*`/`?`/`**`/`{..}` 各计一个单元）。
    #[must_use]
    pub fn wildcards(&self) -> usize {
        self.wildcards
    }

    /// 跨段通配（`**`）数量。
    #[must_use]
    pub fn cross_wildcards(&self) -> usize {
        self.cross
    }

    /// 字面量字符总数：同精度规则之间「字面锚点更长者优先」的度量（规格 §2.4）。
    #[must_use]
    pub fn literal_len(&self) -> usize {
        self.literals
    }

    /// 精确度分级，即冻结的「精确规则 > 通配规则」优先级（规格 §2.4）。
    #[must_use]
    pub fn specificity(&self) -> Specificity {
        if self.all_pages {
            Specificity::AllPages
        } else if self.host_has_wildcard() {
            Specificity::HostWildcard
        } else if self.wildcards > 0 {
            Specificity::HostAnchored
        } else {
            Specificity::Exact
        }
    }

    /// 主机部分是否含通配（含「任意主机」的裸写法）。
    fn host_has_wildcard(&self) -> bool {
        self.host_bare_wildcard || wildcard_count(&self.host) > 0
    }

    /// 判定归一化后的 URL 是否命中本模式。匹配期只借用输入，零分配。
    #[must_use]
    pub fn is_match(&self, url: &NormalizedUrl) -> bool {
        // 兜底模式覆盖一切，无需再逐段比较。
        if self.all_pages {
            return true;
        }
        // 字面主机模式要求 host 形状可用（防御性检查，归一化已保证）。
        if !self.host_bare_wildcard && !host_shape_ok(url.authority()) {
            return false;
        }
        if !super::engine::match_groups(&self.host, &self.text, url.authority(), '.') {
            return false;
        }
        super::engine::match_groups(&self.path, &self.text, url.path(), '/')
    }

    /// 命中时返回 URL 的路径片段（借用自输入的归一化文本，以 `/` 开头）；未命中 `None`。
    ///
    /// 上层用它写审计原因（`matched_rule` + 命中片段），因此只给出「确凿命中」的结果，
    /// 不给「近似命中」留解释空间。
    #[must_use]
    pub fn matched_path<'a>(&self, url: &'a NormalizedUrl) -> Option<&'a str> {
        if self.is_match(url) {
            Some(url.path_slice())
        } else {
            None
        }
    }
}

/// 模式里是否写了 scheme：比较面不含 scheme，检测到即视为配置缺陷。
fn scheme_of_pattern(pattern: &str) -> Option<&str> {
    if let Some(idx) = pattern.find("://") {
        return Some(&pattern[..idx]);
    }
    // `example.com:8443/a` 的 `:` 属于端口，`[::1]:8443/a` 的属于 IPv6 字面量；
    // 冒号后是一串数字 ⇒ 端口，其余「像 scheme 的字母前缀」按 scheme 处理。
    let idx = pattern.find(':')?;
    let candidate = &pattern[..idx];
    let remainder = &pattern[idx + 1..];
    let looks_like_scheme = !candidate.is_empty()
        && !remainder.chars().next().is_some_and(|c| c.is_ascii_digit())
        && candidate
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && candidate.chars().all(|c| c.is_ascii_alphabetic());
    if looks_like_scheme {
        Some(candidate)
    } else {
        None
    }
}

/// 校验 `%` 转义合法（`%` 后必须两位十六进制），不解码。
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

/// 在第一个 `/` 处切分 host 与 path。
fn split_host_path(text: &str) -> (&str, &str) {
    match text.find('/') {
        Some(idx) => text.split_at(idx),
        None => (text, ""),
    }
}

/// host 形状检查：非空且无空标签（归一化已保证，这里作为匹配前的防御位）。
fn host_shape_ok(host: &str) -> bool {
    !host.is_empty() && !host.contains("..")
}
