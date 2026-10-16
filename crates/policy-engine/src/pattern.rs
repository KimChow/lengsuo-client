//! URL 归一化与通配符模式编译（规格 §2.5「URL 匹配」）。
//!
//! 本 crate 冻结的匹配语言（刻意不引入正则依赖：**编译一次，匹配期只借用输入**）：
//!
//! - 比较面只有 **host + path**：`scheme` 归一化后丢弃（缺省 `https`），
//!   `query`/`fragment` 剥离，userinfo 直接拒绝——追加 `?x=` 无法逃逸黑名单。
//! - 按分隔符切段后逐段匹配：host 以 `.` 切分，path 以 `/` 切分。
//! - `*` 段内通配：不跨分隔符、至少吃掉一个字符。例外：整个 host 部分只写 `*`
//!   时按「任意主机」处理（可跨标签），这是「所有网页」通配的写法。
//! - `**` 跨段通配：必须独占一段，禁止 `a**b` 混合写法；host 上至少一个标签，
//!   path 上允许零段。
//! - `?` 段内单字符；`{n}` / `{n..m}` / `{n..}` 只允许出现在模式尾部，限定剩余段数。
//! - 其余字符一律字面量（没有转义语言）；大小写敏感。
//! - 百分号转义只校验合法性，不解码（`%2F` 永远不等于 `/`）。
//!
//! 资源上限（全部显式、可预期，失败即拒绝，不做静默宽松解析）：
//! 模式长度 ≤ [`MAX_PATTERN_LEN`]，段数 ≤ [`MAX_SEGMENTS`]，
//! URL 长度 ≤ [`MAX_URL_LEN`]，单段长度 ≤ [`MAX_SEGMENT_LEN`]。

/// 模式文本长度上限（字节）。
pub const MAX_PATTERN_LEN: usize = 1024;
/// 单条模式的最大段数（host + path 各自计）。
pub const MAX_SEGMENTS: usize = 64;
/// 待匹配 URL 文本长度上限（字节）。
pub const MAX_URL_LEN: usize = 4096;
/// 单段（标签或路径段）最大字节数。
pub const MAX_SEGMENT_LEN: usize = 255;
/// 尾部段数限定的最大上界；`{n..}` 缺省上界取此值。
pub const MAX_SEGMENT_COUNT: usize = 64;

/// 模式编译或 URL 归一化的失败原因。全部 fail-closed：调用方不得回退到任何默认模式。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// 模式或 URL 为空文本。
    #[error("模式或 URL 为空")]
    Empty,
    /// 文本超过长度上限。
    #[error("长度 {0} 超过上限 {1}")]
    TooLong(usize, usize),
    /// 段数超过上限。
    #[error("段数 {0} 超过上限 {1}")]
    TooManySegments(usize, usize),
    /// 单段超过长度上限。
    #[error("段 {0:?} 长度超过上限 {MAX_SEGMENT_LEN}")]
    SegmentTooLong(String),
    /// 只有 `*` / `**` / `?` / 尾部 `{..}` 能独占一段；其余必须含字面量。
    #[error("段 {0:?} 只有通配符，缺少字面量")]
    EmptySegment(String),
    /// `?` 与 `*` 之后必须紧跟字面量。
    #[error("通配符后面缺少字面量")]
    TrailingWildcard,
    /// `**` 必须独占一段。
    #[error("`**` 必须独占一段，不接受 {0:?} 这类混合写法")]
    MixedDoubleStar(String),
    /// `{..}` 只能出现在模式最末尾。
    #[error("段数限定 `{0}` 只能出现在模式尾部")]
    CountNotAtEnd(String),
    /// `{..}` 写法非法（空、非数字、缺字面量前缀）。
    #[error("段数限定 `{0}` 写法非法")]
    BadCount(String),
    /// `{n..m}` 中 m 小于 n。
    #[error("段数限定区间反向：{0}..{1}")]
    ReversedCount(usize, usize),
    /// 段数限定超过上限。
    #[error("段数限定 {0} 超过上限 {MAX_SEGMENT_COUNT}")]
    CountTooLarge(usize),
    /// 段数限定前面必须至少有一个通配段（否则它无法生效）。
    #[error("段数限定 `{0}` 前面没有通配段")]
    CountWithoutWildcard(String),
    /// 段数限定不能跨 host（写在 host 段或 host/path 的分界上）。
    #[error("段数限定只能作用于路径")]
    CountOnHost,
    /// scheme 不是 http/https，或写法残缺。
    #[error("URL 的 scheme {0:?} 不是 http/https")]
    BadScheme(String),
    /// host 为空。
    #[error("URL 或模式缺少主机名")]
    EmptyHost,
    /// host 含空白字符（不做「去掉空白继续跑」的宽松修复）。
    #[error("主机名含空白字符")]
    HostHasWhitespace,
    /// host 含非法字符。
    #[error("主机名字符非法：{0:?}")]
    BadHostChar(char),
    /// host 出现空标签（`a..b`、`.a`、`a.`）。
    #[error("主机名标签为空")]
    EmptyLabel,
    /// 百分号转义不合法（只校验，不解码）。
    #[error("百分号转义不合法：{0:?}")]
    BadPercentEscape(String),
    /// 控制字符或 DEL 出现在 URL 中。
    #[error("URL 含控制字符 U+{0:04X}")]
    ControlChar(u32),
    /// userinfo（`user@host`）没有比较落点，出现即拒绝。
    #[error("URL 不允许包含 userinfo")]
    UserInfo,
    /// IPv6 字面量写法非法。
    #[error("IPv6 字面量写法非法：{0:?}")]
    BadIpv6Literal(String),
}

/// 段内 token：字面量切片（借用模式文本）或段内通配符。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    /// 模式文本切片 `[start, end)`，逐字节字面比较。
    Lit(usize, usize),
    /// `*`：本段内至少一个字符，不跨分隔符。
    Star,
    /// `?`：本段内恰好一个字符。
    One,
}

/// 段级 token：切段之后的匹配单元。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Group {
    /// 恰好一段：段内 token 序列。
    Segment(Vec<Token>),
    /// 独占一段的 `**`（或「整个 host 只写 `*`」）：跨段通配，至少 [`min`] 段。
    Cross { min: usize },
    /// 尾部段数限定：剩余段数落在 `[min, max]`，段内容不作要求。
    Count { min: usize, max: usize },
}

/// 已编译的通配符模式。编译一次，多次匹配；匹配期只借用输入，不分配堆内存。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    text: String,
    host: Vec<Group>,
    /// `None` 表示模式未写路径部分（等价于「任意路径」）。
    path: Option<Vec<Group>>,
    /// 主机部分是否为「保留通配」写法：`*`/`**` 独占整个 host。
    host_wildcard: bool,
    literals: usize,
    wildcard_segments: usize,
    fixed_path_segments: Option<usize>,
    anchored_root: bool,
    all_web: bool,
}

impl Pattern {
    /// 编译模式文本。任何不认识的写法一律 [`Err`]，绝不放宽成「匹配一切」。
    pub fn compile(pattern: &str) -> Result<Self, CompileError> {
        if pattern.is_empty() {
            return Err(CompileError::Empty);
        }
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(CompileError::TooLong(pattern.len(), MAX_PATTERN_LEN));
        }
        check_percent_escapes(pattern)?;

        let (body, tail_count) = split_tail_count(pattern)?;
        // 丢弃 scheme 与 `//`：模式与 URL 在同一比较面上对齐（host + path）。
        let body = strip_scheme(body)?;
        let (host_text, path_text) = split_host_path(body);
        // 模式写出的前导 `/` 只是分隔符；路径按段匹配，不作为字面量。
        let path_text = path_text.strip_prefix('/').unwrap_or(path_text);

        let mut host = compile_groups(host_text, '.', true)?;
        if host.is_empty() {
            return Err(CompileError::EmptyHost);
        }
        // 整个 host 只写 `*` 或 `**`：按「任意主机」处理，可跨标签。
        let host_wildcard = is_bare_star(&host);
        if host_wildcard {
            host = vec![Group::Cross { min: 1 }];
        }

        let path = if path_text.is_empty() && tail_count.is_none() {
            None
        } else {
            let mut groups = compile_groups(path_text, '/', false)?;
            if let Some((min, max)) = tail_count {
                if path_text.is_empty() {
                    return Err(CompileError::CountWithoutWildcard(tail_count_raw(pattern)));
                }
                if !groups.iter().any(matches_group_is_cross) {
                    return Err(CompileError::CountWithoutWildcard(tail_count_raw(pattern)));
                }
                groups.push(Group::Count { min, max });
            }
            Some(groups)
        };

        let mut compiled = Pattern {
            text: pattern.to_string(),
            host,
            path,
            host_wildcard,
            literals: 0,
            wildcard_segments: 0,
            fixed_path_segments: None,
            anchored_root: false,
            all_web: false,
        };
        compiled.analyze();
        Ok(compiled)
    }

    /// 模式原文（用于规则排序 tie-break 与审计原因）。
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// 是否只含通配符（`*`/`**`），即「所有网页」模式。
    #[must_use]
    pub fn is_all_web(&self) -> bool {
        self.all_web
    }

    /// 精确度度量，用于「精确规则 > 通配规则」的冻结优先级。
    #[must_use]
    pub fn specificity(&self) -> Specificity {
        Specificity {
            literals: self.literals,
            wildcard_segments: self.wildcard_segments,
            fixed_path_segments: self.fixed_path_segments,
            anchored_root: self.anchored_root,
        }
    }

    /// 判定归一化后的 URL 是否命中本模式。匹配期零分配。
    #[must_use]
    pub fn is_match(&self, url: &NormalizedUrl) -> bool {
        if !self.host_wildcard && !host_shape_ok(&url.host) {
            return false;
        }
        if !match_groups(&self.host, &url.host, '.') {
            return false;
        }
        match &self.path {
            // 模式未写路径 ⇒ 任意路径。
            None => true,
            Some(groups) => match_groups(groups, &url.path, '/'),
        }
    }

    /// 综合统计字面量与通配规模，供精确度比较与「所有网页」判定。
    fn analyze(&mut self) {
        let mut literals = 0usize;
        let mut wildcards = 0usize;
        let mut all_wild = true;
        for group in self.host.iter().chain(self.path.iter().flatten()) {
            match group {
                Group::Segment(tokens) => {
                    let mut group_has_wildcard = false;
                    for token in tokens {
                        match token {
                            Token::Lit(start, end) => literals += *end - *start,
                            Token::Star | Token::One => {
                                wildcards += 1;
                                group_has_wildcard = true;
                            }
                        }
                    }
                    if !group_has_wildcard {
                        // 纯字面段：必须逐字节相等才可能命中。
                    } else {
                        all_wild = false;
                    }
                }
                Group::Cross { .. } => wildcards += 1,
                Group::Count { .. } => wildcards += 1,
            }
        }
        // Segment 里既有字面量又有通配时，模式不是纯通配。
        for group in self.host.iter().chain(self.path.iter().flatten()) {
            if let Group::Segment(tokens) = group {
                if tokens.iter().any(|t| matches!(t, Token::Lit(..))) {
                    all_wild = false;
                }
            }
        }
        self.literals = literals;
        self.wildcard_segments = wildcards;
        self.anchored_root = self.path.is_none() && self.text.contains('/') == false
            || self.path.as_ref().is_some_and(|g| g.is_empty());
        self.fixed_path_segments = self.path.as_ref().and_then(|groups| {
            if groups
                .iter()
                .all(|g| matches!(g, Group::Segment(_)) && g_all_single(tokens_of(g)))
            {
                Some(groups.len())
            } else {
                None
            }
        });
        self.all_web = all_wild
            && self.host_wildcard
            && self.path.is_none()
                || self.all_web_parts();
    }

    /// 纯通配且覆盖任意主机与任意路径。
    fn all_web_parts(&self) -> bool {
        self.host_wildcard
            && self.path.as_ref().is_some_and(|groups| {
                groups.iter().all(|g| matches!(g, Group::Cross { .. } | Group::Segment(_) ))
                    && groups.iter().all(|g| match g {
                        Group::Cross { .. } => true,
                        Group::Segment(tokens) => {
                            tokens.len() == 1 && matches!(tokens[0], Token::Star)
                        }
                        Group::Count { .. } => false,
                    })
            })
    }
}

/// `Group::Segment` 的全部 token（辅助函数）。
fn tokens_of(group: &Group) -> &[Token] {
    match group {
        Group::Segment(tokens) => tokens,
        Group::Cross { .. } | Group::Count { .. } => &[],
    }
}

/// 段内只有一个 `*`（即恰好一段、内容任意）。
fn g_all_single(tokens: &[Token]) -> bool {
    tokens.len() == 1 && matches!(tokens[0], Token::Star)
}

/// 判断组是否为跨段通配。
fn matches_group_is_cross(group: &Group) -> bool {
    matches!(
        group,
        Group::Cross { .. } | Group::Segment(_)
    ) && match group {
        Group::Cross { .. } => true,
        Group::Segment(tokens) => g_all_single(tokens),
        Group::Count { .. } => false,
    }
}

/// 整个 host 部分只有 `*` 或 `**`。
fn is_bare_star(groups: &[Group]) -> bool {
    matches!(groups, [Group::Segment(tokens)] if g_all_single(tokens))
        || matches!(groups, [Group::Cross { .. }])
}

/// 精确度。`Ord` 的顺序即冻结的优先级：**精确规则 > 通配规则**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Specificity {
    /// 字面量字符总数（主要度量）。
    pub literals: usize,
    /// 通配单元数量（越少越精确，作为次级度量取反向比较）。
    pub wildcard_segments: usize,
    /// 固定段数的路径长度；`None` 表示含跨段通配或任意路径。
    pub fixed_path_segments: Option<usize>,
    /// 是否锚定到站点根（模式未写路径）。
    pub anchored_root: bool,
}

impl Ord for Specificity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.literals
            .cmp(&other.literals)
            .then_with(|| other.wildcard_segments.cmp(&self.wildcard_segments))
            .then_with(|| {
                self.fixed_path_segments
                    .unwrap_or(usize::MAX)
                    .cmp(&other.fixed_path_segments.unwrap_or(usize::MAX))
            })
            .then_with(|| other.anchored_root.cmp(&self.anchored_root))
    }
}

impl PartialOrd for Specificity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// 返回两条模式中更精确的一条；完全同精度返回 `None`（由调用方按规则序 tie-break）。
#[must_use]
pub fn more_specific<'a>(a: &'a Pattern, b: &'a Pattern) -> Option<&'a Pattern> {
    match a.specificity().cmp(&b.specificity()) {
        std::cmp::Ordering::Equal => None,
        std::cmp::Ordering::Greater => Some(a),
        std::cmp::Ordering::Less => Some(b),
    }
}

/// 归一化后的 URL：只保留 `host` 与 `path` 两个比较面。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedUrl {
    host: String,
    path: String,
    normalized: String,
}

impl NormalizedUrl {
    /// 归一化输入 URL。缺省补 `https://`；其余不合规写法一律拒绝。
    pub fn parse(raw: &str) -> Result<Self, CompileError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CompileError::Empty);
        }
        if trimmed.len() > MAX_URL_LEN {
            return Err(CompileError::TooLong(trimmed.len(), MAX_URL_LEN));
        }
        for ch in trimmed.chars() {
            if (ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t') || ch == '\u{7f}' {
                return Err(CompileError::ControlChar(ch as u32));
            }
        }
        check_percent_escapes(trimmed)?;

        // 1. scheme：缺省 https；大小写不敏感；非 http/https 拒绝。
        let rest = strip_scheme_url(trimmed)?;

        // 2. query / fragment 剥离。
        let without_tail = match rest.find(['?', '#']) {
            Some(idx) => &rest[..idx],
            None => rest,
        };
        if without_tail.is_empty() {
            return Err(CompileError::EmptyHost);
        }

        // 3. userinfo 拒绝。
        let host_end = match without_tail.find('/') {
            Some(idx) => idx,
            None => without_tail.len(),
        };
        let (host_part, path_part) = without_tail.split_at(host_end);
        if host_part.contains('@') {
            return Err(CompileError::UserInfo);
        }
        if host_part.contains(' ') || host_part.chars().any(char::is_whitespace) {
            return Err(CompileError::HostHasWhitespace);
        }

        // 4. host 校验（含端口与 IPv6 字面量）。
        let host = normalize_host(host_part)?;
        let path = if path_part.is_empty() {
            "/".to_string()
        } else {
            path_part.to_string()
        };
        let normalized = format!("{host}{path}");
        Ok(NormalizedUrl {
            host,
            path,
            normalized,
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

    /// 路径部分（始终以 `/` 开头，已剥离 query/fragment）。
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// 去掉 URL 的 scheme 与 `//`；缺省视为 https。
fn strip_scheme_url(raw: &str) -> Result<&str, CompileError> {
    match raw.find("://") {
        Some(idx) => {
            let scheme = &raw[..idx];
            check_scheme(scheme)?;
            Ok(&raw[idx + 3..])
        }
        None => {
            if let Some(after) = raw.strip_prefix("//") {
                return Ok(after);
            }
            if raw.contains(':') {
                // 形如 `ftp://x` 已被上面捕获；这里剩下 `javascript:alert(1)`。
                let scheme = raw.split(':').next().unwrap_or("");
                check_scheme(scheme)?;
            }
            if raw.contains('/') && !raw.starts_with('/') {
                // 相对写法：host/path，缺省 https。
                return Ok(raw);
            }
            Ok(raw)
        }
    }
}

fn check_scheme(scheme: &str) -> Result<(), CompileError> {
    let lowered = scheme.to_ascii_lowercase();
    if lowered != "https" && lowered != "http" {
        return Err(CompileError::BadScheme(scheme.to_string()));
    }
    Ok(())
}

/// 模式文本去掉可选 scheme 前缀。
fn strip_scheme(body: &str) -> Result<&str, CompileError> {
    if let Some(idx) = body.find("://") {
        check_scheme(&body[..idx])?;
        return Ok(&body[idx + 3..]);
    }
    if let Some(after) = body.strip_prefix("//") {
        return Ok(after);
    }
    if let Some(idx) = body.find(':') {
        // `example.com:8443/a` 的 `:` 属于端口，不是 scheme 分隔符；
        // 只有后面紧跟 `/` 或字母前缀像 scheme 时才按 scheme 处理。
        let candidate = &body[..idx];
        if !candidate.is_empty()
            && candidate.chars().all(|c| c.is_ascii_alphabetic())
            && idx + 1 < body.len()
            && body.as_bytes()[idx + 1] == b'/'
        {
            check_scheme(candidate)?;
            return Ok(&body[idx + 2..]);
        }
    }
    Ok(body)
}

/// 在第一个 `/` 处切分 host 与 path。
fn split_host_path(text: &str) -> (&str, &str) {
    match text.find('/') {
        Some(idx) => text.split_at(idx),
        None => (text, ""),
    }
}

/// 校验并原样保留 host（大小写敏感、端口与 IPv6 字面量保留）。
fn normalize_host(part: &str) -> Result<String, CompileError> {
    if part.is_empty() {
        return Err(CompileError::EmptyHost);
    }
    let (name, port) = if let Some(idx) = part.rfind(':') {
        if part.starts_with('[') {
            // IPv6 字面量：`]` 之后的 `:` 才是端口分隔符。
            let close = part.find(']').ok_or(CompileError::BadIpv6Literal(part.to_string()))?;
            (&part[..close + 1], &part[close + 1..])
        } else {
            part.split_at(idx)
        }
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
    // 域名：字母数字与 `-` 组成标签，标签非空。
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

/// host 形状检查：字面量模式要求 host 合法。
fn host_shape_ok(host: &str) -> bool {
    !host.is_empty()
}

/// 校验 `%` 转义合法（`%` 后必须两位十六进制），不解码。
fn check_percent_escapes(text: &str) -> Result<(), CompileError> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(CompileError::BadPercentEscape(text[i..].chars().take(4).collect()));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// 拆出尾部 `{..}` 段数限定，返回「去掉限定的正文」与 `(min, max)`。
fn split_tail_count(body: &str) -> Result<(&str, Option<(usize, usize)>), CompileError> {
    let Some(open) = body.rfind('{') else {
        return Ok((body, None));
    };
    if !body.ends_with('}') {
        return Err(CompileError::CountNotAtEnd(body[open..].to_string()));
    }
    let inner = &body[open + 1..body.len() - 1];
    if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(CompileError::BadCount(body[open..].to_string()));
    }
    let host_end = body.find('/').unwrap_or(body.len());
    if open < host_end {
        return Err(CompileError::CountOnHost);
    }
    let bounds = if let Some((lo, hi)) = inner.split_once("..") {
        (
            parse_count(lo, body, open)?,
            if hi.is_empty() {
                MAX_SEGMENT_COUNT
            } else {
                parse_count(hi, body, open)?
            },
        )
    } else {
        let n = parse_count(inner, body, open)?;
        (n, n)
    };
    if bounds.1 > MAX_SEGMENT_COUNT {
        return Err(CompileError::CountTooLarge(bounds.1));
    }
    if bounds.0 > bounds.1 {
        return Err(CompileError::ReversedCount(bounds.0, bounds.1));
    }
    Ok((&body[..open], Some(bounds)))
}

fn parse_count(text: &str, body: &str, open: usize) -> Result<usize, CompileError> {
    text.parse::<usize>()
        .map_err(|_| CompileError::BadCount(body[open..].to_string()))
}

/// `{..}` 的原文（用于错误信息）。
fn tail_count_raw(pattern: &str) -> String {
    match pattern.rfind('{') {
        Some(open) if pattern.ends_with('}') => pattern[open..].to_string(),
        _ => String::new(),
    }
}

/// 按分隔符切段并编译成 [`Group`] 序列。
fn compile_groups(text: &str, sep: char, is_host: bool) -> Result<Vec<Group>, CompileError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut groups = Vec::new();
    for piece in text.split(sep) {
        if piece.len() > MAX_SEGMENT_LEN {
            return Err(CompileError::SegmentTooLong(piece.to_string()));
        }
        if piece.is_empty() {
            return Err(CompileError::EmptySegment(text.to_string()));
        }
        if piece == "**" {
            groups.push(Group::Cross { min: 1 });
            continue;
        }
        if piece == "*" && !is_host {
            groups.push(Group::Segment(vec![Token::Star]));
            continue;
        }
        if piece.contains("**") {
            return Err(CompileError::MixedDoubleStar(piece.to_string()));
        }
        let tokens = compile_segment(piece)?;
        groups.push(Group::Segment(tokens));
        if groups.len() > MAX_SEGMENTS {
            return Err(CompileError::TooManySegments(groups.len(), MAX_SEGMENTS));
        }
    }
    Ok(groups)
}

/// 编译段内 token 序列。
fn compile_segment(piece: &str) -> Result<Vec<Token>, CompileError> {
    let mut tokens = Vec::new();
    let mut literal_start: Option<usize> = None;
    let mut index = 0usize;
    let mut pending_wildcard = false;
    for (offset, ch) in piece.char_indices() {
        match ch {
            '*' | '?' => {
                if let Some(start) = literal_start {
                    tokens.push(Token::Lit(start, offset));
                    literal_start = None;
                }
                tokens.push(if ch == '*' { Token::Star } else { Token::One });
                pending_wildcard = true;
                index = offset + ch.len_utf8();
            }
            _ => {
                if literal_start.is_none() {
                    literal_start = Some(index);
                }
                pending_wildcard = false;
                index = offset + ch.len_utf8();
            }
        }
    }
    if let Some(start) = literal_start {
        tokens.push(Token::Lit(start, piece.len()));
    } else if pending_wildcard {
        return Err(CompileError::TrailingWildcard);
    }
    if tokens.is_empty() {
        return Err(CompileError::EmptySegment(piece.to_string()));
    }
    Ok(tokens)
}

/// 段级匹配：递归 + 访问位图保证终止（组数与段数都有显式上限）。
fn match_groups(groups: &[Group], text: &str, sep: char) -> bool {
    let mut pieces: Vec<&str> = Vec::new();
    if sep == '/' {
        // 路径去掉前导 `/` 后切段；`/` 本身切成空列表。
        let trimmed = text.strip_prefix('/').unwrap_or(text);
        if !trimmed.is_empty() {
            pieces.extend(trimmed.split('/'));
        }
    } else {
        pieces.extend(text.split('.'));
    }
    let mut seen = vec![false; (groups.len() + 1) * (pieces.len() + 1)];
    match_from(groups, &pieces, 0, 0, &mut seen)
}

fn match_from(
    groups: &[Group],
    pieces: &[&str],
    gi: usize,
    pi: usize,
    seen: &mut Vec<bool>,
) -> bool {
    if gi >= groups.len() {
        return pi == pieces.len();
    }
    let key = gi * (pieces.len() + 1) + pi;
    if seen[key] {
        return false;
    }
    seen[key] = true;

    match &groups[gi] {
        Group::Segment(tokens) => {
            let Some(piece) = pieces.get(pi) else {
                return false;
            };
            match_tokens(tokens, piece) && match_from(groups, pieces, gi + 1, pi + 1, seen)
        }
        Group::Cross { min } => {
            for taken in *min..=(pieces.len() - pi) {
                if match_from(groups, pieces, gi + 1, pi + taken, seen) {
                    return true;
                }
            }
            false
        }
        Group::Count { min, max } => {
            let left = pieces.len() - pi;
            left >= *min && left <= *max
        }
    }
}

/// 段内匹配：`*` 至少一个字符，`?` 恰好一个字符，字面量逐字节相等。
fn match_tokens(tokens: &[Token], text: &str) -> bool {
    let mut seen = vec![false; tokens.len() * text.len() + 1];
    match_token_from(tokens, text, 0, 0, &mut seen)
}

fn match_token_from(tokens: &[Token], text: &str, ti: usize, ci: usize, seen: &mut [bool]) -> bool {
    if ti >= tokens.len() {
        return ci == text.len();
    }
    let key = ti * (text.len() + 1) + ci;
    if seen[key] {
        return false;
    }
    seen[key] = true;
    match tokens[ti] {
        Token::Lit(start, end) => {
            let lit = &text[start..end];
            // 字面量按字节切片对齐（token 的偏移来自同一段文本）。
            text.as_bytes().get(ci..ci + lit.len()) == Some(lit.as_bytes())
                && match_token_from(tokens, text, ti + 1, ci + lit.len(), seen)
        }
        Token::One => {
            let rest = &text[ci..];
            match rest.chars().next() {
                Some(ch) => match_token_from(tokens, text, ti + 1, ci + ch.len_utf8(), seen),
                None => false,
            }
        }
        Token::Star => {
            let mut consumed = 1usize;
            while ci + consumed <= text.len() {
                if match_token_from(tokens, text, ti + 1, ci + consumed, seen) {
                    return true;
                }
                consumed += 1;
            }
            false
        }
    }
}
