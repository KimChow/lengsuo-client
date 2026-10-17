//! 模式文本的切段与 token 编译（[`super::Pattern::compile`] 的前半程）。
//!
//! 全部失败都返回 [`CompileError`]，绝不放宽成「匹配一切」。
//! [`Token::Lit`] 记录的是**整条模式文本**的字节区间，因此切段时必须把该段在模式里的
//! 绝对起始偏移传进来——匹配期用同一份模式文本取字面量，才能既零分配又不错位。

use super::CompileError;
use super::{MAX_CROSS_WILDCARDS, MAX_SEGMENTS, MAX_SEGMENT_COUNT, MAX_SEGMENT_LEN};

/// 段内 token：字面量切片（借用整条模式文本）或段内通配符。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Token {
    /// 模式文本字节区间 `[start, end)`，逐字节字面比较。
    Lit(usize, usize),
    /// `*`：本段内至少一个字符，不跨分隔符。
    Star,
    /// `?`：本段内恰好一个字符。
    One,
}

/// 段级 token：切段之后的匹配单元。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Group {
    /// 恰好一段：段内 token 序列。
    Segment(Vec<Token>),
    /// 独占一段的 `**`（或「整个 host 只写 `*`/`**`」）：跨段通配，至少吃掉 [`min`] 段。
    Cross { min: usize },
    /// 尾部段数限定：剩余段数落在 `[min, max]`，段内容不作要求。
    Count { min: usize, max: usize },
}

/// 按分隔符切段并编译成 [`Group`] 序列。`base` 是 `text` 在整条模式里的字节偏移。
///
/// `is_host` 决定裸 `*` 的解释：host 区 `*` 只吃一个标签（与段内通配同一套 token），
/// path 区 `*` 吃一整段。跨段通配 `**` 在 host 区至少吃掉一个标签，在 path 区允许零段
/// （否则 `example.com/**` 无法覆盖站点根）。
pub(crate) fn compile_groups(
    text: &str,
    sep: char,
    is_host: bool,
    base: usize,
) -> Result<Vec<Group>, CompileError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut groups = Vec::new();
    let mut offset = base;
    let piece_count = text.split(sep).count();
    for (index, piece) in text.split(sep).enumerate() {
        if piece.len() > MAX_SEGMENT_LEN {
            return Err(CompileError::SegmentTooLong(piece.to_string()));
        }
        if piece.is_empty() {
            if is_host {
                // `a..b`、`.a`、`a.` 这类 host 写法没有比较落点。
                return Err(CompileError::EmptyLabel);
            }
            // 路径区只有**结尾**那一个空段是合法写法：`example.com/a/` 的尾部 `/`
            // 只是分隔符，与 URL 侧同形空段自然对上，不需要额外成段。
            if index + 1 == piece_count {
                offset += piece.len() + sep.len_utf8();
                continue;
            }
            // 连续 `//` 之类的中间空段：写法缺陷，拒绝。
            return Err(CompileError::EmptySegment(text.to_string()));
        }
        if piece.contains("**") && piece != "**" {
            return Err(CompileError::MixedDoubleStar(piece.to_string()));
        }
        if piece == "**" {
            groups.push(Group::Cross {
                min: usize::from(is_host),
            });
        } else if piece == "*" {
            // 整段通配：host 区吃一个标签，path 区吃一段，都至少一个字符。
            groups.push(Group::Segment(vec![Token::Star]));
        } else {
            groups.push(Group::Segment(compile_segment(piece, offset)?));
            if groups.len() > MAX_SEGMENTS {
                return Err(CompileError::TooManySegments {
                    count: groups.len(),
                    max: MAX_SEGMENTS,
                });
            }
        }
        offset += piece.len() + sep.len_utf8();
    }
    let cross = cross_count(&groups);
    if cross > MAX_CROSS_WILDCARDS {
        return Err(CompileError::TooManyCrossWildcards {
            count: cross,
            max: MAX_CROSS_WILDCARDS,
        });
    }
    Ok(groups)
}

/// 编译段内 token 序列。`*`/`?` 之后必须还有字面量，否则是悬空通配。
fn compile_segment(piece: &str, base: usize) -> Result<Vec<Token>, CompileError> {
    let mut tokens = Vec::new();
    let mut literal_start: Option<usize> = None;
    let mut pending_wildcard = false;
    for (offset, ch) in piece.char_indices() {
        let absolute = base + offset;
        match ch {
            '*' | '?' => {
                if let Some(start) = literal_start {
                    tokens.push(Token::Lit(start, absolute));
                    literal_start = None;
                }
                tokens.push(if ch == '*' { Token::Star } else { Token::One });
                pending_wildcard = true;
            }
            other => {
                if literal_start.is_none() {
                    literal_start = Some(absolute);
                }
                pending_wildcard = false;
                let _ = other;
            }
        }
    }
    if let Some(start) = literal_start {
        tokens.push(Token::Lit(start, base + piece.len()));
    } else if pending_wildcard {
        return Err(CompileError::TrailingWildcard);
    }
    if tokens.is_empty() {
        return Err(CompileError::EmptySegment(piece.to_string()));
    }
    Ok(tokens)
}

/// 通配单元数量（段内 `*`/`?` 与跨段 `**` 各计一个；`{..}` 也算一种通配能力）。
pub(crate) fn wildcard_count(groups: &[Group]) -> usize {
    groups
        .iter()
        .map(|group| match group {
            Group::Segment(tokens) => tokens
                .iter()
                .filter(|t| matches!(t, Token::Star | Token::One))
                .count(),
            Group::Cross { .. } | Group::Count { .. } => 1,
        })
        .sum()
}

/// 跨段通配（`**`）数量。
pub(crate) fn cross_count(groups: &[Group]) -> usize {
    groups
        .iter()
        .filter(|group| matches!(group, Group::Cross { .. }))
        .count()
}

/// 字面量字符总数：段 token 里切片长度之和（同级精度「锚点更长者优先」的度量）。
/// `{..}` 段数限定不写字面量，不计入锚点长度。
pub(crate) fn literal_chars(groups: &[Group]) -> usize {
    groups
        .iter()
        .map(|group| match group {
            Group::Segment(tokens) => tokens
                .iter()
                .map(|t| match t {
                    Token::Lit(start, end) => end - start,
                    Token::Star | Token::One => 0,
                })
                .sum::<usize>(),
            Group::Cross { .. } | Group::Count { .. } => 0,
        })
        .sum()
}

/// 主机部分是否写成「任意主机」：整个 host 只有 `*` 或 `**`。
pub(crate) fn is_bare_host_wildcard(text: &str) -> bool {
    text == "*" || text == "**"
}

/// 路径是否为单个跨段通配 `**`。
pub(crate) fn is_single_cross(groups: &[Group]) -> bool {
    matches!(groups, [Group::Cross { .. }])
}

/// 拆出尾部 `{..}` 段数限定，返回「去掉限定的正文」与 `(min, max)`。
///
pub(crate) type TailSplit<'a> = (&'a str, Option<(usize, usize)>);

/// 只有「紧跟 `/` 且内容含数字」的闭合花括号才是段数限定；其余写法（例如 `{a}`）
/// 一律按字面量处理，不做展开解释——这套通配语言里没有花括号转义。
pub(crate) fn split_tail_count(body: &str) -> Result<TailSplit<'_>, CompileError> {
    let Some(open) = body.rfind('{') else {
        return Ok((body, None));
    };
    // 路径段数限定不可能作用到 host：写在 host 段或 host/path 分界上即拒绝。
    let host_end = body.find('/').unwrap_or(body.len());
    if open < host_end {
        return Err(CompileError::CountOnHost);
    }
    // 花括号必须紧跟分隔符才是独立的一段；`ab{1}` 这类混写按字面量。
    if body.as_bytes().get(open.wrapping_sub(1)) != Some(&b'/') {
        return Ok((body, None));
    }
    let raw = &body[open..];
    if !body.ends_with('}') {
        // 未闭合：`example.com/{`、`example.com/{1` 都是写法错误。
        return Err(CompileError::CountNotAtEnd(raw.to_string()));
    }
    let inner = &body[open + 1..body.len() - 1];
    // 没有任何数字 ⇒ 字面量花括号（例如 `{a}`），不参与段数解释。
    if !inner.chars().any(|c| c.is_ascii_digit()) {
        return Ok((body, None));
    }
    if !inner.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(CompileError::BadCount(raw.to_string()));
    }
    let (min, max) = if let Some((lo, hi)) = inner.split_once("..") {
        let min = parse_count(lo, raw)?;
        if hi.is_empty() {
            // 开区间：`{0..}` 的上界缺省即隐式全通配（绕过精度排序），必须拒绝；
            // `{n..}`（n ≥ 1）按「至少 n 段、上界取显式上限」解释。
            if min == 0 {
                return Err(CompileError::UnboundedAllWildcard { min });
            }
            (min, MAX_SEGMENT_COUNT)
        } else {
            (min, parse_count(hi, raw)?)
        }
    } else {
        let n = parse_count(inner, raw)?;
        (n, n)
    };
    if max > MAX_SEGMENT_COUNT {
        return Err(CompileError::CountTooLarge {
            count: max,
            max: MAX_SEGMENT_COUNT,
        });
    }
    if min > max {
        return Err(CompileError::InvertedSegmentRange { min, max });
    }
    if min == 0 && max == 0 {
        // 模式的分隔符只是分段符，不存在「零段且非空」的路径写法：该模式无法命中。
        return Err(CompileError::EmptySegmentRange { min, max });
    }
    Ok((&body[..open], Some((min, max))))
}

fn parse_count(text: &str, raw: &str) -> Result<usize, CompileError> {
    text.parse::<usize>()
        .map_err(|_| CompileError::BadCount(raw.to_string()))
}
