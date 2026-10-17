//! 段级/段内匹配器：递归 + 访问位图保证终止（组数与段数都有显式上限）。
//!
//! 匹配期只借用模式文本与输入文本，不分配堆内存（规格 §2.5）：
//! [`Token::Lit`] 记的是模式文本的字节区间，输入侧按同长度做字节比较即可。

use super::lex::{Group, Token};

/// 按分隔符切段后逐组匹配。`pattern` 是整条模式文本（字面量 token 的取值来源）。
pub(crate) fn match_groups(groups: &[Group], pattern: &str, text: &str, sep: char) -> bool {
    let mut pieces: Vec<&str> = Vec::new();
    if sep == '/' {
        // 路径去掉前导 `/` 后切段；`/` 本身切成空列表（即「只覆盖站点根」）。
        let trimmed = text.strip_prefix('/').unwrap_or(text);
        if !trimmed.is_empty() {
            pieces.extend(trimmed.split('/'));
        }
    } else {
        pieces.extend(text.split('.'));
    }
    let mut seen = vec![false; (groups.len() + 1) * (pieces.len() + 1)];
    match_from(groups, pattern, &pieces, 0, 0, &mut seen)
}

fn match_from(
    groups: &[Group],
    pattern: &str,
    pieces: &[&str],
    gi: usize,
    pi: usize,
    seen: &mut [bool],
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
            match_tokens(tokens, pattern, piece)
                && match_from(groups, pattern, pieces, gi + 1, pi + 1, seen)
        }
        Group::Cross { min } => {
            // `**`：吃掉 `min..` 段，段内容不作要求。
            for taken in *min..=(pieces.len() - pi) {
                if match_from(groups, pattern, pieces, gi + 1, pi + taken, seen) {
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
fn match_tokens(tokens: &[Token], pattern: &str, text: &str) -> bool {
    let mut seen = vec![false; tokens.len() * (text.len() + 1) + 1];
    match_token_from(tokens, pattern, text, 0, 0, &mut seen)
}

fn match_token_from(
    tokens: &[Token],
    pattern: &str,
    text: &str,
    ti: usize,
    ci: usize,
    seen: &mut [bool],
) -> bool {
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
            // 字面量取自模式文本的字节区间（编译期保证落在同一段内），
            // 输入侧只做同长度字节比较，因此匹配期不再解析模式。
            let Some(lit) = pattern.as_bytes().get(start..end) else {
                return false;
            };
            text.as_bytes().get(ci..ci + lit.len()) == Some(lit)
                && match_token_from(tokens, pattern, text, ti + 1, ci + lit.len(), seen)
        }
        // `?`：恰好一个字符（按 char 推进，多字节字符算一个）。
        Token::One => {
            let rest = &text[ci..];
            match rest.chars().next() {
                Some(ch) => {
                    match_token_from(tokens, pattern, text, ti + 1, ci + ch.len_utf8(), seen)
                }
                None => false,
            }
        }
        // `*`：至少一个字符，不跨分隔符（切段已保证）。
        Token::Star => {
            let mut consumed = 1usize;
            while ci + consumed <= text.len() {
                if match_token_from(tokens, pattern, text, ti + 1, ci + consumed, seen) {
                    return true;
                }
                consumed += 1;
            }
            false
        }
    }
}
