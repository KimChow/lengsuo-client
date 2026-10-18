//! 纯逻辑匹配器：glob（分段，`*`/`?`/`**`）与前缀。零平台依赖。
//!
//! glob 语义（与规则文件文档一致）：
//! - 模式与目标都按 `/` 分段后逐段比较；
//! - 段内 `*` 匹配任意字符序列（不含 `/`），`?` 匹配一个字符（不含 `/`）；
//! - 独立段 `**` 跨段匹配：中间位置匹配零或多段；
//!   位于模式末尾的独立 `**` 匹配「其下至少一段」（gitignore 式边界：
//!   `.ssh/**` 命中 `.ssh/a`，不命中 `.ssh` 本身）。
//! - 无正则元字符转义需求：其它字符一律字面比较。

use crate::types::Matcher;

/// 按匹配器解释 pattern 并判断是否命中 target。
pub fn matches(matcher: Matcher, pattern: &str, target: &str) -> bool {
    match matcher {
        Matcher::Prefix => target.starts_with(pattern),
        Matcher::Glob => {
            let psegs: Vec<&str> = pattern.split('/').collect();
            let tsegs: Vec<&str> = target.split('/').collect();
            glob_match_segments(&psegs, &tsegs)
        }
    }
}

/// 段级 glob：psegs 是否完整匹配 tsegs。
fn glob_match_segments(psegs: &[&str], tsegs: &[&str]) -> bool {
    let Some((&head, rest)) = psegs.split_first() else {
        return tsegs.is_empty();
    };
    if head == "**" {
        // 末尾独立 `**`：匹配其下至少一段。
        if rest.is_empty() {
            return !tsegs.is_empty();
        }
        // 中间 `**`：吞掉零到全部前导目标段，其余递归。
        for skip in 0..=tsegs.len() {
            if glob_match_segments(rest, &tsegs[skip..]) {
                return true;
            }
        }
        return false;
    }
    let Some((&tseg, trec)) = tsegs.split_first() else {
        return false;
    };
    glob_match_segment(head, tseg) && glob_match_segments(rest, trec)
}

/// 段内字符级 glob：`*` 任意串、`?` 单字符、其余字面。迭代式回溯。
fn glob_match_segment(pattern: &str, seg: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = seg.chars().collect();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_p, mut star_s) = (usize::MAX, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = pi;
            star_s = si;
            pi += 1;
        } else if star_p != usize::MAX {
            // 回溯：让上一个 `*` 多吞一个字符。
            pi = star_p + 1;
            star_s += 1;
            si = star_s;
        } else {
            return false;
        }
    }
    // 剩余模式串若全为 `*` 则可匹配空尾。
    p[pi..].iter().all(|&c| c == '*')
}
