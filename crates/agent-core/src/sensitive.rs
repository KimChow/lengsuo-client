//! 敏感动作规则表（开工说明 §4：敏感动作强制 ask，不可配置跳过）。
//!
//! 实现：把命令文本按 shell 连接符切段，每段解析头部命令（跳过 `sudo`/`env`/
//! `VAR=value` 包装，并对 `sh -c '<cmd>'` 递归判定），再用规则表匹配。
//! 引号内的普通参数先做遮蔽，避免 `echo 'do not rm -rf stuff'` 误判。
//! 规则表内置且不可关闭：权限门在 auto 命中之后仍会检查一次。

use regex::Regex;
use std::sync::OnceLock;

/// 敏感动作规则集。
#[derive(Debug, Clone, Copy, Default)]
pub struct SensitiveRules {
    _priv: (),
}

impl SensitiveRules {
    /// v0 规则集（`rm -rf`/强推/格式化/覆写/远程执行/fork 炸弹等）。
    pub fn v0() -> Self {
        Self { _priv: () }
    }

    /// 文本是否命中敏感动作。
    pub fn matches(&self, text: &str) -> bool {
        self.match_reason(text).is_some()
    }

    /// 命中的规则名（供审批事件展示；不回显参数原文）。
    pub fn match_reason(&self, text: &str) -> Option<String> {
        let rules = rules();
        if rules.fork_bomb.is_match(text) {
            return Some("fork-bomb".to_string());
        }
        for piece in pieces(text) {
            let Some(name) = rules.reason_for_piece(&piece) else {
                continue;
            };
            return Some(name);
        }
        // 管道/链式远程执行：curl|wget 之后接解释器
        if rules.piped_remote.is_match(text) {
            return Some("remote-script-exec".to_string());
        }
        None
    }
}

struct Rules {
    rm_force_recursive: Regex,
    git_force_push: Regex,
    disk_wipe: Regex,
    dd_to_device: Regex,
    truncate_zero: Regex,
    find_delete: Regex,
    recursive_wide_perms: Regex,
    bare_overwrite: Regex,
    interpreter: Regex,
    piped_remote: Regex,
    fork_bomb: Regex,
    wrapper: Regex,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| Rules {
        rm_force_recursive: re(r"(?i)^\brm\b[^\n]*?(?:\s-\w*[rf]\w*|\s--(?:force|recursive)|--no-preserve-root)"),
        git_force_push: re(r"(?i)^\bgit\b[^\n]*?\bpush\b[^\n]*?(?:\s-f\b|\s--force)"),
        disk_wipe: re(r"(?i)^(?:mkfs(?:\.\w+)?|fdisk|sfdisk|wipefs|shred|format)\b"),
        dd_to_device: re(r"(?i)^\bdd\b[^\n]*?\sof="),
        truncate_zero: re(r"(?i)^\btruncate\b[^\n]*?\s-s\s*0\b"),
        find_delete: re(r"(?i)^\bfind\b[^\n]*?(?:\s-delete\b|\s-exec\s+rm\b)"),
        recursive_wide_perms: re(r"(?i)^\b(?:chmod|chown|chgrp)\b[^\n]*?\s-\w*r\w*[^\n]*?(?:\s[0-7]{3}\b|\s/(?:\s|$))"),
        bare_overwrite: re(r"(?i)^>{1,2}\s*\S"),
        interpreter: re(r"(?i)^(?:/?\S*/)?(?:sh|bash|zsh|dash|python3?|perl|node)\b"),
        piped_remote: re(r"(?i)(?:curl|wget)[^\n]*?(?:\|\s*(?:/?\S*/)?(?:sh|bash|zsh|dash|python3?|perl|node)|&&\s*(?:/?\S*/)?(?:sh|bash|zsh|dash|python3?|perl|node)\b)"),
        fork_bomb: re(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&"),
        wrapper: re(r"(?i)^(?:sudo|env|doas|time|nice|nohup|command|xargs)\b"),
    })
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("敏感动作正则必须可编译")
}

impl Rules {
    fn reason_for_piece(&self, piece: &str) -> Option<String> {
        let trimmed = piece.trim_start();
        // 纯覆写重定向（`> file`）先判：无头部命令
        if self.bare_overwrite.is_match(trimmed) {
            return Some("overwrite-redirect".to_string());
        }
        let masked = mask_quotes(trimmed);
        // 从头部命令起算（跳过 sudo/env/VAR= 包装）
        let from_head = head_command(&masked);
        let command = from_head.split(char::is_whitespace).next().unwrap_or("");
        if command.is_empty() {
            return None;
        }
        // 解释器 -c 包裹：递归判定内层命令（用未遮蔽原文）
        if self.interpreter.is_match(command) {
            if let Some(inner) = quoted_after_dash_c(trimmed) {
                if let Some(reason) = SensitiveRules::v0().match_reason(&inner) {
                    return Some(format!("nested:{reason}"));
                }
            }
        }
        for (name, pattern) in [
            ("rm-force-recursive", &self.rm_force_recursive),
            ("git-force-push", &self.git_force_push),
            ("disk-wipe", &self.disk_wipe),
            ("dd-to-device", &self.dd_to_device),
            ("truncate-zero", &self.truncate_zero),
            ("find-delete", &self.find_delete),
            ("recursive-wide-perms", &self.recursive_wide_perms),
        ] {
            if pattern.is_match(from_head) {
                return Some(name.to_string());
            }
        }
        None
    }
}

/// 按 shell 连接符切段（`&&`、`||`、`;`、`|`、换行）。
fn pieces(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
                current.push(c);
                i += 1;
                continue;
            }
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                current.push(c);
                i += 1;
                continue;
            }
            None => {}
        }
        let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
        if two == "&&" || two == "||" {
            out.push(std::mem::take(&mut current));
            i += 2;
            continue;
        }
        if c == ';' || c == '|' || c == '\n' || c == '&' {
            out.push(std::mem::take(&mut current));
            i += 1;
            continue;
        }
        current.push(c);
        i += 1;
    }
    out.push(current);
    out.into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// 遮蔽引号内容，避免把散文里的危险词当成命令。
fn mask_quotes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    for c in text.chars() {
        match quote {
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                out.push(c);
            }
            Some(q) => {
                if c == q {
                    quote = None;
                    out.push(c);
                } else {
                    out.push('x');
                }
            }
            None => out.push(c),
        }
    }
    out
}

/// 取从头部命令开始的子串（跳过 `sudo`/`env`/`VAR=value`/前导 flag 包装）。
///
/// 返回切片而非首个 token：规则表需要连同参数一起匹配（`rm -rf`、`git push --force`），
/// 只返回头部命令会让所有带参规则失效。
fn head_command(piece: &str) -> &str {
    let mut rest = piece;
    loop {
        let trimmed = rest.trim_start();
        let Some((token, tail)) = trimmed.split_once(char::is_whitespace) else {
            return trimmed;
        };
        let is_wrapper =
            rules().wrapper.is_match(token) || token.contains('=') || token.starts_with('-');
        if !is_wrapper || tail.trim_start().is_empty() {
            return trimmed;
        }
        rest = tail;
    }
}

/// 提取 `sh -c '<inner>'` / `bash -c "<inner>"` 的内层命令。
fn quoted_after_dash_c(piece: &str) -> Option<String> {
    let idx = piece.find("-c")?;
    let tail = &piece[idx + 2..];
    let quote = tail.chars().find(|c| *c == '\'' || *c == '"')?;
    let start = tail.find(quote)? + 1;
    let end = tail[start..].find(quote)? + start;
    Some(tail[start..end].to_string())
}
