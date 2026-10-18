//! 搜索通道：`file:search`（文件名 glob，限量 + 总数）与 `file:glob`（路径模式）。
//!
//! `glob` crate 0.3 的 `**` 无跨目录递归语义，故路径模式用 `regex` 自行翻译：
//! `**` 跨 `/`，`*`/`?` 不跨 `/`。

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::error::ToolError;
use crate::types::SearchHit;

/// 单次遍历的上限，防止超大工作区把能力层打爆。
const MAX_SCAN_ENTRIES: usize = 50_000;

impl crate::FsToolbox {
    /// `file:search`：在 `root` 下递归按**文件名**匹配 glob，返回 `(前 limit 条, 总数)`。
    /// 文件名匹配用 `glob::Pattern`，不跨目录分隔符。
    pub fn search(
        &self,
        root: &str,
        pattern: &str,
        limit: usize,
    ) -> Result<(Vec<SearchHit>, usize), ToolError> {
        let root_abs = self.guard(Path::new(root))?;
        let meta = fs::metadata(&root_abs).map_err(|e| ToolError::from_io(root_abs.clone(), e))?;
        if !meta.is_dir() {
            return Err(ToolError::NotADirectory(root_abs));
        }
        let compiled = glob::Pattern::new(pattern)
            .map_err(|e| ToolError::other(root_abs.clone(), format!("glob 模式非法: {e}")))?;
        let mut hits: Vec<SearchHit> = Vec::new();
        for entry in self.walk(&root_abs)? {
            let name = entry
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !compiled.matches(&name) {
                continue;
            }
            hits.push(SearchHit {
                rel_path: self.rel_display(&entry.path),
                name,
                is_dir: entry.is_dir,
                size: entry.size,
            });
        }
        hits.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        let total = hits.len();
        if limit > 0 {
            hits.truncate(limit);
        } else {
            hits.clear();
        }
        Ok((hits, total))
    }

    /// `file:glob`：`root` 下递归匹配**路径**模式（`**` 跨目录），返回至多 `limit` 条相对路径。
    pub fn glob(&self, root: &str, pattern: &str, limit: usize) -> Result<Vec<String>, ToolError> {
        let root_abs = self.guard(Path::new(root))?;
        let meta = fs::metadata(&root_abs).map_err(|e| ToolError::from_io(root_abs.clone(), e))?;
        if !meta.is_dir() {
            return Err(ToolError::NotADirectory(root_abs));
        }
        let re = path_glob_regex(pattern)
            .map_err(|e| ToolError::other(root_abs.clone(), format!("glob 模式无法编译: {e}")))?;
        let base = self.rel_display(&root_abs);
        let mut out: Vec<String> = Vec::new();
        for entry in self.walk(&root_abs)? {
            let full = self.rel_display(&entry.path);
            // 模式针对 root 下的相对路径匹配，结果回传相对工作区路径（可直接喂 read）。
            let matched = full.strip_prefix(base.as_str()).unwrap_or(&full);
            let matched = matched.trim_start_matches('/');
            if re.is_match(matched) {
                out.push(full);
            }
        }
        out.sort();
        if limit > 0 {
            out.truncate(limit);
        } else {
            out.clear();
        }
        Ok(out)
    }

    /// 深度优先遍历工作区内子树；跳过符号链接避免环，条目数受 `MAX_SCAN_ENTRIES` 约束。
    pub(crate) fn walk(&self, root: &Path) -> Result<Vec<WalkEntry>, ToolError> {
        let mut out: Vec<WalkEntry> = Vec::new();
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let read = match fs::read_dir(&dir) {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
                Err(e) => return Err(ToolError::from_io(dir, e)),
            };
            for item in read {
                let item = item.map_err(|e| ToolError::from_io(dir.clone(), e))?;
                let path = item.path();
                let meta = match fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                let is_dir = meta.is_dir();
                out.push(WalkEntry {
                    path: path.clone(),
                    is_dir,
                    size: if is_dir { 0 } else { meta.len() },
                });
                if is_dir {
                    stack.push(path);
                }
                if out.len() >= MAX_SCAN_ENTRIES {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }
}

pub(crate) struct WalkEntry {
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
}

/// 路径 glob → 锚定正则。`**` 跨分隔符，`*`/`?` 不跨，`[...]` 透传（`!` 取反）。
fn path_glob_regex(pattern: &str) -> Result<Regex, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut re = String::from("^");
    let mut i = 0usize;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    // "**/" 或 "**"：跨目录；后面紧跟 '/' 时该分隔符一并吞掉并允许零层。
                    i += 2;
                    if i < chars.len() && chars[i] == '/' {
                        re.push_str("(?:.*/)?");
                        i += 1;
                    } else {
                        re.push_str(".*");
                    }
                } else {
                    re.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                re.push_str("[^/]");
                i += 1;
            }
            '[' => {
                // 没有闭合 `]` 视为非法模式（与 glob::Pattern 行为一致）。
                let Some(off) = chars[i + 1..].iter().position(|&c| c == ']') else {
                    return Err(format!("glob 模式未闭合字符类: {pattern}"));
                };
                let close = i + 1 + off;
                let body: String = chars[i + 1..close].iter().collect();
                let body = match body.strip_prefix('!') {
                    Some(rest) => format!("^{rest}"),
                    None => body,
                };
                re.push_str(&format!("[{}]", body.replace('\\', "\\\\")));
                i = close + 1;
            }
            c => {
                re.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    re.push('$');
    Regex::new(&re).map_err(|e| e.to_string())
}
