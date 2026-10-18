//! 绝对路径 ↔ 锚定显示路径的双向换算：模型只见锚定路径，真实绝对路径不出工具层。
//!
//! 锚定路径把 workspace 显示成固定前缀 [`ANCHOR_PREFIX`]（`/workspace`），其下的文件即
//! `/workspace/子路径`。约定只影响**展示与入参写法**，不改变安全闸：锚定路径同样不允许
//! `..` 穿越，指向 workspace 之外的真实绝对路径一律 `Denied`。
use std::path::{Path, PathBuf};

/// 锚定路径前缀：workspace 在模型侧统一显示为它。
pub const ANCHOR_PREFIX: &str = "/workspace";

/// workspace 内的相对路径 → 锚定显示路径（`/workspace/子路径`）；相对路径为空时返回前缀本身。
///
/// 分隔符统一成 `/`，Windows 下也不会漏出 `\`。
pub fn anchor_from_relative(relative: &Path) -> String {
    if relative.as_os_str().is_empty() || relative == Path::new(".") {
        return ANCHOR_PREFIX.to_string();
    }
    let text = relative.to_string_lossy().replace('\\', "/");
    format!("{ANCHOR_PREFIX}/{text}")
}

/// 真实绝对路径 → 锚定显示路径。`absolute` 不在 `workspace` 之下时返回 `None`（本就不该展示）。
pub fn anchor_display(absolute: &Path, workspace: &Path) -> Option<String> {
    let relative = absolute.strip_prefix(workspace).ok()?;
    Some(anchor_from_relative(relative))
}

/// 锚定显示路径 → workspace 内的相对路径。非锚定写法返回 `None`。
///
/// `/workspace` 本身映射为空路径（即 workspace 根）；`/workspace/../x` 保留 `..` 交给安全闸拒绝。
pub fn anchor_to_relative(anchored: &str) -> Option<PathBuf> {
    if anchored == ANCHOR_PREFIX {
        return Some(PathBuf::new());
    }
    let rest = anchored.strip_prefix(ANCHOR_PREFIX)?.strip_prefix('/')?;
    Some(PathBuf::from(rest))
}

/// 是否形似锚定路径（以 `/workspace` 开头）：用于给越权错误补一句『只接受锚定路径』的提示。
pub(crate) fn looks_anchored(p: &str) -> bool {
    p == ANCHOR_PREFIX || p.starts_with(&format!("{ANCHOR_PREFIX}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_from_relative_uses_forward_slashes() {
        assert_eq!(anchor_from_relative(Path::new("a/b.txt")), "/workspace/a/b.txt");
        // 空相对路径 = workspace 根本身
        assert_eq!(anchor_from_relative(Path::new("")), "/workspace");
        assert_eq!(anchor_from_relative(Path::new(".")), "/workspace");
    }

    #[test]
    fn anchor_display_only_for_paths_inside_workspace() {
        let workspace = Path::new("/tmp/ws-check");
        assert_eq!(
            anchor_display(Path::new("/tmp/ws-check/sub/f.txt"), workspace).as_deref(),
            Some("/workspace/sub/f.txt")
        );
        assert_eq!(anchor_display(workspace, workspace).as_deref(), Some("/workspace"));
        assert_eq!(anchor_display(Path::new("/etc/passwd"), workspace), None);
    }

    #[test]
    fn anchor_to_relative_round_trips_with_anchor_from_relative() {
        for rel in ["a/b.txt", "中文/档.md", "a"] {
            let anchored = anchor_from_relative(Path::new(rel));
            assert_eq!(anchor_to_relative(&anchored), Some(PathBuf::from(rel)));
        }
        assert_eq!(anchor_to_relative("/workspace"), Some(PathBuf::new()));
    }

    #[test]
    fn anchor_to_relative_rejects_non_anchored_and_prefix_lookalikes() {
        assert_eq!(anchor_to_relative("a/b.txt"), None);
        assert_eq!(anchor_to_relative("/workspacex/a"), None);
        assert_eq!(anchor_to_relative("/etc/passwd"), None);
        // 反斜杠写法不算锚定路径（模型侧只见 `/`）
        assert_eq!(anchor_to_relative("/workspace\\a"), None);
        assert!(looks_anchored("/workspace/a"));
        assert!(looks_anchored("/workspace"));
        assert!(!looks_anchored("/workspacee/a"));
    }
}
