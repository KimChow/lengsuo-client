//! 安全闸：workspace 词法前缀校验（`..` 拒绝、绝对路径逃逸拒绝）。
//!
//! v0 为纯词法校验，不解析符号链接，逃逸由 `FsToolbox::resolve` 二次校验兜底。

use std::path::{Component, Path, PathBuf};

use crate::error::ToolError;

impl crate::FsToolbox {
    /// 把调用方路径（相对工作区或工作区内绝对路径）解析为工作区内绝对路径。
    ///
    /// 任何 `..` 成分直接拒绝；解析结果必须以工作区为前缀，否则 `Denied`。
    pub(crate) fn guard(&self, p: &Path) -> Result<PathBuf, ToolError> {
        let candidate = if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.workspace.join(p)
        };
        if candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(ToolError::Denied(p.to_path_buf()));
        }
        let normalized = normalize(&candidate);
        if normalized.starts_with(&self.workspace) {
            Ok(normalized)
        } else {
            Err(ToolError::Denied(p.to_path_buf()))
        }
    }

    /// guard 结果的相对工作区展示路径（`/` 分隔）。
    pub(crate) fn rel_display(&self, abs: &Path) -> String {
        abs.strip_prefix(&self.workspace)
            .unwrap_or(abs)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

/// 逐成分解析符号链接后的词法规范化（v1 预留，v0 未接入 guard）。
///
/// 对 `p` 的每个前缀尝试 `canonicalize`：已存在的中间符号链接（含断链的**父目录**）
/// 被换成真实目标，不存在的尾段原样保留，最后再做一次词法规范化。
/// 已知边界：`p` 末段自身是断链时 `canonicalize` 失败，只能保留链接路径本身。
#[allow(dead_code)] // v0 未接入 guard：理由与后续启用见 result.md「已知限制」第 2 条
pub(crate) fn resolve_links(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(seg) => {
                out.push(seg);
                if let Ok(real) = out.canonicalize() {
                    out = real;
                }
            }
        }
    }
    normalize(&out)
}

/// 词法规范化：折叠 `.` 与重复分隔符，不触碰文件系统。
pub(crate) fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        if !matches!(c, Component::CurDir) {
            out.push(c.as_os_str());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::testutil::TempDir;

    use super::*;

    fn tb(workspace: &str) -> crate::FsToolbox {
        crate::FsToolbox::new(workspace)
    }

    #[test]
    fn guard_接受相对路径并折叠点段() {
        let t = tb("/tmp/ws");
        assert_eq!(
            t.guard(Path::new("a/b.txt")).unwrap(),
            PathBuf::from("/tmp/ws/a/b.txt")
        );
        assert_eq!(
            t.guard(Path::new("./a//b.txt")).unwrap(),
            PathBuf::from("/tmp/ws/a/b.txt")
        );
    }

    #[test]
    fn guard_拒绝穿越与工作区外绝对路径() {
        let t = tb("/tmp/ws");
        assert_eq!(
            t.guard(Path::new("../etc/passwd")),
            Err(ToolError::Denied(PathBuf::from("../etc/passwd")))
        );
        assert_eq!(
            t.guard(Path::new("a/../../b")),
            Err(ToolError::Denied(PathBuf::from("a/../../b")))
        );
        assert_eq!(
            t.guard(Path::new("/etc/passwd")),
            Err(ToolError::Denied(PathBuf::from("/etc/passwd")))
        );
    }

    #[test]
    fn guard_接受工作区内绝对路径_工作区自身合法() {
        let t = tb("/tmp/ws");
        assert_eq!(
            t.guard(Path::new("/tmp/ws/x")).unwrap(),
            PathBuf::from("/tmp/ws/x")
        );
        assert_eq!(t.guard(Path::new(".")).unwrap(), PathBuf::from("/tmp/ws"));
        assert_eq!(t.guard(Path::new("")).unwrap(), PathBuf::from("/tmp/ws"));
    }

    #[test]
    fn guard_拒绝同前缀兄弟目录逃逸() {
        let t = tb("/tmp/ws");
        // /tmp/wsx 不是 /tmp/ws 的子路径，即便字符串前缀相同也必须拒绝。
        assert!(t.guard(Path::new("/tmp/wsx/a")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_links_逐成分还原符号链接目标() {
        let t = TempDir::new();
        std::fs::create_dir(t.path().join("real")).unwrap();
        std::fs::write(t.path().join("real/x.txt"), "").unwrap();
        std::os::unix::fs::symlink("real", t.path().join("link")).unwrap();
        // 工作区内的符号链接：解析回真实目标，仍在工作区内。
        assert_eq!(
            resolve_links(&t.path().join("link/x.txt")),
            t.path().join("real/x.txt")
        );

        let outside = TempDir::new();
        std::fs::write(outside.path().join("secret.txt"), "").unwrap();
        std::os::unix::fs::symlink(outside.path(), t.path().join("out")).unwrap();
        // 词法上前缀仍在工作区内，逐成分解析后逃逸 —— 这正是 v0 词法闸的漏洞，
        // 由 FsToolbox::resolve（解析闸）拦截，见集成测试 support/mod.rs。
        assert!(t.path().join("out/secret.txt").starts_with(t.path()));
        assert!(!resolve_links(&t.path().join("out/secret.txt")).starts_with(t.path()));
    }

    #[test]
    fn rel_display_返回工作区相对路径() {
        let t = tb("/tmp/ws");
        assert_eq!(t.rel_display(Path::new("/tmp/ws/a/b.txt")), "a/b.txt");
        assert_eq!(t.rel_display(Path::new("/tmp/ws")), "");
    }
}
