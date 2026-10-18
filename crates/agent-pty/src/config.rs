//! 会话创建配置（规格冻结的 `PtyConfig`）。

use std::collections::BTreeMap;
use std::path::PathBuf;

/// 默认列数（80×24 是终端通用出厂尺寸）。
pub const DEFAULT_COLS: u16 = 80;
/// 默认行数。
pub const DEFAULT_ROWS: u16 = 24;

/// 创建一个伪终端会话所需的配置。
///
/// `shell` 是**命令行**而非单个可执行路径：按 `shell-words` 规则分词为 argv，
/// 因此 `"bash -c 'echo hi'"`、`"/bin/zsh --login"` 都能表达。
/// 冻结规格里这个字段叫 `shell`，但集成终端（对照 参照平台）实际要的是
/// “在 PTY 里跑什么”，只允许单个路径会丢掉 `-c`/`--login` 这类形态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyConfig {
    /// 在 PTY 中启动的命令行；默认 `$SHELL`，缺失时 `/bin/bash`。
    pub shell: String,
    /// 子进程工作目录；`None` 表示继承当前进程的家目录。
    pub cwd: Option<PathBuf>,
    /// 初始列数。
    pub cols: u16,
    /// 初始行数。
    pub rows: u16,
    /// 追加/覆盖的环境变量（在当前进程环境之上叠加，不进日志）。
    pub env: BTreeMap<String, String>,
}

impl Default for PtyConfig {
    /// 默认 shell 取 `$SHELL`（非空即用），否则 `/bin/bash`（规格要求）。
    fn default() -> Self {
        Self {
            shell: default_shell(),
            cwd: None,
            cols: DEFAULT_COLS,
            rows: DEFAULT_ROWS,
            env: BTreeMap::new(),
        }
    }
}

impl PtyConfig {
    /// 把 `shell` 命令行分词为 argv；空命令行返回 `None`（调用方转成错误）。
    pub(crate) fn argv(&self) -> Option<Vec<String>> {
        let parts = shell_words::split(&self.shell).ok()?;
        if parts.iter().all(|p| p.trim().is_empty()) {
            return None;
        }
        Some(parts)
    }
}

/// `$SHELL` 优先，其次 `/bin/bash`。
fn default_shell() -> String {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/bin/bash".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_shell_is_non_empty() {
        assert!(!default_shell().is_empty());
        assert_eq!(PtyConfig::default().cols, DEFAULT_COLS);
        assert_eq!(PtyConfig::default().rows, DEFAULT_ROWS);
    }

    #[test]
    fn argv_splits_like_shell_words() {
        let c = PtyConfig {
            shell: "bash --norc -c \"echo 'hi there'\"".into(),
            ..PtyConfig::default()
        };
        assert_eq!(
            c.argv().unwrap(),
            vec![
                "bash".to_string(),
                "--norc".to_string(),
                "-c".to_string(),
                "echo 'hi there'".to_string()
            ]
        );
    }

    #[test]
    fn empty_or_invalid_command_line_is_none() {
        let c = PtyConfig {
            shell: String::new(),
            ..PtyConfig::default()
        };
        assert_eq!(c.argv(), None);
        let c = PtyConfig {
            shell: "   ".into(),
            ..PtyConfig::default()
        };
        assert_eq!(c.argv(), None);
        // 未闭合引号：shell-words 报错 ⇒ None，不猜意图。
        let c = PtyConfig {
            shell: "bash -c \"oops".into(),
            ..PtyConfig::default()
        };
        assert_eq!(c.argv(), None);
    }
}
