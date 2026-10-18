//! 待 spawn 的 server 命令（program + args + env）。
//!
//! `Debug` 手工实现：参数与环境变量可能含机密，只输出计数、不输出内容。

use std::collections::BTreeMap;

/// 待 spawn 的 MCP server 命令。
#[derive(Clone)]
pub struct StdioServerCommand {
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

impl std::fmt::Debug for StdioServerCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioServerCommand")
            .field("program", &self.program)
            .field("argument_count", &self.args.len())
            .field("environment_count", &self.env.len())
            .finish_non_exhaustive()
    }
}

impl StdioServerCommand {
    /// 以可执行程序名创建命令。
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
        }
    }

    /// 追加命令行参数。
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// 追加环境变量（只增不改已有系统环境的其它项）。
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    pub(crate) fn args_slice(&self) -> &[String] {
        &self.args
    }

    pub(crate) fn env_iter(&self) -> &BTreeMap<String, String> {
        &self.env
    }
}
