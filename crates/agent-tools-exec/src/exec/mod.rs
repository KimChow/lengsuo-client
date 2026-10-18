//! Shell 执行工具：受控超时、进程组终止、有界输出。
//!
//! 命令文本**只作为单个 argv** 交给 `bash -c`，本 crate 不拼接、不追加参数，
//! 因此不存在宿主侧注入面；命令自身的 shell 语义由调用方（模型）负责，
//! 权限判定不在本层（归 `agent-core` 权限门）。

mod process;

use std::path::Path;
use std::time::Duration;

use crate::error::ExecError;

/// 可执行 shell 种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// Bash（Linux/POSIX 主路径）。
    Bash,
    /// PowerShell（本 crate 未实现，一律 [`ExecError::Unsupported`]）。
    PowerShell,
}

impl Shell {
    /// 当前平台是否提供该 shell 的实现。
    pub fn available_on_this_platform(self) -> bool {
        matches!(self, Shell::Bash)
    }

    /// 可执行文件名。
    fn program(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::PowerShell => "pwsh",
        }
    }
}

/// 执行配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecConfig {
    /// 未显式传 `timeout` 时生效的超时。
    pub default_timeout: Duration,
    /// stdout 与 stderr **各自**的字节上限；超出即截断并置 `truncated`。
    pub max_output_bytes: usize,
    /// 允许使用的 shell；不在列表内 ⇒ [`ExecError::Unsupported`]。
    pub allowed_shells: Vec<Shell>,
}

impl Default for ExecConfig {
    fn default() -> Self {
        ExecConfig {
            default_timeout: Duration::from_secs(30),
            max_output_bytes: 30_000,
            allowed_shells: vec![Shell::Bash],
        }
    }
}

/// 一次执行的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// 退出码；被信号终止或被我们杀掉时为 `-1`（无退出码）。
    pub exit_code: i32,
    /// 已保留的 stdout（按字节截断，非法 UTF-8 序列已丢弃）。
    pub stdout: String,
    /// 已保留的 stderr。
    pub stderr: String,
    /// 任一流被截断。
    pub truncated: bool,
    /// 从 spawn 到收尾的毫秒数。
    pub duration_ms: u64,
    /// 是否因超时被终止；为真时 `stdout`/`stderr` 保留超时前已产出的部分。
    pub timed_out: bool,
}

/// Bash 风格命令执行器。
#[derive(Debug, Clone)]
pub struct ExecRunner {
    cfg: ExecConfig,
}

impl ExecRunner {
    /// 用给定配置构造执行器。
    pub fn new(cfg: ExecConfig) -> Self {
        ExecRunner { cfg }
    }

    /// 当前配置。
    pub fn config(&self) -> &ExecConfig {
        &self.cfg
    }

    /// 运行一条命令。
    ///
    /// * `timeout` 为空则用 [`ExecConfig::default_timeout`]；
    /// * `cwd` 为空则继承当前进程工作目录；
    /// * 超时 ⇒ 杀整个进程组（子进程在独立进程组中启动），保留已有输出，
    ///   `timed_out = true`；
    /// * 输出按 [`ExecConfig::max_output_bytes`] 截断，`truncated = true`。
    pub async fn run(
        &self,
        shell: Shell,
        command: &str,
        cwd: Option<&Path>,
        timeout: Option<Duration>,
    ) -> Result<ExecResult, ExecError> {
        self.check_shell(shell)?;
        let timeout = timeout.unwrap_or(self.cfg.default_timeout);
        process::run(
            shell.program(),
            command,
            cwd,
            timeout,
            self.cfg.max_output_bytes,
        )
        .await
    }

    fn check_shell(&self, shell: Shell) -> Result<(), ExecError> {
        if !self.cfg.allowed_shells.contains(&shell) {
            return Err(ExecError::Unsupported("shell 不在 allowed_shells 内"));
        }
        if !shell.available_on_this_platform() {
            return Err(ExecError::Unsupported(if cfg!(target_os = "windows") {
                "PowerShell 执行尚未实现"
            } else {
                "Linux 仅支持 Bash，PowerShell 不可用"
            }));
        }
        Ok(())
    }
}
