//! stdio 传输：spawn 子进程，取走 stdin/stdout 管道，交给 [`crate::session::Session`]。
//!
//! v0 只做 stdio（MCP 规范中本地 server 必须支持的传输）；HTTP/SSE 未实现，
//! 见 result.md 遗留项。
//!
//! 子进程 stderr 接到 `Stdio::null()`：MCP server 常往 stderr 写日志，继承
//! 父进程 stderr 会污染客户端输出，而无人读取的管道又会写满阻塞对端。
//! v0 不采集 stderr；需要时由调用方让 server 自行落盘。
//!
//! `kill_on_drop(true)`：即使上层忘记 shutdown，子进程也不会变成孤儿。

use std::process::Stdio;
use std::sync::Arc;

use tokio::process::Command;

use crate::client::StdioServerCommand;
use crate::error::Error;
use crate::session::{Session, SessionConfig};

/// 已建立的 stdio 连接（子进程 + 会话）。
pub(crate) struct StdioTransport {
    session: Arc<Session>,
}

impl StdioTransport {
    /// spawn `command` 并建立会话。
    ///
    /// # Errors
    /// [`Error::Transport`]：spawn 失败，或子进程未提供 stdin/stdout 管道。
    pub(crate) async fn spawn(
        command: &StdioServerCommand,
        config: &SessionConfig,
    ) -> Result<Self, Error> {
        let mut child = Command::new(command.program())
            .args(command.args_slice())
            .envs(command.env_iter())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::Transport {
                reason: format!(
                    "启动 MCP server 子进程失败（program={:?}）：{e}",
                    command.program()
                ),
            })?;

        let stdin = child.stdin.take().ok_or_else(|| Error::Transport {
            reason: "子进程未提供 stdin 管道".to_string(),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| Error::Transport {
            reason: "子进程未提供 stdout 管道".to_string(),
        })?;

        // 会话构造与传输安装分两步（裁决：session.rs 为权威 API）：
        // with_config 只建状态，attach_stdio 接管管道并启动 reader。
        let session = Session::with_config(config.clone());
        session.attach_stdio(stdin, stdout, child).await?;
        Ok(Self { session })
    }

    pub(crate) fn session(&self) -> &Arc<Session> {
        &self.session
    }
}
