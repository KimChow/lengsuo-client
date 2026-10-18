//! agent-tools-exec：执行与网络工具（波次 1 卡 2/6）。
//!
//! 对照 参考客户端 的 Bash/PowerShell/WebFetch 能力，提供两件事：
//! - [`ExecRunner`]：在受控 shell 中运行一条命令，带超时（杀整个进程组）与字节截断；
//! - [`WebFetcher`]：只走 http/https 的小额度抓取，把 HTML 收成纯文本。
//!
//! 规格源：worktree 根 `AGENT-KICKOFF.md` 与本卡 API 冻结说明。
//! 本 crate 只做工具执行与抓取，不做权限判定（归 `agent-core` 的权限门），
//! 也不做 WebSearch（需密钥，由调用方层实现）。

pub mod error;
pub mod exec;
pub mod html;
pub mod web;

pub use error::ExecError;
pub use exec::{ExecConfig, ExecResult, ExecRunner, Shell};
pub use web::{FetchResult, WebFetcher};
