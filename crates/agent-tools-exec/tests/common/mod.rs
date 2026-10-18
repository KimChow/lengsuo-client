//! 测试辅助：真实子进程、后台线程收流、一次性微型 HTTP 服务器。
//!
//! 库本体只依赖 tokio 的 process/time/io-util 等特性；测试另需 `rt`/`macros`，由
//! dev-dependencies 提供，用 `#[tokio::test]` 直接跑 async。
//!
//! 同步子进程的输出一律在本线程之外的工作线程上收取并 reap：主线程直接 `wait` 会让
//! rustix 的 SIGCHLD 回收线程抢先 reap，`Child::try_wait` 随即报 "already dead"、
//! ExitCodeStatus 缺失，退出码读不出来。

mod checks;
mod process;
mod server;

pub use checks::{
    check_exec, check_exec_error, check_fetch, check_fetch_error, default_fetcher,
    fetcher_at_limit, fetcher_with_timeout,
};
pub use process::{run_in, spawn_process, TestProcess};
pub use server::{Route, TestServer};
