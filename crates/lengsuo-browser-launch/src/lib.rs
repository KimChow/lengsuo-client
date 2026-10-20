//! 环境隔离的浏览器进程启动层。
//!
//! **契约边界**：`lengsuo-browser-lifecycle` 明确声明「never spawns or kills a
//! process」——它只做阶段机与监督语义，**不碰进程**。
//! 本 crate 负责**真正启动**浏览器进程，并把该环境的**代理出口配置**注入进去，
//! 使「同一台机器、同一浏览器、多个环境、多个不同出口」成为可执行的事实。
//!
//! 设计要点：
//! - **凭据不进命令行**：Windows 上进程命令行可被他人读取，代理口令一律经
//!   环境变量或独立配置文件注入；命令行渲染后还有一道泄漏自检。
//! - **不靠 sleep 猜就绪**：启动后必须做可判定的就绪探测（端口 / 文件）。
//! - **fail-closed**：浏览器起不来 ⇒ 明确失败，**不得**降级为「无代理的裸连」。
//! - **必回收**：进程句柄必须能取消、kill 并 wait，避免留下孤儿进程。
//!
//! ## 用法
//!
//! ```no_run
//! use lengsuo_browser_launch::{
//!     BrowserBinary, EnvironmentId, Generation, LaunchSpec, Launcher, ProbeBudget,
//!     ProxyConfig, ProxyScheme,
//! };
//! use std::path::PathBuf;
//!
//! let proxy = ProxyConfig::empty()
//!     .with_endpoint(ProxyScheme::Http, "127.0.0.1", 8080)?;
//! let spec = LaunchSpec::new(
//!     BrowserBinary::locate(std::path::Path::new("/opt/chrome/chrome")),
//!     PathBuf::from("/var/lengsuo/env-a"),
//!     EnvironmentId::new("env-a")?,
//!     Generation::new(1)?,
//!     proxy,
//!     vec![],
//!     ProbeBudget::new(20_000)?,
//! )?
//! .with_remote_debugging(true);
//!
//! let mut launcher = Launcher::new();
//! let mut launched = launcher.launch(&spec)?;
//! println!("pid={}", launched.process.pid());
//! launched.process.shutdown()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod command;
mod credential;
mod error;
mod identity;
mod launch;
mod probe;
mod process;
mod proxy;
mod secret;
mod spec;

pub use command::{render, CommandLine};
pub use credential::{
    assert_no_credential_leak, render_credential_file, CredentialInjection, CredentialPlan,
    CREDENTIAL_FILE_NAME, SIDE_CAR_ENV_PREFIX,
};
pub use error::{LaunchError, ProxyError};
pub use identity::{EnvironmentId, Generation, ProbeBudget, MAX_PROBE_BUDGET_MS};
pub use launch::{Launched, Launcher};
pub use probe::{
    wait_for_ready, ProbeOutcome, ProcessWatch, ReadinessStrategy, DEVTOOLS_PORT_FILE,
};
pub use process::BrowserProcess;
pub use proxy::{ProxyConfig, ProxyCredential, ProxyEndpoint, ProxyScheme};
pub use secret::Secret;
pub use spec::{BrowserBinary, LaunchSpec};
