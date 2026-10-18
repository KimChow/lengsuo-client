//! agent-pty：异步伪终端（PTY）会话管理，对应 参照平台 集成终端能力。
//!
//! 规格源：波次 1 卡 4（冻结 API）。底层用 `portable-pty` 0.8（MIT）提供 PTY 原语，
//! 本 crate 在其上加 tokio 异步外观、每会话一条输出流，以及 ≤1 MiB 环形历史回放。
//!
//! 关键取舍（详见根目录 `result.md`）：
//! - 输出通道选 **mpsc**（单订阅者 + 背压），不选 broadcast；
//! - 阻塞的 PTY 读取放在专用 OS 线程，经 `Handle::block_on` 投递到有界通道；
//! - `PtyConfig::shell` 按**命令行**解析（`shell-words`），因此 `bash -c 'echo hi'` 可表达；
//! - 本 crate 无 `unsafe`：平台细节全部由 `portable-pty` 承担。
//!
//! ```no_run
//! use agent_pty::{PtyConfig, PtyManager};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let mut mgr = PtyManager::new();
//! let id = mgr.create(PtyConfig::default()).await?;
//! mgr.write(id, b"ls -l\r").await?;
//! let mut rx = mgr.take_output(id).await.unwrap();
//! while let Some(chunk) = rx.recv().await {
//!     // chunk 推给 UI 终端组件
//!     let _ = chunk;
//! }
//! let history = mgr.replay(id); // 重开 UI 时回放
//! # Ok(())
//! # }
//! ```

// 对外只暴露规格冻结的类型；`ring`/`session` 是实现细节，保持私有。
mod ring;
mod session;

pub mod config;
pub mod error;
pub mod manager;

pub use config::{PtyConfig, DEFAULT_COLS, DEFAULT_ROWS};
pub use error::PtyError;
pub use manager::{PtyManager, SessionInfo};
pub use ring::HISTORY_BYTES;
