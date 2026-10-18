//! GPUI 渲染层（阶段二）。
//!
//! 分层约定：
//! - **纯逻辑（任何 feature 组合都可编译、可单测）**：
//!   [`tool_titles`]（工具名 → 人话标题）、[`diff`]（行级 diff）、[`palette`]（命令面板命令表）。
//!   这三个模块不 import gpui，因此 `cargo test -p lengsuo-shell`（不开 `ui`）也能覆盖。
//! - **GPUI 视图（只在 `feature = "ui"` 下存在）**：[`app`]、[`session_view`]、[`input`]。
//!
//! 渲染层约束（AGENTS.md §6、任务卡）：
//! - 数据只来自既有视图状态（[`crate::state`]）与网关客户端（[`crate::gateway`]），
//!   不在视图里实现任何业务语义，也不直连运行时。
//! - **不持有凭据**：握手 token 只在 [`crate::gateway::GatewayClient`] 内存中，
//!   视图层不读取、不显示、不落盘。

mod diff;
mod palette;
mod tool_titles;

pub use diff::{diff_lines, DiffKind, DiffLine};
pub use palette::{filter_commands, PaletteCommand, PaletteCommandKind, PALETTE_COMMANDS};
pub use tool_titles::{tool_title, tool_title_of};

#[cfg(feature = "ui")]
mod app;
#[cfg(feature = "ui")]
mod input;
#[cfg(feature = "ui")]
mod session_view;

#[cfg(feature = "ui")]
#[cfg(feature = "ui")]
pub use app::{launch, ShellApp};
#[cfg(feature = "ui")]
#[cfg(feature = "ui")]
pub use input::{input_key_action, InputKey, InputKeyAction};
#[cfg(feature = "ui")]
#[cfg(feature = "ui")]
pub use session_view::SessionStreamView;
