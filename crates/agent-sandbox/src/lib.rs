//! agent-sandbox：agent 沙箱体系的执行分发层（D4）。
//!
//! 平台抽象（`SandboxType` / `SandboxablePreference` / `get_platform_sandbox` / 降级链）
//! 语义对照 codex（`codex-rs/protocol/src/sandbox.rs`、`codex-rs/sandboxing/src/manager.rs`）。
//! 本卡交付 Linux（bwrap + seccomp profile 构造）完整实现；
//! macOS 为编译通过的 TODO 骨架；Windows 为 fail-closed 桩（后续卡实现）。

#![cfg_attr(not(windows), forbid(unsafe_code))]
// windows.rs 的只读 FFI 探测（GetModuleHandleW/GetProcAddress）是本 crate 唯一 unsafe 例外，
// 仅限 windows target、且为外部 API 调用的强制 unsafe；仓库「生产网络代码禁 unsafe」规则不受影响。

mod baseline;
mod types;

pub use baseline::{
    cache_roots_for_home, env_passlist, is_denied_path, CACHE_DIR_NAMES, DENY_PATH_COMPONENTS,
    ENV_PASSLIST,
};
pub use types::{
    CommandSpec, ExecOutcome, ExecStatus, NetworkMode, SandboxError, SandboxPolicy, SandboxType,
    SandboxablePreference,
};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    build_bwrap_argv, detect_sandbox_with, find_bwrap_in_path_with, find_system_bwrap_in_path,
    get_platform_sandbox, masks_for, run_sandboxed, run_sandboxed_with, SandboxProbe, SystemProbe,
};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::{get_platform_sandbox, run_sandboxed};

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{get_platform_sandbox, restricted_token_available, run_sandboxed};

/// 非支持平台（既非 linux/macos/windows）：无沙箱实现，探测恒 None（fail-closed）。
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn get_platform_sandbox() -> Option<SandboxType> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn run_sandboxed(
    _spec: CommandSpec,
    pref: SandboxablePreference,
    _policy: SandboxPolicy,
) -> Result<ExecOutcome, SandboxError> {
    match pref {
        SandboxablePreference::Forbid => Err(SandboxError::Unavailable(
            "no backend for this platform".into(),
        )),
        _ => Err(SandboxError::Unavailable(
            "no sandbox backend for this platform".into(),
        )),
    }
}
