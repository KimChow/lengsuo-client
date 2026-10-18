//! Windows 沙箱实现：受限令牌（[`SandboxType::WindowsRestrictedToken`]）路。
//!
//! 令牌构造参数**照抄** codex `windows-sandbox-rs/src/token.rs:455-525`
//! （flags 与 SID 顺序即语义），进程启动照抄 `process.rs:104-203`，
//! deny ACE 照抄 `acl.rs:1005-1016`。只取受限令牌主线——不搬 codex 的 helper service /
//! elevated / AppContainer / WFP 全家桶（21,604 行）。
//!
//! ## 编译分工（关键）
//! 纯构造逻辑在 [`construct`]，不依赖 `windows-sys`、不依赖 `target_os`，**在 Linux（47）上可单测**。
//! 本文件与 `token`/`acl`/`process` 子模块是 windows-sys FFI，仅 `cfg(windows)` 编译；
//! 其在 47 上以 `cargo check --target x86_64-pc-windows-msvc` 做类型级验证，
//! **运行期行为（CreateProcessAsUserW 权限、ACL 生效）只能由本机 Windows 冒烟确认**——见下。
//!
//! ## 待本机验证（design §7，卡内如实标注）
//! - `CreateProcessAsUserW` 对「从自身令牌派生的受限令牌」是否需要 `SE_ASSIGNPRIMARYTOKEN_NAME`：
//!   文档要求该特权，但同 logon 会话下普通用户实践可用（codex 基础的 RestrictedToken 级未提权）。
//!   若本机冒烟失败，退化路径为 `CreateProcessWithTokenW`（需 `SE_IMPERSONATE`）。
//! - deny ACE 对本机用户 SID 的实际拦截效果（`type %USERPROFILE%\.ssh\id_rsa` 应报拒绝访问）。
//!
//! ## TODO（design §6，本期明确不做）
//! - **网络阻断**（`NetworkMode::Blocked`）：需 WFP/LocalProxy（codex `wfp.rs`）或 MXC；
//!   当前 fail-closed：`Err(NeedsApproval)`，绝不静默放行（见 [`construct::resolve_backend`]）。
//! - **deny-read 递归 walker**：只 deny 目录本身 + 已知凭据路径；深层渗透留审批。
//! - **进程树终止 / 资源限额（Job Object）**：本期不建 Job Object（codex 基础路径亦未依赖它）。
//! - **WindowsMxc**：依赖微软 mxc 仓，枚举值已预留。
//! - **AppContainer capabilities**：`CreateRestrictedToken` 的 entries 留空（仅 logon + Everyone）。
//! - **Elevated 专用 sandbox 账户**：codex `elevated/` 16 个模块，不做；LOA 令牌对当前用户已够。

pub mod construct;

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod token;

#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use crate::types::{
    CommandSpec, ExecOutcome, ExecStatus, SandboxError, SandboxPolicy, SandboxType,
    SandboxablePreference,
};
#[cfg(windows)]
use construct::Backend;

#[cfg(windows)]
use windows_sys::Win32::Foundation::HMODULE;
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

/// 只读探测：advapi32 是否导出 CreateRestrictedToken（不加载新库、不调用任何沙箱 API）。
///
/// # Safety
/// `GetModuleHandleW`/`GetProcAddress` 是受 WinAPI 契约保证的只读查询；
/// 传入静态 UTF-16 缓冲与静态 ASCII 函数名，不释放任何句柄，解引用仅限返回指针非空分支。
#[cfg(windows)]
pub fn restricted_token_available() -> bool {
    const ADVAPI32: &[u16] = &[
        b'a' as u16,
        b'd' as u16,
        b'v' as u16,
        b'a' as u16,
        b'p' as u16,
        b'i' as u16,
        b'3' as u16,
        b'2' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    const FUNC: &[u8] = b"CreateRestrictedToken\0";
    let module: HMODULE = unsafe { GetModuleHandleW(ADVAPI32.as_ptr()) };
    if module.is_null() {
        return false;
    }
    let proc = unsafe { GetProcAddress(module, FUNC.as_ptr()) };
    proc.is_some()
}

/// 平台沙箱探测（design §4）：**干跑**真建一次受限令牌再销毁；成功 → `Some(WindowsRestrictedToken)`。
///
/// 上层配置开关（codex `windows_sandbox_enabled`）由调用方在 [`construct::platform_sandbox_plan`]
/// 处传入；本 crate 不持有配置，故此处恒视为启用。
#[cfg(windows)]
pub fn get_platform_sandbox() -> Option<SandboxType> {
    construct::platform_sandbox_plan(true, token::probe_create_restricted_token)
}

/// 主 API：按偏好/策略分发执行（真实探测 + 干跑）。
#[cfg(windows)]
pub fn run_sandboxed(
    spec: CommandSpec,
    pref: SandboxablePreference,
    policy: SandboxPolicy,
) -> Result<ExecOutcome, SandboxError> {
    // `Forbid` 无需探测——避免为一次显式非沙箱执行白白建/销毁一个受限令牌。
    let available = match pref {
        SandboxablePreference::Forbid => false,
        _ => get_platform_sandbox().is_some(),
    };
    match construct::resolve_backend(pref, policy, spec.network, available)? {
        Backend::Unsandboxed => run_unsandboxed(spec),
        Backend::RestrictedToken => run_restricted_token(spec),
    }
}

/// 受限令牌沙箱执行：建令牌 → deny ACL → 构造 cmdline/env → `CreateProcessAsUserW` → 收管道。
#[cfg(windows)]
fn run_restricted_token(spec: CommandSpec) -> Result<ExecOutcome, SandboxError> {
    let base = token::open_current_token()?;
    // deny ACE 的受托者是当前用户 SID（受限令牌仍保留该 SID，故 deny 生效）。
    let user_sid = token::token_user_sid_bytes(base.raw())?;
    let restricted = token::create_restricted_token(base.raw())?;

    let user_profile = env_path("USERPROFILE");
    let app_data = env_path("APPDATA");
    let targets = construct::deny_acl_targets(&spec, user_profile.as_deref(), app_data.as_deref());
    acl::apply_deny_acls(&targets, user_sid.as_ptr().cast_mut().cast())?;

    let env = construct::build_env_entries(&process_env_entries(), &spec.env);
    process::spawn_and_wait(restricted.raw(), &spec, &env)
}

/// `Forbid`（或显式放行）→ 无隔离直跑；env 仍按 R8 清洗（绝不整块继承）。
#[cfg(windows)]
fn run_unsandboxed(spec: CommandSpec) -> Result<ExecOutcome, SandboxError> {
    let label = spec.program.to_string_lossy().into_owned();
    let mut cmd = std::process::Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(construct::build_env_entries(
            &process_env_entries(),
            &spec.env,
        ))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    let out = cmd
        .output()
        .map_err(|e| SandboxError::Spawn(format!("{label}: {e}")))?;
    Ok(ExecOutcome {
        status: ExecStatus {
            code: out.status.code(),
            signal: None,
            success: out.status.success(),
        },
        stdout: out.stdout,
        stderr: out.stderr,
        sandbox: SandboxType::None,
    })
}

/// 读一个环境变量为路径（供 `%USERPROFILE%` / `%APPDATA%` 展开）。
#[cfg(windows)]
fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

/// 收集本进程 env 作为白名单过滤的输入（`OsString` 以 lossy 转换；非 Unicode 变量在 Windows 上罕见）。
#[cfg(windows)]
fn process_env_entries() -> Vec<(String, String)> {
    std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect()
}
