//! Windows 沙箱的**纯构造层**：不依赖 `windows-sys`、不依赖 `target_os`，
//! 因此可在 Linux（47）上直接单测。FFI 侧（`token`/`acl`/`process`）只消费本模块的产物。
//!
//! 与 codex 的对应关系（参数级照抄）：
//! - [`quote_windows_arg`] / [`build_command_line`] ← `windows-sandbox-rs/src/winutil.rs:76-121`
//!   （CRT / `CommandLineToArgvW` 规则：空格、引号、反斜杠）；
//! - [`build_env_block`] ← `windows-sandbox-rs/src/process.rs:53-63`（`K=V\0…\0` 双层 NUL）；
//! - [`platform_sandbox_plan`] / [`resolve_backend`] / [`deny_acl_targets`] 为 design §3/§4 的纯决策，
//!   与 codex 的 `sandboxing/src/manager.rs` 降级链同构。

use std::path::{Path, PathBuf};

use crate::baseline::is_denied_path;
use crate::types::{
    CommandSpec, NetworkMode, SandboxError, SandboxPolicy, SandboxType, SandboxablePreference,
};

/// Windows 派生进程 env 白名单（design §3.8）。
///
/// 绝不整块继承父进程环境：进程自身 env 与 `CommandSpec::env` 都按本表过滤（R8）。
pub const WINDOWS_ENV_ALLOWLIST: &[&str] = &[
    "SYSTEMROOT",
    "PATH",
    "USERPROFILE",
    "USERNAME",
    "TEMP",
    "TMP",
    "LANG",
];

/// 判断 env 键是否命中白名单（Windows 键名大小写不敏感）。
pub fn env_key_allowed(key: &str) -> bool {
    WINDOWS_ENV_ALLOWLIST
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(key))
}

/// 按 `CommandLineToArgvW` / CRT 规则引用单个参数。
///
/// 规则（照抄 codex `winutil.rs:76-112`，与 Rust `std::process::Command` 在 Windows 上的行为一致）：
/// - 空串，或含空格 / 制表 / 换行 / 回车 / 双引号的参数需要加引号；
/// - 参数内**末尾连续反斜杠**要加倍（否则会转义收尾引号）；
/// - 双引号前的连续反斜杠要加倍再加一个（`2n+1`），用于转义该引号。
pub fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '"'));
    if !needs_quotes {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }
    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes * 2));
    }
    quoted.push('"');
    quoted
}

/// 拼 `CreateProcess` 系 API 的命令行：`argv[0]`（program）逐项引用后以单空格连接。
///
/// 注意：`CreateProcessAsUserW` 的 `lpApplicationName` 传 null，可执行文件由本串首项解析
/// （与 codex `process.rs:168` 同款）。
pub fn build_command_line(program: &Path, args: &[String]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(args.len() + 1);
    parts.push(quote_windows_arg(&program.to_string_lossy()));
    parts.extend(args.iter().map(|arg| quote_windows_arg(arg)));
    parts.join(" ")
}

/// UTF-16 + NUL 终止（`to_wide`，照抄 codex `winutil.rs:32-36`）。
pub fn to_utf16_nul(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// 构造 `CREATE_UNICODE_ENVIRONMENT` 环境块：每条 `K=V` 后跟一个 NUL，末尾再补一个 NUL
/// （照抄 codex `process.rs:53-63`）。空表退化为单个 NUL——调用方不得借此继承父环境。
pub fn build_env_block(entries: &[(String, String)]) -> Vec<u16> {
    let mut block: Vec<u16> = Vec::new();
    for (key, value) in entries {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// 构造派生进程 env（R8 清洗）：
/// 1. 进程自身 env 与 `spec.env` 都按 [`WINDOWS_ENV_ALLOWLIST`] 过滤（大小写不敏感）；
/// 2. `spec.env` 覆盖进程 env 的同名键（大小写不敏感）；键的**拼写**沿用首次出现者；
/// 3. 输出按 `key.to_ascii_uppercase()` 排序，保证确定性（便于黄金向量）。
pub fn build_env_entries(
    process_env: &[(String, String)],
    spec_env: &[(String, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (key, value) in process_env.iter().chain(spec_env.iter()) {
        if !env_key_allowed(key) {
            continue;
        }
        match out
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(key))
        {
            // 同键：保留首次出现的拼写，值取最后出现者（spec.env 在后 → 显式请求胜出）。
            Some(entry) => entry.1.clone_from(value),
            None => out.push((key.clone(), value.clone())),
        }
    }
    out.sort_by_key(|(key, _)| key.to_ascii_uppercase());
    out
}

/// 需要加 deny ACE 的凭据路径（design §3.6 / §7）：
/// - `%USERPROFILE%\.ssh`、`%APPDATA%\gnupg`（由调用方展开环境变量后传入）；
/// - `spec` 的 `writable_roots` / `read_only_roots` 中命中安全基线（`.ssh`/`.gnupg` 及其子路径）的条目。
///
/// 结果排序去重；返回的每一条都会在 FFI 侧被拒绝读取（deny ACE 置 DACL 首位）。
pub fn deny_acl_targets(
    spec: &CommandSpec,
    user_profile: Option<&Path>,
    app_data: Option<&Path>,
) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = spec
        .writable_roots
        .iter()
        .chain(spec.read_only_roots.iter())
        .filter(|p| is_denied_path(p))
        .cloned()
        .collect();
    if let Some(profile) = user_profile {
        targets.push(profile.join(".ssh"));
    }
    if let Some(appdata) = app_data {
        targets.push(appdata.join("gnupg"));
    }
    targets.sort();
    targets.dedup();
    targets
}

/// 平台沙箱探测计划（design §4）：
/// - `enabled == false`（上层配置关闭）→ `None`，**不**执行干跑；
/// - `enabled == true` → 由 `dry_run`（真建一次受限令牌再销毁）决定 `Some(WindowsRestrictedToken)` / `None`。
///
/// `enabled` 由调用方（agent-core 的配置）提供；本 crate 不持有配置。
pub fn platform_sandbox_plan(enabled: bool, dry_run: impl FnOnce() -> bool) -> Option<SandboxType> {
    if !enabled {
        return None;
    }
    if dry_run() {
        Some(SandboxType::WindowsRestrictedToken)
    } else {
        None
    }
}

/// 执行后端选择结果（纯决策，不起进程）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// 受限令牌沙箱执行。
    RestrictedToken,
    /// 无隔离直跑（仅 `Forbid`，或显式要求时）。
    Unsandboxed,
}

/// 偏好 / 策略 / 网络的纯决策（design §4 + §5；语义与 `linux.rs` 的降级链对齐）：
///
/// - `Forbid` → [`Backend::Unsandboxed`]（无隔离，仅调用方显式要求时）；
/// - `Require` + 无沙箱 → `Err(Unavailable)`（fail-closed）；
/// - `Auto` + 无沙箱 → `policy.allow_approval_fallback` ? `Err(NeedsApproval)` : `Err(Denied)`；
/// - 有沙箱但 `NetworkMode::Blocked` → `Err(NeedsApproval)`：**Windows 本期无法阻断网络**
///   （design §5），fail-closed 转人工审批，绝不静默放行；
/// - 有沙箱且网络已放行（`NetworkMode::Allow`）→ [`Backend::RestrictedToken`]。
pub fn resolve_backend(
    pref: SandboxablePreference,
    policy: SandboxPolicy,
    network: NetworkMode,
    sandbox_available: bool,
) -> Result<Backend, SandboxError> {
    match pref {
        SandboxablePreference::Forbid => Ok(Backend::Unsandboxed),
        SandboxablePreference::Require if !sandbox_available => Err(SandboxError::Unavailable(
            "no sandbox available on this platform but Require was requested".into(),
        )),
        SandboxablePreference::Auto if !sandbox_available => {
            if policy.allow_approval_fallback {
                Err(SandboxError::NeedsApproval(
                    "sandbox unavailable; command must go through manual approval".into(),
                ))
            } else {
                Err(SandboxError::Denied(
                    "sandbox unavailable and approval fallback disabled".into(),
                ))
            }
        }
        _ if network.should_unshare_network() => Err(SandboxError::NeedsApproval(
            "windows restricted-token sandbox cannot block the network yet; \
             manual approval required (fail-closed)"
                .into(),
        )),
        _ => Ok(Backend::RestrictedToken),
    }
}

#[cfg(test)]
#[path = "construct_tests.rs"]
mod tests;
