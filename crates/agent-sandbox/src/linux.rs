//! Linux 沙箱实现：bwrap argv 构造 + 可注入探测 + 降级链 + 执行。
//!
//! argv 顺序冻结（黄金向量逐项断言；已在 47 上 bubblewrap 0.9.0 实测）：
//!
//! 1. 会话/父死子亡/身份：`--new-session --die-with-parent --uid 0 --gid 0`
//! 2. 基础挂载：`--ro-bind / /`、`--proc /proc`、`--dev /dev`、`--tmpfs /tmp`
//!
//! 注：不显式 `--unshare-user`——47 实测传该 flag 会让 deny 遮蔽用的 `--tmpfs` 挂载点
//! mkdir 失败；无特权宿主下 bwrap 自行拒绝 userns 时以非零退出失败，fail-closed。
//! 3. `NetworkMode::Blocked` 追加 `--unshare-net`（Allow 则不出现）
//! 4. read_only_roots 逐条 `--ro-bind r r`（按输入顺序；安全基线命中者剔除）
//! 5. writable_roots 逐条 `--bind w w`（安全基线命中者剔除，绝不进入绑定列表）
//! 6. deny 遮蔽：`masks` 逐条 `--tmpfs m`（空 tmpfs 盖掉 .ssh/.gnupg，连读取都不允许）
//! 7. `--chdir <cwd>`（有 cwd 时）
//! 8. env：`--clearenv` 后按白名单顺序 `--setenv K V`（R8 清洗）
//! 9. `--cap-drop ALL`，然后 `-- program args`

use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use crate::baseline::{env_passlist, is_denied_path};
use crate::types::{
    CommandSpec, ExecOutcome, ExecStatus, SandboxError, SandboxPolicy, SandboxType,
    SandboxablePreference,
};

pub mod seccomp;

/// bwrap 固定前缀（构造层黄金向量的锚点，禁止漂移）。
const PREFIX: &[&str] = &[
    "--new-session",
    "--die-with-parent",
    "--uid",
    "0",
    "--gid",
    "0",
    "--ro-bind",
    "/",
    "/",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
];

/// 探测注入面：文件系统/内核能力可替换，测试不触真实磁盘。
pub trait SandboxProbe {
    /// bwrap 可执行文件是否在 PATH 且可运行。
    fn bwrap_available(&self) -> bool;
    /// landlock 是否可用（本卡恒 false：Landlock 路径留 TODO，不假装支持）。
    fn landlock_available(&self) -> bool;
}

/// 真实系统探测。
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProbe;

impl SandboxProbe for SystemProbe {
    fn bwrap_available(&self) -> bool {
        find_system_bwrap_in_path().is_some()
    }
    fn landlock_available(&self) -> bool {
        // TODO(landlock): 探测 /sys/kernel/security/landlock 并实现降级路径。
        // 实现前返回 false：无 bwrap 时探测结果为 None（fail-closed）。
        false
    }
}

/// 在 PATH 中查找可执行的 bwrap。
pub fn find_system_bwrap_in_path() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    find_bwrap_in_path_with(&path_var, is_executable_file)
}

fn is_executable_file(p: &Path) -> bool {
    std::fs::metadata(p)
        .map(|m| {
            m.is_file() && (std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o111 != 0)
        })
        .unwrap_or(false)
}

/// 注入版 PATH 查找：`is_executable` 回调决定命中，便于单测（不起真实进程）。
pub fn find_bwrap_in_path_with(
    path_var: &std::ffi::OsStr,
    is_executable: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    std::env::split_paths(path_var)
        .map(|dir| dir.join("bwrap"))
        .find(|candidate| is_executable(candidate))
}

/// 降级链（注入版）：bwrap 可用 → LinuxSeccomp；landlock → TODO（返回 None）；都无 → None。
pub fn detect_sandbox_with(probe: &impl SandboxProbe) -> Option<SandboxType> {
    if probe.bwrap_available() {
        return Some(SandboxType::LinuxSeccomp);
    }
    if probe.landlock_available() {
        // TODO(landlock): 接入 Landlock 后端；实现前保持 None（fail-closed），不假装支持。
        return None;
    }
    None
}

/// 平台沙箱探测：Linux 下 bwrap 可用 → Some(LinuxSeccomp)，否则 None。
pub fn get_platform_sandbox() -> Option<SandboxType> {
    detect_sandbox_with(&SystemProbe)
}

/// 收集需要遮蔽的凭据路径：显式 roots 里命中安全基线的 + 家目录下真实存在的 .ssh/.gnupg。
/// 返回排序去重后的列表；不存在的路径不遮蔽（目标本来不可见）。
pub fn masks_for(spec: &CommandSpec) -> Vec<PathBuf> {
    let mut masks: Vec<PathBuf> = spec
        .writable_roots
        .iter()
        .chain(spec.read_only_roots.iter())
        .filter(|p| is_denied_path(p))
        .cloned()
        .collect();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for name in ["ssh", "gnupg"] {
            let p = home.join(format!(".{name}"));
            if p.is_dir() && !masks.contains(&p) {
                masks.push(p);
            }
        }
    }
    masks.sort();
    masks.dedup();
    masks
}

/// 构造 bwrap argv（不含 argv[0]=bwrap 本身）。
///
/// - writable/read_only roots 中命中安全基线（.ssh/.gnupg 等）的条目被剔除，绝不进绑定列表；
/// - `masks` 逐条转 `--tmpfs` 遮蔽；不命中安全基线的 mask 项被忽略（防误用）。
pub fn build_bwrap_argv(spec: &CommandSpec, masks: &[PathBuf]) -> Vec<String> {
    let mut argv: Vec<String> = PREFIX.iter().map(|s| s.to_string()).collect();
    if spec.network.should_unshare_network() {
        argv.push("--unshare-net".to_string());
    }
    for root in &spec.read_only_roots {
        if is_denied_path(root) {
            continue;
        }
        argv.push("--ro-bind".to_string());
        push_path(&mut argv, root);
        push_path(&mut argv, root);
    }
    for root in &spec.writable_roots {
        if is_denied_path(root) {
            continue;
        }
        argv.push("--bind".to_string());
        push_path(&mut argv, root);
        push_path(&mut argv, root);
    }
    for mask in masks {
        if !is_denied_path(mask) {
            continue;
        }
        argv.push("--tmpfs".to_string());
        push_path(&mut argv, mask);
    }
    if let Some(cwd) = &spec.cwd {
        argv.push("--chdir".to_string());
        push_path(&mut argv, cwd);
    }
    argv.push("--clearenv".to_string());
    for (k, v) in env_passlist(&spec.env) {
        argv.push("--setenv".to_string());
        argv.push(k);
        argv.push(v);
    }
    argv.push("--cap-drop".to_string());
    argv.push("ALL".to_string());
    argv.push("--".to_string());
    push_path(&mut argv, &spec.program);
    argv.extend(spec.args.iter().cloned());
    argv
}

fn push_path(argv: &mut Vec<String>, p: &Path) {
    argv.push(p.to_string_lossy().into_owned());
}

/// 主 API：按偏好/策略分发执行（真实探测）。
pub fn run_sandboxed(
    spec: CommandSpec,
    pref: SandboxablePreference,
    policy: SandboxPolicy,
) -> Result<ExecOutcome, SandboxError> {
    run_sandboxed_with(&SystemProbe, spec, pref, policy)
}

/// 注入版分发：降级链与 preference 语义的完整实现。
pub fn run_sandboxed_with(
    probe: &impl SandboxProbe,
    spec: CommandSpec,
    pref: SandboxablePreference,
    policy: SandboxPolicy,
) -> Result<ExecOutcome, SandboxError> {
    let target = match pref {
        SandboxablePreference::Forbid => SandboxType::None,
        _ => detect_sandbox_with(probe).unwrap_or(SandboxType::None),
    };
    match (pref, target) {
        // Require + 无沙箱 → fail-closed 拒绝。
        (SandboxablePreference::Require, SandboxType::None) => Err(SandboxError::Unavailable(
            "no sandbox available on this platform but Require was requested".into(),
        )),
        // Auto + 无沙箱 → 按策略转人工审批，或拒绝。
        (SandboxablePreference::Auto, SandboxType::None) => {
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
        // Forbid（或显式放行）→ 非沙箱直跑，env 仍按 R8 清洗。
        (_, SandboxType::None) => run_unsandboxed(spec),
        (_, SandboxType::LinuxSeccomp) => run_bwrap(spec),
        (_, other) => Err(SandboxError::Unavailable(format!(
            "{} is not a Linux sandbox backend",
            other.as_metric_tag()
        ))),
    }
}

fn run_unsandboxed(spec: CommandSpec) -> Result<ExecOutcome, SandboxError> {
    let label = spec.program.to_string_lossy().into_owned();
    let mut cmd = ProcessCommand::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(env_passlist(&spec.env))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    capture(cmd, SandboxType::None, &label)
}

/// bwrap 沙箱执行。
/// TODO(seccomp-apply): 把 `seccomp::linux_seccomp_profile()` 编译为 BPF 并经 fd 传给
/// `--seccomp <fd>`（参照 参考实现 linux-sandbox/src/seccomp.rs）。当前仅 bwrap 命名空间/绑定层
/// 生效，seccomp profile 只以构造+断言存在——**未应用，不得声称已生效**。
fn run_bwrap(spec: CommandSpec) -> Result<ExecOutcome, SandboxError> {
    let bwrap = find_system_bwrap_in_path()
        .ok_or_else(|| SandboxError::Unavailable("bwrap not found in PATH".to_string()))?;
    let masks = masks_for(&spec);
    let argv = build_bwrap_argv(&spec, &masks);
    let label = bwrap.to_string_lossy().into_owned();
    let mut cmd = ProcessCommand::new(&bwrap);
    cmd.args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    capture(cmd, SandboxType::LinuxSeccomp, &label)
}

fn capture(
    mut cmd: ProcessCommand,
    sandbox: SandboxType,
    label: &str,
) -> Result<ExecOutcome, SandboxError> {
    let out = cmd
        .output()
        .map_err(|e| SandboxError::Spawn(format!("{label}: {e}")))?;
    Ok(ExecOutcome {
        status: to_exec_status(&out.status),
        stdout: out.stdout,
        stderr: out.stderr,
        sandbox,
    })
}

fn to_exec_status(status: &std::process::ExitStatus) -> ExecStatus {
    use std::os::unix::process::ExitStatusExt;
    ExecStatus {
        code: status.code(),
        signal: status.signal(),
        success: status.success(),
    }
}
