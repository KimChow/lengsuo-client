//! 黄金向量与语义测试：bwrap argv 确定性、安全基线剔除、探测注入、偏好降级链。
//! 真实 bwrap smoke 见 `smoke_bwrap_exit_code`（#[ignore]，正常测试不跑）。

#![cfg(target_os = "linux")]
#![allow(clippy::type_complexity)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use agent_sandbox::{
    build_bwrap_argv, detect_sandbox_with, env_passlist, find_bwrap_in_path_with, is_denied_path,
    masks_for, run_sandboxed_with, CommandSpec, NetworkMode, SandboxError, SandboxPolicy,
    SandboxProbe, SandboxType, SandboxablePreference,
};

struct FakeProbe {
    bwrap: bool,
    landlock: bool,
}

impl SandboxProbe for FakeProbe {
    fn bwrap_available(&self) -> bool {
        self.bwrap
    }
    fn landlock_available(&self) -> bool {
        self.landlock
    }
}

fn base_spec() -> CommandSpec {
    CommandSpec {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_string(), "exit 3".to_string()],
        env: vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("SECRET_TOKEN".to_string(), "hunter2".to_string()),
            ("HOME".to_string(), "/home/tester".to_string()),
        ],
        cwd: Some(PathBuf::from("/work/dir")),
        writable_roots: vec![PathBuf::from("/repo")],
        read_only_roots: vec![PathBuf::from("/etc/ssl")],
        network: NetworkMode::Blocked,
    }
}

/// 冻结完整 argv 逐项相等；任何 flag 漂移都会让此测试失败。
#[test]
fn golden_bwrap_argv_full_equality() {
    let spec = base_spec();
    let masks: Vec<PathBuf> = vec![];
    let argv = build_bwrap_argv(&spec, &masks);
    assert_eq!(
        argv,
        vec![
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
            "--unshare-net",
            "--ro-bind",
            "/etc/ssl",
            "/etc/ssl",
            "--bind",
            "/repo",
            "/repo",
            "--chdir",
            "/work/dir",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/home/tester",
            "--cap-drop",
            "ALL",
            "--",
            "/bin/sh",
            "-c",
            "exit 3",
        ]
    );
}

/// R8：非白名单 env（SECRET_TOKEN）绝不透传进 argv。
#[test]
fn golden_env_passlist_scrubs_secrets() {
    let spec = base_spec();
    let argv = build_bwrap_argv(&spec, &[]);
    let joined = argv.join("\n");
    assert!(!joined.contains("hunter2"));
    assert!(!joined.contains("SECRET_TOKEN"));
    assert!(joined.contains("--clearenv"));
    // 独立验证清洗函数本身。
    let scrubbed = env_passlist(&spec.env);
    assert_eq!(
        scrubbed,
        vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("HOME".to_string(), "/home/tester".to_string()),
        ]
    );
}

/// .ssh/.gnupg 即使显式列在 writable_roots 也绝不进入 --bind/--ro-bind，
/// 只能以 --tmpfs 遮蔽出现。
#[test]
fn golden_credentials_never_bound() {
    let mut spec = base_spec();
    spec.writable_roots.push(PathBuf::from("/home/tester/.ssh"));
    spec.read_only_roots
        .push(PathBuf::from("/home/tester/.gnupg"));
    let masks = vec![
        PathBuf::from("/home/tester/.ssh"),
        PathBuf::from("/home/tester/.gnupg"),
    ];
    let argv = build_bwrap_argv(&spec, &masks);

    // 逐条扫描：没有任何 --bind/--ro-bind 的参数指向凭据路径。
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "--bind" || argv[i] == "--ro-bind" {
            let src = &argv[i + 1];
            assert!(
                !is_denied_path(Path::new(src)),
                "凭据路径 {src} 出现在绑定列表，违反安全基线"
            );
            i += 3;
        } else {
            i += 1;
        }
    }
    // 每个凭据路径都以 --tmpfs <path> 成对出现（遮蔽而非绑定）。
    for cred in ["/home/tester/.ssh", "/home/tester/.gnupg"] {
        let masked = argv.windows(2).any(|w| w[0] == "--tmpfs" && w[1] == cred);
        assert!(masked, "{cred} 未被 --tmpfs 遮蔽");
    }
    // 无 cwd 时不出现 --chdir。
    let mut s2 = base_spec();
    s2.cwd = None;
    assert!(!build_bwrap_argv(&s2, &[]).contains(&"--chdir".to_string()));
}

/// NetworkMode::Blocked → --unshare-net 出现；Allow → 不出现。
#[test]
fn golden_network_mode_unshare_net() {
    let blocked = build_bwrap_argv(&base_spec(), &[]);
    assert!(blocked.iter().any(|a| a == "--unshare-net"));

    let mut allowed = base_spec();
    allowed.network = NetworkMode::Allow;
    let argv = build_bwrap_argv(&allowed, &[]);
    assert!(!argv.iter().any(|a| a == "--unshare-net"));
}

/// masks_for：显式列出的凭据被收集，且返回项全部命中 denylist；缓存根不被误判。
#[test]
fn masks_for_collects_only_credentials() {
    let mut spec = base_spec();
    spec.writable_roots.push(PathBuf::from("/home/u/.ssh"));
    spec.writable_roots.push(PathBuf::from("/home/u/.cargo"));
    let masks = masks_for(&spec);
    assert!(masks.contains(&PathBuf::from("/home/u/.ssh")));
    assert!(masks.iter().all(|m| is_denied_path(m)));
    assert!(!masks.contains(&PathBuf::from("/home/u/.cargo")));
}

/// 探测注入：有 bwrap → LinuxSeccomp；无 bwrap（含 landlock TODO 分支）→ None。
#[test]
fn detect_with_probe_branches() {
    assert_eq!(
        detect_sandbox_with(&FakeProbe {
            bwrap: true,
            landlock: false
        }),
        Some(SandboxType::LinuxSeccomp)
    );
    assert_eq!(
        detect_sandbox_with(&FakeProbe {
            bwrap: false,
            landlock: false
        }),
        None
    );
    // landlock 路径当前留 TODO：即便探测说有，也只返回 None（不假装支持）。
    assert_eq!(
        detect_sandbox_with(&FakeProbe {
            bwrap: false,
            landlock: true
        }),
        None
    );
}

/// PATH 查找注入：命中可执行 bwrap。
#[test]
fn find_bwrap_in_path_injected() {
    let path = OsString::from("/nonexistent:/opt/sbx/bin");
    let found = find_bwrap_in_path_with(&path, |p| p == Path::new("/opt/sbx/bin/bwrap"));
    assert_eq!(found, Some(PathBuf::from("/opt/sbx/bin/bwrap")));
    let none = find_bwrap_in_path_with(&path, |_| false);
    assert_eq!(none, None);
}

/// preference 语义（探测注入，不起真实进程；Forbid 用 /bin/true 直跑验证）。
#[test]
fn preference_semantics() {
    // Require + 无沙箱 → Err(Unavailable)（fail-closed）。
    let r = run_sandboxed_with(
        &FakeProbe {
            bwrap: false,
            landlock: false,
        },
        base_spec(),
        SandboxablePreference::Require,
        SandboxPolicy {
            allow_approval_fallback: true,
        },
    );
    assert!(matches!(r, Err(SandboxError::Unavailable(_))));

    // Auto + 无沙箱 + 允许审批 → Err(NeedsApproval)。
    let r = run_sandboxed_with(
        &FakeProbe {
            bwrap: false,
            landlock: false,
        },
        base_spec(),
        SandboxablePreference::Auto,
        SandboxPolicy {
            allow_approval_fallback: true,
        },
    );
    assert!(matches!(r, Err(SandboxError::NeedsApproval(_))));

    // Auto + 无沙箱 + 禁审批 → Err(Denied)。
    let r = run_sandboxed_with(
        &FakeProbe {
            bwrap: false,
            landlock: false,
        },
        base_spec(),
        SandboxablePreference::Auto,
        SandboxPolicy {
            allow_approval_fallback: false,
        },
    );
    assert!(matches!(r, Err(SandboxError::Denied(_))));

    // Forbid → 直行（非沙箱执行 /bin/true，与探测无关）。
    let spec = CommandSpec {
        program: PathBuf::from("/bin/true"),
        args: vec![],
        env: vec![],
        cwd: None,
        writable_roots: vec![],
        read_only_roots: vec![],
        network: NetworkMode::Blocked,
    };
    let out = run_sandboxed_with(
        &FakeProbe {
            bwrap: false,
            landlock: false,
        },
        spec,
        SandboxablePreference::Forbid,
        SandboxPolicy::default(),
    )
    .expect("Forbid should run");
    assert_eq!(out.sandbox, SandboxType::None);
    assert!(out.status.success);
    assert_eq!(out.status.code, Some(0));
}

/// Forbid 的非沙箱直跑仍按 R8 清洗 env：秘密不进子进程。
#[test]
fn forbid_run_scrubs_env() {
    let spec = CommandSpec {
        program: PathBuf::from("/usr/bin/env"),
        args: vec![],
        env: vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("SECRET_TOKEN".to_string(), "hunter2".to_string()),
        ],
        cwd: None,
        writable_roots: vec![],
        read_only_roots: vec![],
        network: NetworkMode::Blocked,
    };
    let out = run_sandboxed_with(
        &FakeProbe {
            bwrap: true,
            landlock: false,
        },
        spec,
        SandboxablePreference::Forbid,
        SandboxPolicy::default(),
    )
    .expect("env should run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("hunter2"),
        "secret leaked into child env:\n{stdout}"
    );
}

/// 真实 smoke（47 环境）：用实际 bwrap 跑 `--ro-bind / / --uid 0 --gid 0 --unshare-net
/// /bin/sh -c "exit 3"` 断言退出码 3 透传。#[ignore]——正常测试不跑，需特权环境手动
/// `cargo test -- --ignored`。
#[test]
#[ignore = "requires privileged bwrap (user namespaces) and the real binary"]
fn smoke_bwrap_exit_code() {
    if agent_sandbox::find_system_bwrap_in_path().is_none() {
        eprintln!("bwrap not present; skipping smoke");
        return;
    }
    let spec = CommandSpec {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_string(), "exit 3".to_string()],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: None,
        writable_roots: vec![],
        read_only_roots: vec![],
        network: NetworkMode::Blocked,
    };
    let out = run_sandboxed_with(
        &agent_sandbox::SystemProbe,
        spec,
        SandboxablePreference::Require,
        SandboxPolicy::default(),
    )
    .expect("bwrap smoke should run under privileged host");
    assert_eq!(out.sandbox, SandboxType::LinuxSeccomp);
    assert_eq!(
        out.status.code,
        Some(3),
        "exit code 3 must propagate through bwrap"
    );
    assert!(!out.status.success);
}
