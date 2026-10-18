//! 纯构造层黄金向量（在 Linux/47 上直接可跑，不依赖 windows-sys 与 Windows 真机）。

use std::cell::Cell;
use std::path::{Path, PathBuf};

use super::*;

/// 无空格/引号/反斜杠的参数原样透传。
#[test]
fn quote_arg_plain_unchanged() {
    assert_eq!(quote_windows_arg("hello"), "hello");
    assert_eq!(quote_windows_arg("/c"), "/c");
    assert_eq!(quote_windows_arg(r"C:\path\to"), r"C:\path\to");
}

/// 空格 → 加引号；空参数 → 空引号对。
#[test]
fn quote_arg_spaces_and_empty() {
    assert_eq!(quote_windows_arg("hello world"), r#""hello world""#);
    assert_eq!(quote_windows_arg(""), r#""""#);
    // 制表符同样触发引用，且内容不被改写。
    assert_eq!(quote_windows_arg("a\tb"), "\"a\tb\"");
}

/// 反斜杠转义：末尾连续反斜杠加倍；引号前连续反斜杠 `2n+1`。
#[test]
fn quote_arg_backslash_and_quote_escaping() {
    // 路径以反斜杠收尾且含空格：收尾反斜杠必须加倍，否则会转义收尾引号。
    assert_eq!(
        quote_windows_arg(r"C:\Program Files\"),
        r#""C:\Program Files\\""#
    );
    // 内嵌双引号：1 个反斜杠 + 引号。
    assert_eq!(quote_windows_arg(r#"say "hi""#), r#""say \"hi\"""#);
    // 引号前的反斜杠已在普通字符处结算（不是"连续"），故只补 1 个转义反斜杠。
    assert_eq!(quote_windows_arg(r#"a\b"c"#), r#""a\b\"c""#);
    // 真正连续的反斜杠（紧邻引号）才走 2n+1：`a\\"` → 引号前 2 个 → 共 5 个反斜杠。
    let trailing = String::from_iter(['a', '\\', '\\', '"']);
    assert_eq!(
        quote_windows_arg(&trailing),
        format!("\"a{}\"\"", "\\".repeat(5))
    );
}

/// 命令行 = argv[0]（program）+ 逐项引用的 args，单空格连接。
#[test]
fn command_line_golden() {
    let args = vec!["/c".to_string(), "echo ok".to_string()];
    assert_eq!(
        build_command_line(Path::new(r"C:\Windows\System32\cmd.exe"), &args),
        r#"C:\Windows\System32\cmd.exe /c "echo ok""#
    );
    // 无参数时只剩 program 本身。
    assert_eq!(
        build_command_line(Path::new(r"C:\Windows\notepad.exe"), &[]),
        r"C:\Windows\notepad.exe"
    );
}

/// UTF-16 编码 + NUL 终止。
#[test]
fn utf16_nul_terminated() {
    assert_eq!(to_utf16_nul("ab"), vec![0x61u16, 0x62, 0]);
    assert_eq!(to_utf16_nul(""), vec![0u16]);
}

/// 环境块：每条 `K=V` 后一个 NUL，整体再补一个 NUL（双层终止）。
#[test]
fn env_block_double_nul_terminated() {
    let entries = vec![
        ("PATH".to_string(), r"C:\bin".to_string()),
        ("LANG".to_string(), "en_US".to_string()),
    ];
    let block = build_env_block(&entries);
    let expected: Vec<u16> = "PATH=C:\\bin\0LANG=en_US\0\0".encode_utf16().collect();
    assert_eq!(block, expected);
    assert_eq!(&block[block.len() - 2..], &[0, 0]);
    // 空表退化为单个 NUL——调用方不得借此继承父环境。
    assert_eq!(build_env_block(&[]), vec![0u16]);
}

/// R8：非白名单键（恶意 env 名）绝不进入派生进程 env；spec.env 覆盖同名进程 env 的值。
#[test]
fn env_allowlist_filters_malicious_names() {
    let process_env = vec![
        ("Path".to_string(), r"C:\Windows\System32".to_string()),
        (
            "SSH_AUTH_SOCK".to_string(),
            r"\\.\pipe\agent-ssh".to_string(),
        ),
        ("SYSTEMROOT".to_string(), r"C:\Windows".to_string()),
    ];
    let spec_env = vec![
        ("LANG".to_string(), "en_US.UTF-8".to_string()),
        (
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "sk-live-secret".to_string(),
        ),
        ("PATH".to_string(), r"C:\tools".to_string()),
    ];
    let got = build_env_entries(&process_env, &spec_env);
    assert_eq!(
        got,
        vec![
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
            // 拼写沿用首次出现者（进程 env 的 "Path"），值取 spec.env。
            ("Path".to_string(), r"C:\tools".to_string()),
            ("SYSTEMROOT".to_string(), r"C:\Windows".to_string()),
        ]
    );
    // 端到端：序列化后秘密与未白名单键名都不可见。
    let serialized = String::from_utf16_lossy(&build_env_block(&got));
    assert!(!serialized.contains("sk-live-secret"));
    assert!(!serialized.contains("AWS_SECRET_ACCESS_KEY"));
    assert!(!serialized.contains("SSH_AUTH_SOCK"));
    assert!(env_key_allowed("systemroot"));
    assert!(!env_key_allowed("HOME"));
}

/// deny 名单：显式凭据子路径 + 展开的 `%USERPROFILE%\.ssh` / `%APPDATA%\gnupg`；普通 root 不进名单。
#[test]
fn deny_targets_include_credentials_only() {
    let spec = CommandSpec {
        program: PathBuf::from(r"C:\Windows\System32\cmd.exe"),
        args: vec![],
        env: vec![],
        cwd: None,
        writable_roots: vec![PathBuf::from("/home/u/.ssh/keys"), PathBuf::from("/repo")],
        read_only_roots: vec![PathBuf::from("/home/u/.gnupg")],
        network: NetworkMode::Allow,
    };
    let targets = deny_acl_targets(
        &spec,
        Some(Path::new("/home/u")),
        Some(Path::new("/home/u/AppData/Roaming")),
    );
    assert!(targets.contains(&PathBuf::from("/home/u/.ssh/keys")));
    assert!(targets.contains(&PathBuf::from("/home/u/.gnupg")));
    assert!(targets.contains(&PathBuf::from("/home/u/.ssh")));
    assert!(targets.contains(&PathBuf::from("/home/u/AppData/Roaming/gnupg")));
    assert!(!targets.contains(&PathBuf::from("/repo")));
    // 未提供环境变量展开时，仍保留 spec 里的显式凭据路径。
    let without_env = deny_acl_targets(&spec, None, None);
    assert_eq!(
        without_env,
        vec![
            PathBuf::from("/home/u/.gnupg"),
            PathBuf::from("/home/u/.ssh/keys")
        ]
    );
}

/// 探测计划：enabled=false 时不执行干跑；enabled=true 时由干跑结果决定。
#[test]
fn probe_plan_gates_on_enabled_and_dry_run() {
    let called = Cell::new(false);
    assert_eq!(
        platform_sandbox_plan(false, || {
            called.set(true);
            true
        }),
        None
    );
    assert!(!called.get(), "enabled=false 时不得执行干跑探测");
    assert_eq!(
        platform_sandbox_plan(true, || true),
        Some(SandboxType::WindowsRestrictedToken)
    );
    assert_eq!(platform_sandbox_plan(true, || false), None);
}

/// preference 语义四组 + 网络 fail-closed（与 linux.rs 的降级链对齐）。
#[test]
fn preference_semantics_and_network_fail_closed() {
    let approve = SandboxPolicy {
        allow_approval_fallback: true,
    };
    let deny = SandboxPolicy {
        allow_approval_fallback: false,
    };

    // 1) Require + 无沙箱 → Unavailable（fail-closed）。
    assert!(matches!(
        resolve_backend(
            SandboxablePreference::Require,
            approve,
            NetworkMode::Allow,
            false
        ),
        Err(SandboxError::Unavailable(_))
    ));
    // 2) Auto + 无沙箱 + 允许审批 → NeedsApproval。
    assert!(matches!(
        resolve_backend(
            SandboxablePreference::Auto,
            approve,
            NetworkMode::Allow,
            false
        ),
        Err(SandboxError::NeedsApproval(_))
    ));
    // 3) Auto + 无沙箱 + 禁审批 → Denied。
    assert!(matches!(
        resolve_backend(SandboxablePreference::Auto, deny, NetworkMode::Allow, false),
        Err(SandboxError::Denied(_))
    ));
    // 4) Forbid → 无隔离直跑（与探测结果、网络模式无关）。
    assert_eq!(
        resolve_backend(
            SandboxablePreference::Forbid,
            SandboxPolicy::default(),
            NetworkMode::Blocked,
            false
        )
        .expect("Forbid 直行"),
        Backend::Unsandboxed
    );

    // 有沙箱 + 网络放行 → 走受限令牌。
    assert_eq!(
        resolve_backend(
            SandboxablePreference::Auto,
            SandboxPolicy::default(),
            NetworkMode::Allow,
            true
        )
        .expect("Allow 网络下可沙箱执行"),
        Backend::RestrictedToken
    );
    // 有沙箱但网络需阻断（Windows 本期无法阻断）→ NeedsApproval，绝不静默放行。
    assert!(matches!(
        resolve_backend(
            SandboxablePreference::Auto,
            SandboxPolicy::default(),
            NetworkMode::Blocked,
            true
        ),
        Err(SandboxError::NeedsApproval(_))
    ));
    assert!(matches!(
        resolve_backend(
            SandboxablePreference::Require,
            approve,
            NetworkMode::Blocked,
            true
        ),
        Err(SandboxError::NeedsApproval(_))
    ));
}
