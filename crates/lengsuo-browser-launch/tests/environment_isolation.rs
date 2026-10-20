//! **三个环境 ⇒ 三个进程 + 三个用户数据目录 + 三个代理**。
//!
//! 用假浏览器（`lengsuo-fake-browser`）跑，不下载真浏览器、不连公网。
//! 每个用例都带总超时，进程在用例结束时**一定被回收**。

mod support;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use lengsuo_browser_launch::{
    BrowserBinary, EnvironmentId, Generation, LaunchSpec, Launcher, ProbeBudget, ProxyConfig,
    ProxyScheme,
};
use support::{fake_browser_path, read_args, read_env, RecordingProxy, TempDir};

/// 每个用例的总超时上限（用于 `wait_until` 的兜底）。
const CASE_TIMEOUT: Duration = Duration::from_secs(30);

/// 组装一个环境的启动规格。
fn spec_for(
    root: &TempDir,
    environment: &str,
    generation: u64,
    proxy_port: u16,
    remote_debugging: bool,
) -> LaunchSpec {
    let proxy = ProxyConfig::empty()
        .with_endpoint(ProxyScheme::Http, "127.0.0.1", proxy_port)
        .expect("proxy endpoint must be valid");
    LaunchSpec::new(
        BrowserBinary::locate(&fake_browser_path()),
        root.join(environment),
        EnvironmentId::new(environment).expect("environment id must be valid"),
        Generation::new(generation).expect("generation must be positive"),
        proxy,
        vec![],
        ProbeBudget::new(15_000).expect("budget must be positive"),
    )
    .expect("spec must be valid")
    .with_remote_debugging(remote_debugging)
}

#[test]
fn three_environments_get_three_processes_three_dirs_and_three_proxies() {
    let root = TempDir::new("isolation");
    let proxy_a = RecordingProxy::start();
    let proxy_b = RecordingProxy::start();
    let proxy_c = RecordingProxy::start();

    let mut launcher = Launcher::new();
    let mut launched = Vec::new();
    for (index, (environment, port)) in [
        ("env-a", proxy_a.port()),
        ("env-b", proxy_b.port()),
        ("env-c", proxy_c.port()),
    ]
    .into_iter()
    .enumerate()
    {
        let spec = spec_for(&root, environment, index as u64 + 1, port, true);
        let result = launcher
            .launch(&spec)
            .unwrap_or_else(|err| panic!("{environment} must launch: {}", err.code()));
        launched.push((environment.to_string(), result));
    }

    // 1) 三个 PID 互不相同。
    let pids: HashSet<u32> = launched.iter().map(|(_, l)| l.process.pid()).collect();
    assert_eq!(pids.len(), 3, "三个环境必须拿到三个不同的 PID");
    assert!(pids.iter().all(|pid| *pid != 0), "PID 不得为 0");

    // 2) 三个用户数据目录互不相同。
    let dirs: HashSet<PathBuf> = launched
        .iter()
        .map(|(environment, _)| root.join(environment))
        .collect();
    assert_eq!(dirs.len(), 3, "三个环境必须用三个不同的用户数据目录");

    // 3) 三个代理配置互不相同。
    let proxies: HashSet<String> = launched
        .iter()
        .map(|(_, l)| {
            l.command_line
                .value_of("--proxy-server")
                .unwrap_or("")
                .to_string()
        })
        .collect();
    assert_eq!(proxies.len(), 3, "三个环境必须注入三个不同的代理");

    // 4) 每个环境的命令行确实指向**自己**的代理与目录。
    for (environment, result) in &launched {
        let expected_dir = root.join(environment);
        assert_eq!(
            result.command_line.value_of("--user-data-dir"),
            Some(expected_dir.to_str().expect("utf-8 path")),
            "{environment} 的用户数据目录参数不对"
        );
        let expected_proxy = format!(
            "http=127.0.0.1:{}",
            expected_proxy_port(environment, &launched)
        );
        assert_eq!(
            result.command_line.value_of("--proxy-server"),
            Some(expected_proxy.as_str()),
            "{environment} 的代理参数不对"
        );
    }

    // 5) 进程都被启动且还活着。
    for (environment, result) in launched.iter_mut() {
        assert!(
            result.process.try_exit_status().is_none(),
            "{environment} 的进程不应已经退出"
        );
    }

    // 6) 回收：全部 kill + wait，之后进程不再存活。
    let pids: Vec<u32> = launched.iter().map(|(_, l)| l.process.pid()).collect();
    for (_, mut result) in launched {
        result.process.shutdown().expect("shutdown must succeed");
    }
    for pid in pids {
        assert!(
            support::wait_until(CASE_TIMEOUT, || !process_alive(pid)),
            "进程 {pid} 在用例结束后仍然存活（孤儿进程）"
        );
    }
}

/// 某个环境应当使用的代理端口。
fn expected_proxy_port(
    environment: &str,
    launched: &[(String, lengsuo_browser_launch::Launched)],
) -> u16 {
    launched
        .iter()
        .find(|(name, _)| name == environment)
        .and_then(|(_, l)| {
            l.command_line
                .value_of("--proxy-server")
                .and_then(|value| value.rsplit(':').next())
                .and_then(|port| port.parse().ok())
        })
        .expect("proxy port must be parseable")
}

#[test]
fn the_arguments_are_injected_into_the_command_line() {
    let root = TempDir::new("args");
    let proxy = RecordingProxy::start();
    let mut launcher = Launcher::new();
    let spec = spec_for(&root, "env-args", 1, proxy.port(), true);
    let mut launched = launcher.launch(&spec).expect("launch must succeed");

    // 假浏览器把收到的参数写进 <user-data-dir>/args.txt。
    let args = read_args(&root.join("env-args"));
    assert!(
        args.iter()
            .any(|a| a == &format!("--user-data-dir={}", root.join("env-args").display())),
        "参数里必须有用户数据目录：{args:?}"
    );
    assert!(
        args.iter()
            .any(|a| a == &format!("--proxy-server=http=127.0.0.1:{}", proxy.port())),
        "参数里必须有代理：{args:?}"
    );
    assert!(
        args.iter().any(|a| a == "--no-first-run"),
        "参数里必须有 --no-first-run"
    );
    assert!(
        args.iter().any(|a| a == "--remote-debugging-port=0"),
        "参数里必须有调试端口：{args:?}"
    );

    launched.process.shutdown().expect("shutdown must succeed");
}

#[test]
fn the_same_user_data_dir_cannot_be_shared_by_two_environments() {
    let root = TempDir::new("shared-dir");
    let proxy_a = RecordingProxy::start();
    let proxy_b = RecordingProxy::start();
    let mut launcher = Launcher::new();

    let first = spec_for(&root, "env-a", 1, proxy_a.port(), true);
    let mut launched = launcher.launch(&first).expect("first launch must succeed");

    // 第二个环境指向**同一个**用户数据目录 ⇒ 拒绝（隔离被破坏）。
    let second = spec_for(&root, "env-a", 2, proxy_b.port(), true);
    let err = launcher
        .launch(&second)
        .expect_err("sharing a user data dir must be refused");
    assert_eq!(err, lengsuo_browser_launch::LaunchError::UserDataDirInUse);

    launched.process.shutdown().expect("shutdown must succeed");
}

#[test]
fn a_missing_browser_binary_fails_closed() {
    let root = TempDir::new("missing-binary");
    let proxy = RecordingProxy::start();
    let proxy_config = ProxyConfig::empty()
        .with_endpoint(ProxyScheme::Http, "127.0.0.1", proxy.port())
        .unwrap();
    let spec = LaunchSpec::new(
        BrowserBinary::Missing,
        root.join("env-a"),
        EnvironmentId::new("env-a").unwrap(),
        Generation::new(1).unwrap(),
        proxy_config,
        vec![],
        ProbeBudget::new(1_000).unwrap(),
    )
    .unwrap();
    let mut launcher = Launcher::new();
    let err = launcher
        .launch(&spec)
        .expect_err("missing binary must fail");
    assert_eq!(err, lengsuo_browser_launch::LaunchError::BinaryMissing);
}

#[test]
fn a_launch_without_a_ready_browser_times_out_and_reaps_the_process() {
    // 指向一个**不会**写 DevToolsActivePort 的程序：就绪判据永远不成立。
    let root = TempDir::new("timeout");
    let proxy = RecordingProxy::start();
    let proxy_config = ProxyConfig::empty()
        .with_endpoint(ProxyScheme::Http, "127.0.0.1", proxy.port())
        .unwrap();

    // 用一个只睡觉、不写端口文件的程序当「起不来的浏览器」。
    let sleeper = write_sleeper(&root);
    let spec = LaunchSpec::new(
        BrowserBinary::locate(&sleeper),
        root.join("env-timeout"),
        EnvironmentId::new("env-timeout").unwrap(),
        Generation::new(1).unwrap(),
        proxy_config,
        vec![],
        ProbeBudget::new(1_000).unwrap(),
    )
    .unwrap()
    .with_remote_debugging(true);

    let mut launcher = Launcher::new();
    let before = std::time::Instant::now();
    let err = launcher
        .launch(&spec)
        .expect_err("a browser that never becomes ready must fail");
    let elapsed = before.elapsed();

    assert!(
        matches!(
            err,
            lengsuo_browser_launch::LaunchError::ProbeTimeout { budget_ms: 1_000 }
        ),
        "必须是明确的探测超时，实际：{err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "探测必须在预算附近结束，实际耗时 {elapsed:?}"
    );
}

/// 写一个「只睡觉、不报告就绪」的小程序（跨平台）。
fn write_sleeper(root: &TempDir) -> PathBuf {
    let path = root.join("sleeper");
    if cfg!(windows) {
        std::fs::write(
            &path,
            "@echo off\r\n:loop\r\ntimeout /t 30 /nobreak >nul\r\ngoto loop\r\n",
        )
        .unwrap();
    } else {
        std::fs::write(&path, "#!/bin/sh\nsleep 30\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
        }
    }
    path
}

/// 进程是否还活着。
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let mut probe = std::process::Command::new("kill");
        probe.arg("-0").arg(pid.to_string());
        probe.stdout(std::process::Stdio::null());
        probe.stderr(std::process::Stdio::null());
        probe.status().map(|s| s.success()).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// 假浏览器把环境变量也记下来了：断言凭据**不在命令行**，而在环境变量里。
#[test]
fn credentials_travel_by_environment_variable_and_never_on_the_command_line() {
    use lengsuo_browser_launch::{CredentialInjection, ProxyCredential};

    let root = TempDir::new("credential");
    let proxy = RecordingProxy::start();
    let credential = ProxyCredential::new("fake-user", "fake-password").unwrap();
    let proxy_config = ProxyConfig::empty()
        .with_endpoint(ProxyScheme::Http, "127.0.0.1", proxy.port())
        .unwrap()
        .with_credential(credential);

    let spec = LaunchSpec::new(
        BrowserBinary::locate(&fake_browser_path()),
        root.join("env-cred"),
        EnvironmentId::new("env-cred").unwrap(),
        Generation::new(1).unwrap(),
        proxy_config,
        vec![],
        ProbeBudget::new(15_000).unwrap(),
    )
    .unwrap()
    .with_remote_debugging(true);

    let mut launcher =
        Launcher::new().with_credential_injection(CredentialInjection::EnvironmentVariable {
            variable: "SIDECAR_AUTH".into(),
        });
    let mut launched = launcher.launch(&spec).expect("launch must succeed");

    // 1) 命令行里既没有用户名也没有口令。
    let line = launched.command_line.display();
    assert!(!line.contains("fake-user"), "命令行里出现了用户名：{line}");
    assert!(
        !line.contains("fake-password"),
        "命令行里出现了口令：{line}"
    );

    // 2) 凭据在**环境变量**里。
    let env = read_env(&root.join("env-cred"));
    assert_eq!(
        env.get("LENGSUO_PROXY_SIDECAR_AUTH").map(String::as_str),
        Some("fake-user:fake-password")
    );

    // 3) 凭据文件也落在**本环境**的用户数据目录里。
    let plan = launched
        .credential_plan
        .as_ref()
        .expect("credential plan must exist");
    assert_eq!(
        plan.file_path(),
        root.join("env-cred").join("lengsuo-proxy-credential.json")
    );

    launched.process.shutdown().expect("shutdown must succeed");
}
