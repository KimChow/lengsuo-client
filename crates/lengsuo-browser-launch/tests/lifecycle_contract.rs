//! 与 `lengsuo-browser-lifecycle` 的**契约边界**测试。
//!
//! `lengsuo-browser-lifecycle` 明确声明「never spawns or kills a process」。
//! 本测试证明两件事：
//!
//! 1. 本 crate 是**唯一**真正 spawn 的地方：状态机只接收**观测到的**身份与
//!    阶段回调，自己从不碰进程；
//! 2. 启动层产出的东西能**直接喂给**状态机：代次、进程身份、资源记账对得上。

mod support;

use std::time::Duration;

use lengsuo_browser_launch::{
    BrowserBinary, EnvironmentId, Generation, LaunchSpec, Launcher, ProbeBudget, ProxyConfig,
    ProxyScheme,
};
use lengsuo_browser_lifecycle::{
    Failure, LifecycleError, Phase, ProcessIdentity, Stage, Supervisor,
};
use support::{fake_browser_path, TempDir};

/// 由**外部**提供的进程身份：PID + 创建随机数。
///
/// 状态机不接受「只有 PID」的收养，所以这里必须有一个非零 nonce。
fn observed_identity(pid: u32) -> ProcessIdentity {
    let mut nonce = [0u8; 16];
    nonce[0] = 0x5A;
    nonce[15] = pid as u8;
    ProcessIdentity::new(pid, nonce).expect("identity must be valid")
}

fn spec_for(root: &TempDir, environment: &str, generation: u64) -> LaunchSpec {
    let proxy = ProxyConfig::empty()
        .with_endpoint(ProxyScheme::Http, "127.0.0.1", 18080)
        .expect("proxy endpoint must be valid");
    LaunchSpec::new(
        BrowserBinary::locate(&fake_browser_path()),
        root.join(environment),
        EnvironmentId::new(environment).unwrap(),
        Generation::new(generation).unwrap(),
        proxy,
        vec![],
        ProbeBudget::new(15_000).unwrap(),
    )
    .unwrap()
    .with_remote_debugging(true)
}

#[test]
fn a_launched_browser_can_be_adopted_by_the_lifecycle_state_machine() {
    let root = TempDir::new("lifecycle");
    let mut launcher = Launcher::new();
    let mut launched = launcher
        .launch(&spec_for(&root, "env-a", 1))
        .expect("launch must succeed");

    // 状态机：从 Stopped 开始，走完授权/安装/网络三段。
    let mut supervisor = Supervisor::new(0);
    assert_eq!(supervisor.phase(), Phase::Stopped);
    let token = supervisor
        .begin_start(
            lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap(),
            1_000,
            5_000,
        )
        .expect("begin_start must be accepted");
    supervisor
        .complete(token, Stage::Authorization, 1_100, 5_000)
        .expect("authorization must be accepted");
    supervisor
        .complete(token, Stage::Install, 1_200, 5_000)
        .expect("install must be accepted");
    supervisor
        .complete(token, Stage::Network, 1_300, 5_000)
        .expect("network must be accepted");
    assert_eq!(supervisor.phase(), Phase::StartingProcess);

    // 启动层把**观测到的**身份交给状态机。
    let identity = observed_identity(launched.process.pid());
    supervisor
        .report_identity(token, identity, 1_400, 5_000)
        .expect("identity must be adopted");
    assert_eq!(supervisor.phase(), Phase::Probing);
    assert_eq!(supervisor.process(), Some(identity));
    assert!(supervisor.resources().process_held());

    // 就绪探测通过 ⇒ 状态机进入 Running。
    supervisor
        .complete(token, Stage::Probe, 1_500, 5_000)
        .expect("probe must be accepted");
    assert_eq!(supervisor.phase(), Phase::Running);

    // 停止 ⇒ 状态机要求外部做真正的回收。
    let (_phase, cleanup) = supervisor
        .stop(token, 1_600)
        .expect("stop must be accepted");
    let cleanup = cleanup.expect("cleanup must be demanded");
    assert_eq!(cleanup.identity(), Some(identity));
    assert!(cleanup.isolation_established());

    // 真正的回收由**启动层**做（状态机自己不碰进程）。
    launched.process.shutdown().expect("shutdown must succeed");
    supervisor
        .cleanup_completed(token, 1_700)
        .expect("cleanup acknowledgement must be accepted");
    assert_eq!(supervisor.phase(), Phase::Stopped);
    assert!(!supervisor.resources().any_held());
}

#[test]
fn a_probe_timeout_is_reported_as_a_lifecycle_failure_and_the_process_is_reaped() {
    // 状态机把「探测超时」记成 Failure::DeadlineExpired。
    let mut supervisor = Supervisor::new(0);
    let token = supervisor
        .begin_start(
            lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap(),
            1_000,
            5_000,
        )
        .unwrap();
    supervisor
        .complete(token, Stage::Authorization, 1_100, 5_000)
        .unwrap();
    supervisor
        .complete(token, Stage::Install, 1_200, 5_000)
        .unwrap();
    supervisor
        .complete(token, Stage::Network, 1_300, 5_000)
        .unwrap();
    let identity = observed_identity(4_242);
    supervisor
        .report_identity(token, identity, 1_400, 5_000)
        .unwrap();
    assert_eq!(supervisor.phase(), Phase::Probing);

    // 探测预算耗尽 ⇒ 状态机失败关闭。
    let outcome = supervisor.deadline_expired(1_400 + 5_000);
    let cleanup = outcome
        .expect("deadline observation must be accepted")
        .expect("deadline must have expired");
    assert_eq!(cleanup.identity(), Some(identity));
    assert_eq!(supervisor.phase(), Phase::Failed);
    assert_eq!(
        supervisor.last_error(),
        Some(LifecycleError::Failure(Failure::DeadlineExpired))
    );
    assert!(supervisor.resources().cleanup_outstanding());

    // 失败之后仍要有人做真正的回收：启动层负责。
    supervisor.cleanup_completed(token, 1_400 + 5_001).unwrap();
    assert_eq!(supervisor.phase(), Phase::Stopped);
}

#[test]
fn the_lifecycle_crate_still_never_spawns_a_process() {
    // 契约边界的**文本**证据：lifecycle 的 crate 文档仍然声明它不碰进程，
    // 且本 crate 没有把进程代码塞进 lifecycle。
    let lifecycle_src =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lengsuo-browser-lifecycle/src");
    let lib = std::fs::read_to_string(lifecycle_src.join("lib.rs"))
        .expect("lifecycle lib.rs must be readable");
    assert!(
        lib.contains("It never spawns or kills a process"),
        "lifecycle 的「不 spawn」契约声明必须仍在"
    );

    // lifecycle 的源码里不得出现任何真正的进程创建。
    let mut spawn_hits = Vec::new();
    for entry in std::fs::read_dir(&lifecycle_src).expect("lifecycle src must be readable") {
        let entry = entry.expect("dir entry must be readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("source must be readable");
        for needle in ["Command::new", ".spawn(", "std::process"] {
            if text.contains(needle) {
                spawn_hits.push(format!("{}: {needle}", path.display()));
            }
        }
    }
    assert!(
        spawn_hits.is_empty(),
        "lifecycle 不得包含进程创建代码：{spawn_hits:?}"
    );
}

#[test]
fn a_launched_browser_keeps_running_until_it_is_explicitly_stopped() {
    let root = TempDir::new("running");
    let mut launcher = Launcher::new();
    let mut launched = launcher
        .launch(&spec_for(&root, "env-a", 1))
        .expect("launch must succeed");
    let pid = launched.process.pid();

    // 存活一段时间，确认不是「起来就退」。
    std::thread::sleep(Duration::from_millis(300));
    assert!(launched.process.try_exit_status().is_none());
    assert!(process_alive(pid), "浏览器进程应当还活着");

    launched.process.shutdown().expect("shutdown must succeed");
    assert!(support::wait_until(Duration::from_secs(10), || {
        !process_alive(pid)
    }));
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
