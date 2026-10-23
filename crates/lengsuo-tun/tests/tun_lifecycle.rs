//! TUN 生命周期的顺序/回滚契约测试（默认套件实跑，无 `#[ignore]`）。
//!
//! 设备与路由都用把调用顺序记进共享 `Arc<Mutex<Vec<String>>>` 的假实现，
//! 断言 = 调用序列（`open` / `install#k` / `revoke#k` / `close`）+ 返回的错误
//! 变体。假路由经 `RouteManager::dry_run` 铸造句柄（`RouteHandle` 只能从
//! `route` 层获得，`dry_run` 不触碰系统）；最后一条用例用**真** `RouteManager`
//! 验证非 Windows 平台 fail-closed 上抛 `Unsupported`。

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use lengsuo_tun::lifecycle::{DeviceOps, LifecycleError, RouteOps, TunLifecycle};
use lengsuo_tun::route::{RouteDestination, RouteError, RouteHandle, RouteManager, RouteSpec};

type Log = Arc<Mutex<Vec<String>>>;

/// 假设备：按开关注入 open/close 失败，全程记录调用顺序。
#[derive(Debug)]
struct FakeDevice {
    log: Log,
    open_fails: bool,
    close_fails: bool,
}

impl DeviceOps for FakeDevice {
    fn open(&mut self) -> Result<(), String> {
        self.log
            .lock()
            .expect("日志锁不应中毒")
            .push("open".to_string());
        if self.open_fails {
            return Err("注入 open 失败".to_string());
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), String> {
        self.log
            .lock()
            .expect("日志锁不应中毒")
            .push("close".to_string());
        if self.close_fails {
            return Err("注入 close 失败".to_string());
        }
        Ok(())
    }
}

/// 构造指定失败开关的假设备（参数名与字段名一致，构造处单行可读）。
fn fake_device(log: &Log, open_fails: bool, close_fails: bool) -> FakeDevice {
    FakeDevice {
        log: log.clone(),
        open_fails,
        close_fails,
    }
}

/// 假路由：句柄经 `dry_run` 铸造（不触碰系统），revoke 按 `spec` 反查下标记录
/// `install#k` / `revoke#k`；可指定某条 install / revoke 注入失败。
#[derive(Debug)]
struct FakeRouter {
    log: Log,
    install_fail_at: Option<usize>,
    revoke_fail_at: Option<usize>,
    next_index: usize,
    installed_specs: Vec<RouteSpec>,
}

impl FakeRouter {
    fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            install_fail_at: None,
            revoke_fail_at: None,
            next_index: 0,
            installed_specs: Vec::new(),
        }
    }
}

impl RouteOps for FakeRouter {
    fn install(&mut self, spec: &RouteSpec) -> Result<RouteHandle, RouteError> {
        let index = self.next_index;
        self.next_index += 1;
        self.log
            .lock()
            .expect("日志锁不应中毒")
            .push(format!("install#{index}"));
        if self.install_fail_at == Some(index) {
            return Err(fake_route_error("install"));
        }
        let handle = RouteManager::new()
            .dry_run(*spec)
            .expect("测试参数应通过 dry-run 校验");
        self.installed_specs.push(*spec);
        Ok(handle)
    }

    fn revoke(&mut self, handle: RouteHandle) -> Result<(), RouteError> {
        let index = self
            .installed_specs
            .iter()
            .position(|spec| *spec == *handle.spec())
            .expect("被撤销的必须是先前装上的路由");
        self.log
            .lock()
            .expect("日志锁不应中毒")
            .push(format!("revoke#{index}"));
        if self.revoke_fail_at == Some(index) {
            return Err(fake_route_error("revoke"));
        }
        let mut handle = handle;
        handle.remove()
    }
}

/// 注入用的可区分路由错误（非权限、非平台问题，避免与真实变体混淆）。
fn fake_route_error(operation: &str) -> RouteError {
    RouteError::CommandFailed {
        operation: "fake",
        code: Some(1),
        message: format!("{operation} 注入失败"),
    }
}

/// 第 `k` 条假路由：`198.51.k.0/24`、非 0 接口、metric 落在 `1..=9999`。
fn spec_at(k: usize) -> RouteSpec {
    let address: IpAddr = format!("198.51.{k}.0").parse().expect("测试地址应可解析");
    let destination = RouteDestination::prefix(address, 24).expect("测试前缀应合法");
    RouteSpec::new(destination, 12, 100)
}

fn specs(count: usize) -> Vec<RouteSpec> {
    (0..count).map(spec_at).collect()
}

fn new_log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

fn snapshot(log: &Log) -> Vec<String> {
    log.lock().expect("日志锁不应中毒").clone()
}

/// 断言完整调用序列（`open` / `install#k` / `revoke#k` / `close`）。
fn expect_sequence(log: &Log, expected: &[&str]) {
    assert_eq!(snapshot(log), expected);
}

fn count_occurrences(log: &Log, label: &str) -> usize {
    snapshot(log).iter().filter(|entry| *entry == label).count()
}

/// `RouteInstall` 的解构断言：下标与回滚失败清单一次验完。
fn assert_route_install(error: LifecycleError, want_index: usize, want_rollback: usize) {
    match error {
        LifecycleError::RouteInstall {
            index,
            rollback_failures,
            ..
        } => {
            assert_eq!(index, want_index, "失败下标应为声明的第 {want_index} 条");
            assert_eq!(
                rollback_failures.len(),
                want_rollback,
                "回滚失败清单长度：{rollback_failures:?}"
            );
        }
        other => panic!("应为 RouteInstall，实得 {other:?}"),
    }
}

#[test]
fn start_opens_device_before_installing_routes() {
    let log = new_log();
    let device = fake_device(&log, false, false);
    let router = FakeRouter::new(&log);
    let lifecycle = TunLifecycle::start(device, router, specs(2)).expect("全部成功时 start 应成功");
    assert_eq!(snapshot(&log), ["open", "install#0", "install#1"]);
    assert_eq!(lifecycle.installed(), 2);
    assert!(!lifecycle.device().open_fails);
    lifecycle.teardown().expect("无注入失败时收尾应成功");
}

#[test]
fn first_route_install_failure_closes_device_and_installs_nothing() {
    let log = new_log();
    let device = fake_device(&log, false, false);
    let mut router = FakeRouter::new(&log);
    router.install_fail_at = Some(0);
    let error =
        TunLifecycle::start(device, router, specs(2)).expect_err("第 0 条注入失败时 start 应失败");
    assert_route_install(error, 0, 0);
    assert_eq!(snapshot(&log), ["open", "install#0", "close"]);
}

#[test]
fn route_install_failure_revokes_prior_routes_in_reverse_then_closes() {
    let log = new_log();
    let device = fake_device(&log, false, false);
    let mut router = FakeRouter::new(&log);
    // 失败下标必须有 >=2 条已装路由才能证明「逆序撤销」；卡片示例序列
    // （index:1 却出现 revoke#1）不可实现：失败的 install 不产生句柄，
    // 按语义规则 2（对已装的 0..k 条逆序 revoke）改为第 2 条失败。
    router.install_fail_at = Some(2);
    let error =
        TunLifecycle::start(device, router, specs(3)).expect_err("第 2 条注入失败时 start 应失败");
    assert_route_install(error, 2, 0);
    expect_sequence(
        &log,
        &[
            "open",
            "install#0",
            "install#1",
            "install#2",
            "revoke#1",
            "revoke#0",
            "close",
        ],
    );
}

#[test]
fn device_open_failure_touches_no_routes_and_does_not_close() {
    let log = new_log();
    let device = fake_device(&log, true, false);
    let router = FakeRouter::new(&log);
    let error =
        TunLifecycle::start(device, router, specs(2)).expect_err("open 注入失败时 start 应失败");
    assert_eq!(
        error,
        LifecycleError::DeviceOpen {
            detail: "注入 open 失败".to_string()
        }
    );
    assert_eq!(snapshot(&log), ["open"]);
}

#[test]
fn teardown_revokes_routes_reverse_then_closes_device() {
    let log = new_log();
    let device = fake_device(&log, false, false);
    let router = FakeRouter::new(&log);
    let lifecycle = TunLifecycle::start(device, router, specs(2)).expect("start 应成功");
    lifecycle.teardown().expect("无注入失败时 teardown 应 Ok");
    expect_sequence(
        &log,
        &[
            "open",
            "install#0",
            "install#1",
            "revoke#1",
            "revoke#0",
            "close",
        ],
    );
}

#[test]
fn teardown_still_closes_device_when_a_route_revoke_fails() {
    let log = new_log();
    let device = fake_device(&log, false, false);
    let mut router = FakeRouter::new(&log);
    router.revoke_fail_at = Some(0);
    let lifecycle = TunLifecycle::start(device, router, specs(2)).expect("start 应成功");
    let error = lifecycle
        .teardown()
        .expect_err("revoke#0 注入失败时 teardown 应失败");
    match error {
        LifecycleError::Teardown {
            route_failures,
            device,
        } => {
            assert_eq!(route_failures.len(), 1, "只注入了 revoke#0 一处失败");
            assert_eq!(device, None, "close 未注入失败，不应上报设备错误");
        }
        other => panic!("应为 Teardown，实得 {other:?}"),
    }
    // revoke 失败后仍须撤销其余路由并关设备。
    expect_sequence(
        &log,
        &[
            "open",
            "install#0",
            "install#1",
            "revoke#1",
            "revoke#0",
            "close",
        ],
    );
}

#[test]
fn teardown_reports_device_close_failure() {
    let log = new_log();
    let device = fake_device(&log, false, true);
    let router = FakeRouter::new(&log);
    let lifecycle = TunLifecycle::start(device, router, specs(1)).expect("start 应成功");
    let error = lifecycle
        .teardown()
        .expect_err("close 注入失败时 teardown 应失败");
    assert_eq!(
        error,
        LifecycleError::Teardown {
            route_failures: Vec::new(),
            device: Some("注入 close 失败".to_string()),
        }
    );
    assert_eq!(snapshot(&log), ["open", "install#0", "revoke#0", "close"]);
}

#[test]
fn drop_is_best_effort_revokes_before_close_and_never_panics() {
    let log = new_log();
    let device = fake_device(&log, false, true);
    let router = FakeRouter::new(&log);
    let lifecycle = TunLifecycle::start(device, router, specs(2)).expect("start 应成功");
    drop(lifecycle); // 不显式 teardown：close 失败也绝不 panic
    let entries = snapshot(&log);
    let close_pos = entries
        .iter()
        .position(|entry| entry == "close")
        .expect("Drop 收尾应尝试 close");
    assert!(
        entries.iter().any(|entry| entry.starts_with("revoke#")),
        "Drop 收尾应先撤销路由"
    );
    for (pos, entry) in entries.iter().enumerate() {
        if entry.starts_with("revoke#") {
            assert!(pos < close_pos, "所有 revoke 必须先于 close：{entries:?}");
        }
    }
    expect_sequence(
        &log,
        &[
            "open",
            "install#0",
            "install#1",
            "revoke#1",
            "revoke#0",
            "close",
        ],
    );
}

#[test]
fn explicit_teardown_then_drop_does_not_double_revoke_or_close() {
    let log = new_log();
    let device = fake_device(&log, false, false);
    let router = FakeRouter::new(&log);
    let lifecycle = TunLifecycle::start(device, router, specs(2)).expect("start 应成功");
    lifecycle.teardown().expect("teardown 应成功");
    // teardown(self) 内部即触发 Drop；此后不得出现第二次 revoke/close。
    for label in ["revoke#0", "revoke#1", "close"] {
        assert_eq!(
            count_occurrences(&log, label),
            1,
            "{label} 应恰好出现一次：{:?}",
            snapshot(&log)
        );
    }
}

#[test]
fn zero_routes_still_opens_and_closes_device() {
    let log = new_log();
    let device = fake_device(&log, false, false);
    let router = FakeRouter::new(&log);
    let lifecycle = TunLifecycle::start(device, router, specs(0)).expect("空路由表也应能启动");
    assert_eq!(lifecycle.installed(), 0);
    lifecycle.teardown().expect("空表收尾应 Ok");
    assert_eq!(snapshot(&log), ["open", "close"]);
}

#[test]
#[cfg(not(windows))]
fn real_route_manager_install_is_fail_closed_on_this_platform() {
    let mut manager = RouteManager::new();
    // 方法语法会命中 inherent install；必须显式经 RouteOps 调用。
    let outcome = RouteOps::install(&mut manager, &spec_at(0));
    assert_eq!(
        outcome.expect_err("非 Windows 桩不得伪装安装成功"),
        RouteError::Unsupported {
            os: std::env::consts::OS
        }
    );
}
