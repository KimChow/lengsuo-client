//! 路由安装/撤销的契约测试（默认套件实跑）。
//!
//! Linux 上走非 Windows 桩：`install` 在参数合法时返回 `Unsupported`，参数非法时
//! 返回与 Windows 完全相同的校验错误；`dry_run` 在两个平台都只校验、不碰系统。
//! Windows 上的真实安装/撤销在 `windows_real_install_readback_and_remove`
//! （`#[ignore]`，需管理员）中执行，并用 `netsh ... show route` 读回取证。

use std::net::IpAddr;

use lengsuo_tun::route::{
    RouteDestination, RouteError, RouteGuard, RouteManager, RouteSpec, MAX_METRIC, MIN_METRIC,
};

fn host(address: &str) -> RouteDestination {
    RouteDestination::host(address.parse::<IpAddr>().expect("测试地址应可解析"))
}

#[test]
fn host_route_spec_is_accepted() {
    let destination = host("192.0.2.7");
    assert_eq!(destination.prefix_len(), 32);
    assert_eq!(
        destination.network(),
        "192.0.2.7".parse::<IpAddr>().unwrap()
    );
    assert!(!destination.is_default());

    let spec = RouteSpec::new(destination, 12, 5);
    assert!(!spec.allow_default);
    spec.validate().expect("合法 host 路由");

    let handle = RouteManager::new().dry_run(spec).expect("dry-run 通过");
    assert_eq!(handle.spec(), &spec);
    assert!(handle.is_simulated(), "dry_run 不得伪装成已安装");
    assert!(!handle.is_removed());
}

#[test]
fn ipv6_host_and_prefix_are_supported() {
    let host6 = host("2001:db8::1");
    assert_eq!(host6.prefix_len(), 128);
    let prefix6 =
        RouteDestination::prefix("2001:db8::".parse().unwrap(), 32).expect("合法 v6 前缀");
    assert_eq!(prefix6.prefix_len(), 32);
    assert!(!prefix6.is_default());

    for destination in [host6, prefix6] {
        let spec = RouteSpec::new(destination, 9, 100);
        spec.validate().expect("合法 v6 路由");
        RouteManager::new().dry_run(spec).expect("v6 dry-run");
    }
}

#[test]
fn default_route_requires_explicit_allow_default() {
    let v4_default = RouteDestination::prefix("0.0.0.0".parse().unwrap(), 0).unwrap();
    let v6_default = RouteDestination::prefix("::".parse().unwrap(), 0).unwrap();
    for destination in [v4_default, v6_default] {
        let spec = RouteSpec::new(destination, 7, 5);
        assert_eq!(
            spec.validate(),
            Err(RouteError::DefaultRouteNotAllowed),
            "缺省路由不得静默放行"
        );
        assert_eq!(
            RouteManager::new().dry_run(spec).unwrap_err(),
            RouteError::DefaultRouteNotAllowed
        );
        assert!(spec.with_allow_default().validate().is_ok());
        assert!(RouteManager::new()
            .dry_run(spec.with_allow_default())
            .is_ok());
    }
}

#[test]
fn zero_interface_index_is_rejected() {
    let spec = RouteSpec::new(host("192.0.2.1"), 0, 5);
    assert_eq!(
        spec.validate(),
        Err(RouteError::InvalidInterfaceIndex { value: 0 })
    );
    assert_eq!(
        RouteManager::new().dry_run(spec).unwrap_err(),
        RouteError::InvalidInterfaceIndex { value: 0 }
    );
}

#[test]
fn out_of_range_metrics_are_rejected() {
    for metric in [0, MAX_METRIC + 1, u32::MAX] {
        let spec = RouteSpec::new(host("192.0.2.1"), 1, metric);
        assert_eq!(
            spec.validate(),
            Err(RouteError::InvalidMetric {
                value: metric,
                min: MIN_METRIC,
                max: MAX_METRIC,
            })
        );
    }
    for metric in [MIN_METRIC, 100, MAX_METRIC] {
        assert!(RouteSpec::new(host("192.0.2.1"), 1, metric)
            .validate()
            .is_ok());
    }
}

#[test]
fn non_canonical_prefixes_are_rejected_without_normalising() {
    let host_bits = RouteDestination::prefix("192.0.2.7".parse().unwrap(), 24);
    assert!(matches!(host_bits, Err(RouteError::HostBitsSet { .. })));

    let v6_host_bits = RouteDestination::prefix("2001:db8::1".parse().unwrap(), 64);
    assert!(matches!(v6_host_bits, Err(RouteError::HostBitsSet { .. })));

    let overflow = RouteDestination::prefix("192.0.2.0".parse().unwrap(), 33);
    assert!(matches!(
        overflow,
        Err(RouteError::InvalidPrefix {
            family: "IPv4",
            max: 32,
            ..
        })
    ));
}

#[test]
fn remove_is_idempotent_and_drop_is_safe() {
    let spec = RouteSpec::new(host("192.0.2.9"), 3, 42);
    let mut handle = RouteManager::new().dry_run(spec).expect("dry-run");
    handle.remove().expect("第一次撤销");
    assert!(handle.is_removed());
    handle.remove().expect("第二次撤销必须幂等");
    handle.remove().expect("第三次撤销同样幂等");

    // Drop 路径：句柄与守卫都不得 panic。
    let dropped = RouteManager::new().dry_run(spec).expect("dry-run");
    drop(dropped);
    let guarded = RouteGuard::new(RouteManager::new().dry_run(spec).expect("dry-run"));
    assert_eq!(guarded.spec(), &spec);
    drop(guarded);
}

#[test]
fn guard_release_reports_success() {
    let spec = RouteSpec::new(host("192.0.2.10"), 4, 77);
    let guard = RouteGuard::new(RouteManager::new().dry_run(spec).expect("dry-run"));
    guard.release().expect("显式撤销成功");
}

#[test]
fn install_validates_before_any_platform_call() {
    // 这些参数错误在 Linux 桩与 Windows 真实实现上都必须在系统调用之前返回。
    let cases = [
        (
            RouteSpec::new(host("192.0.2.1"), 0, 5),
            RouteError::InvalidInterfaceIndex { value: 0 },
        ),
        (
            RouteSpec::new(host("192.0.2.1"), 1, 0),
            RouteError::InvalidMetric {
                value: 0,
                min: MIN_METRIC,
                max: MAX_METRIC,
            },
        ),
        (
            RouteSpec::new(
                RouteDestination::prefix("0.0.0.0".parse().unwrap(), 0).unwrap(),
                1,
                5,
            ),
            RouteError::DefaultRouteNotAllowed,
        ),
    ];
    for (spec, expected) in cases {
        assert_eq!(RouteManager::new().install(spec).unwrap_err(), expected);
    }
}

#[cfg(not(windows))]
#[test]
fn stub_install_is_explicitly_unsupported() {
    let spec = RouteSpec::new(host("192.0.2.11"), 2, 5);
    assert_eq!(
        RouteManager::new().install(spec).unwrap_err(),
        RouteError::Unsupported {
            os: std::env::consts::OS,
        },
        "非 Windows 桩不得伪装安装成功"
    );
}

/// 真实安装 → `show route` 读回 → 撤销 → 再读回 → 幂等撤销 → Drop 清理。
///
/// 运行方式（Windows + 管理员）：
/// ```text
/// cargo test -p lengsuo-tun --test route --locked -- --ignored --nocapture
/// ```
/// 默认接口索引为 1（回环伪接口）；如本机不同，可设
/// `LENGSUO_TUN_TEST_INTERFACE_INDEX`。目标取 TEST-NET-1 地址，只新增一条
/// `/32` 路由，不改既有路由；`RouteHandle`/`RouteGuard` 的 `Drop` 负责在断言
/// 失败时清理。
#[cfg(windows)]
#[test]
#[ignore = "Windows + 管理员：真实安装/撤销系统路由并读回取证"]
fn windows_real_install_readback_and_remove() {
    use std::process::Command;

    fn show_routes() -> String {
        let output = Command::new("netsh")
            .args(["interface", "ipv4", "show", "route"])
            .output()
            .expect("启动 netsh show route");
        assert!(output.status.success(), "netsh show route 必须成功");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("--- netsh interface ipv4 show route ---\n{text}");
        text
    }

    let interface_index = std::env::var("LENGSUO_TUN_TEST_INTERFACE_INDEX")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1);
    let spec = RouteSpec::new(host("192.0.2.201"), interface_index, 9999);
    let manager = RouteManager::new();

    let mut handle = manager.install(spec).expect("安装路由（需管理员）");
    let after_add = show_routes();
    assert!(
        after_add.contains("192.0.2.201/32"),
        "show route 必须读回刚安装的 host 路由"
    );

    handle.remove().expect("撤销路由");
    let after_remove = show_routes();
    assert!(
        !after_remove.contains("192.0.2.201/32"),
        "撤销后 show route 不得再出现该路由"
    );
    handle.remove().expect("重复撤销必须幂等");

    // Drop 清理路径：再装一次，交给守卫，Drop 后必须消失。
    let guard = RouteGuard::new(manager.install(spec).expect("再次安装路由"));
    assert!(show_routes().contains("192.0.2.201/32"));
    drop(guard);
    assert!(
        !show_routes().contains("192.0.2.201/32"),
        "RouteGuard::Drop 必须撤销路由"
    );
}
