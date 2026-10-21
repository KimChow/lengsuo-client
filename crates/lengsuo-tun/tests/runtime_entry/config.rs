//! 配置校验与命令行解析的用例。
//!
//! 本组的全部断言口径是**fail-closed**：缺字段、非法数值、非法前缀都必须**显式
//! 报错**，不得静默套用默认值。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::runtime_entry::{parse_args, ConfigError, RawConfig, RouteRule, MAX_MTU, MIN_MTU};

use crate::support::route_rule;

/// 缺必填字段 ⇒ 显式报错，**不是**默默用默认值。
#[test]
fn missing_required_fields_are_rejected() {
    // 缺设备名。
    let error = RawConfig {
        mtu: Some(1500),
        ..RawConfig::default()
    }
    .into_config()
    .expect_err("缺设备名必须报错");
    assert_eq!(error, ConfigError::Missing { field: "设备名" });

    // 缺 MTU。
    let error = RawConfig {
        device_name: Some("lstest0".to_string()),
        ..RawConfig::default()
    }
    .into_config()
    .expect_err("缺 MTU 必须报错");
    assert_eq!(error, ConfigError::Missing { field: "MTU" });
}

/// 非法 MTU ⇒ 显式报错。
#[test]
fn invalid_mtu_is_rejected() {
    let error = RawConfig {
        device_name: Some("lstest0".to_string()),
        mtu: Some(100),
        ..RawConfig::default()
    }
    .into_config()
    .expect_err("MTU 越界必须报错");
    assert_eq!(
        error,
        ConfigError::InvalidMtu {
            value: 100,
            min: MIN_MTU,
            max: MAX_MTU
        }
    );
}

/// MTU 的上下界本身必须被接受。
#[test]
fn mtu_bounds_are_accepted() {
    for mtu in [MIN_MTU, MAX_MTU] {
        let config = RawConfig {
            device_name: Some("lstest0".to_string()),
            mtu: Some(mtu),
            ..RawConfig::default()
        }
        .into_config()
        .expect("边界 MTU 应被接受");
        assert_eq!(config.mtu, mtu);
    }
}

/// 非法路由前缀（带主机位）⇒ 显式报错，且**不进路由表**。
#[test]
fn invalid_route_prefix_is_rejected() {
    let error = RawConfig {
        device_name: Some("lstest0".to_string()),
        mtu: Some(1500),
        routes: vec![RouteRule {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            prefix_len: 24,
            interface_index: 7,
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        }],
        ..RawConfig::default()
    }
    .into_config()
    .expect_err("带主机位的前缀必须报错");
    assert!(matches!(error, ConfigError::InvalidRoutePrefix { .. }));
}

/// 出接口索引为 0 ⇒ 显式报错。
#[test]
fn zero_interface_index_is_rejected() {
    let error = RawConfig {
        device_name: Some("lstest0".to_string()),
        mtu: Some(1500),
        routes: vec![RouteRule {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            interface_index: 0,
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        }],
        ..RawConfig::default()
    }
    .into_config()
    .expect_err("接口索引 0 必须报错");
    assert_eq!(error, ConfigError::InvalidInterfaceIndex { value: 0 });
}

/// 前缀与源地址不同族 ⇒ 显式报错。
#[test]
fn route_family_mismatch_is_rejected() {
    let error = RawConfig {
        device_name: Some("lstest0".to_string()),
        mtu: Some(1500),
        routes: vec![RouteRule {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            interface_index: 7,
            source: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        }],
        ..RawConfig::default()
    }
    .into_config()
    .expect_err("不同族必须报错");
    assert!(matches!(error, ConfigError::RouteFamilyMismatch { .. }));
}

/// 设备名过长 ⇒ 显式报错（Linux 的 `IFNAMSIZ` 只有 16 字节）。
#[test]
fn overly_long_device_name_is_rejected() {
    let error = RawConfig {
        device_name: Some("x".repeat(16)),
        mtu: Some(1500),
        ..RawConfig::default()
    }
    .into_config()
    .expect_err("设备名过长必须报错");
    assert!(matches!(error, ConfigError::InvalidArgument { .. }));
}

/// 命令行解析：非 `key=value`、未知键、非法数值都显式报错。
#[test]
fn malformed_command_line_is_rejected() {
    assert!(parse_args(["device_name"]).is_err());
    assert!(parse_args(["nope=1"]).is_err());
    assert!(parse_args(["mtu=abc"]).is_err());
    assert!(parse_args(["route=10.0.0.0/24"]).is_err());
    assert!(parse_args(["route=10.0.0.0/24,7"]).is_err());
    assert!(parse_args(["route=10.0.0.0/24,7,10.0.0.1"]).is_ok());
}

/// 合法命令行被解析成配置，且必填字段仍然必填。
#[test]
fn command_line_parses_into_a_valid_config() {
    let raw = parse_args([
        "device_name=lstest0",
        "mtu=1400",
        "route=10.0.0.0/24,7,10.0.0.1",
    ])
    .expect("应可解析");
    let config = raw.into_config().expect("应可转成配置");
    assert_eq!(config.device_name, "lstest0");
    assert_eq!(config.mtu, 1400);
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.routes[0].interface_index, 7);
    assert_eq!(
        config.routes[0].source,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
}

/// 路由表按最长前缀匹配查表；查不到 ⇒ `None`（调用方 fail-closed）。
#[test]
fn route_table_is_a_longest_prefix_match_table() {
    let config = crate::support::config();
    let table = config.route_table().expect("路由表应可构造");
    assert_eq!(table.len(), 1);
    let hit = table.lookup("10.0.0.9".parse().unwrap()).expect("应命中");
    assert_eq!(hit.interface_index, 7);
    assert_eq!(hit.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    // 超出表范围：查不到 ⇒ 调用方拒绝，不走默认路由。
    assert!(table.lookup("192.0.2.1".parse().unwrap()).is_none());
    // 地址族不同一律不匹配。
    assert!(table.lookup("::1".parse().unwrap()).is_none());
}

/// 规则本身也走同一条校验路径（不靠 `into_config` 单独把关）。
#[test]
fn route_rule_validation_is_reusable() {
    assert!(route_rule().validate().is_ok());
    let mut bad = route_rule();
    bad.interface_index = 0;
    assert_eq!(
        bad.validate().expect_err("接口索引 0 必须被拒"),
        ConfigError::InvalidInterfaceIndex { value: 0 }
    );
}
