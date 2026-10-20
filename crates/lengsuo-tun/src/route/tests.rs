//! 路由参数校验的内部单元测试；平台行为见 `tests/route.rs`。

use super::*;

#[test]
fn default_route_requires_explicit_allow_default() {
    let destination = RouteDestination::prefix("0.0.0.0".parse().unwrap(), 0).unwrap();
    let spec = RouteSpec::new(destination, 7, 5);
    assert_eq!(spec.validate(), Err(RouteError::DefaultRouteNotAllowed));
    assert!(spec.with_allow_default().validate().is_ok());

    let v6 = RouteDestination::prefix("::".parse().unwrap(), 0).unwrap();
    assert!(v6.is_default());
    assert_eq!(
        RouteSpec::new(v6, 7, 5).validate(),
        Err(RouteError::DefaultRouteNotAllowed)
    );
}

#[test]
fn metric_and_interface_are_fail_closed() {
    let destination = RouteDestination::host("192.0.2.1".parse().unwrap());
    assert_eq!(
        RouteSpec::new(destination, 0, 5).validate(),
        Err(RouteError::InvalidInterfaceIndex { value: 0 })
    );
    for metric in [0, MAX_METRIC + 1, u32::MAX] {
        assert_eq!(
            RouteSpec::new(destination, 1, metric).validate(),
            Err(RouteError::InvalidMetric {
                value: metric,
                min: MIN_METRIC,
                max: MAX_METRIC,
            })
        );
    }
    assert!(RouteSpec::new(destination, 1, MIN_METRIC)
        .validate()
        .is_ok());
    assert!(RouteSpec::new(destination, 1, MAX_METRIC)
        .validate()
        .is_ok());
}
