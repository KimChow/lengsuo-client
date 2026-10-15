//! 路由核心的真实行为测试：同站点 A/B/C 独立出口、离线设备、代次失效与重建。
//!
//! A/B/C 是三个彼此独立的浏览器环境身份；域名不出现在任何 API 签名里，
//! 因此本文件同时证明「域名不参与身份判定」。
//!
//! 代次耗尽与「绑定指向离线设备」属于内部不变量的防御分支，
//! 放在 `src/router.rs` 的单元测试里直接构造状态验证。

use lengsuo_environment::{Binding, DeviceId, EnvironmentId, Lease, Router, RouterError};

const ENV_A: EnvironmentId = EnvironmentId(1);
const ENV_B: EnvironmentId = EnvironmentId(2);
const ENV_C: EnvironmentId = EnvironmentId(3);

const DEV_1: DeviceId = DeviceId(10);
const DEV_2: DeviceId = DeviceId(20);
const DEV_3: DeviceId = DeviceId(30);

/// 上线设备并绑定环境，返回签发的 lease。
fn bind_online(router: &mut Router, env: EnvironmentId, dev: DeviceId) -> Lease {
    assert_eq!(router.set_online(dev, true), 0);
    router.bind(env, dev).expect("在线设备绑定应成功")
}

/// 同一个网站域名下，A/B/C 三个环境必须解析到互不相同的出口设备。
#[test]
fn same_site_three_environments_get_independent_egress_devices() {
    let mut router = Router::new().unwrap();
    let lease_a = bind_online(&mut router, ENV_A, DEV_1);
    let lease_b = bind_online(&mut router, ENV_B, DEV_2);
    let lease_c = bind_online(&mut router, ENV_C, DEV_3);

    let resolved_a = router.resolve(ENV_A).expect("A 应可解析");
    let resolved_b = router.resolve(ENV_B).expect("B 应可解析");
    let resolved_c = router.resolve(ENV_C).expect("C 应可解析");

    assert_eq!(resolved_a, lease_a);
    assert_eq!(resolved_b, lease_b);
    assert_eq!(resolved_c, lease_c);
    assert_eq!(resolved_a.device, DEV_1);
    assert_eq!(resolved_b.device, DEV_2);
    assert_eq!(resolved_c.device, DEV_3);
    assert_ne!(resolved_a.device, resolved_b.device);
    assert_ne!(resolved_b.device, resolved_c.device);
    assert_ne!(resolved_a.device, resolved_c.device);
    // 三次成功绑定各自消耗一个全局代次，互不共享。
    assert!(lease_a.epoch < lease_b.epoch && lease_b.epoch < lease_c.epoch);
    // 一个身份的撤销不影响另外两个，也不会给出默认出口。
    assert_eq!(
        router.remove(ENV_A),
        Some(Binding {
            device: DEV_1,
            epoch: lease_a.epoch
        })
    );
    assert_eq!(router.resolve(ENV_B).unwrap().device, DEV_2);
    assert_eq!(router.resolve(ENV_C).unwrap().device, DEV_3);
    assert!(matches!(
        router.resolve(ENV_A),
        Err(RouterError::UnknownEnvironment(ENV_A))
    ));
}

/// 从未注册的环境身份必须被拒绝。
#[test]
fn unknown_environment_is_rejected() {
    let mut router = Router::new().unwrap();
    assert_eq!(router.binding_count(), 0);
    assert!(matches!(
        router.resolve(EnvironmentId(999)),
        Err(RouterError::UnknownEnvironment(EnvironmentId(999)))
    ));
    assert!(matches!(
        router.validate(Lease {
            instance: [0; 16],
            environment: EnvironmentId(999),
            device: DEV_1,
            epoch: 1,
        }),
        Err(RouterError::UnknownEnvironment(EnvironmentId(999)))
    ));
    // 设备默认离线，绑定路径同样拒绝，不会静默接受未知身份。
    assert!(matches!(
        router.bind(EnvironmentId(999), DEV_1),
        Err(RouterError::DeviceOffline(DEV_1))
    ));
    assert_eq!(router.binding_count(), 0);
}

/// 设备默认离线；绑定离线设备必须失败，且原绑定与代次计数都不变。
#[test]
fn bind_offline_device_fails_without_changing_existing_binding() {
    let mut router = Router::new().unwrap();
    assert!(!router.is_online(DEV_1));
    assert!(matches!(
        router.bind(ENV_A, DEV_1),
        Err(RouterError::DeviceOffline(DEV_1))
    ));
    assert_eq!(router.binding_count(), 0);
    assert_eq!(router.binding_of(ENV_A), None);

    let lease = bind_online(&mut router, ENV_A, DEV_1);
    let before = router.binding_of(ENV_A).expect("绑定应存在");

    // DEV_2 从未上线，绑到它必须失败，原绑定逐字不变。
    assert!(matches!(
        router.bind(ENV_A, DEV_2),
        Err(RouterError::DeviceOffline(DEV_2))
    ));
    assert_eq!(router.binding_of(ENV_A), Some(before));
    assert_eq!(router.resolve(ENV_A).unwrap(), lease);
    assert!(router.validate(lease).is_ok());
    assert!(!router.is_online(DEV_2));
    // 失败的绑定不消耗代次：下一次成功绑定是当前代次 + 1。
    let next = router.bind(ENV_A, DEV_1).expect("在线设备重绑应成功");
    assert_eq!(next.epoch, before.epoch + 1);
    assert!(router.validate(lease).is_err());
    assert_eq!(router.binding_count(), 1);
}

/// 换设备或重绑后旧 lease 立即失效，不同设备/代次的字段不能拼凑成有效凭据。
#[test]
fn rebinding_invalidates_previous_lease() {
    let mut router = Router::new().unwrap();
    let old_lease = bind_online(&mut router, ENV_A, DEV_1);
    let same_device_rebind = router.bind(ENV_A, DEV_1).expect("同设备重绑也要新代次");
    assert_ne!(old_lease.epoch, same_device_rebind.epoch);
    assert_eq!(
        router.validate(old_lease),
        Err(RouterError::StaleLease(old_lease))
    );
    assert!(router.validate(same_device_rebind).is_ok());

    assert_eq!(router.set_online(DEV_2, true), 0);
    let moved = router.bind(ENV_A, DEV_2).expect("目标设备在线应可绑定");
    assert_eq!(moved.device, DEV_2);
    assert_eq!(
        router.validate(same_device_rebind),
        Err(RouterError::StaleLease(same_device_rebind))
    );
    // 新设备 + 旧代次的混搭凭据也必须失败（fail-closed，不只看设备）。
    let mismatched = Lease {
        instance: same_device_rebind.instance,
        environment: ENV_A,
        device: DEV_2,
        epoch: same_device_rebind.epoch,
    };
    assert_eq!(
        router.validate(mismatched),
        Err(RouterError::StaleLease(mismatched))
    );
    assert!(router.validate(moved).is_ok());
    assert_eq!(router.resolve(ENV_A).unwrap().device, DEV_2);
    // 切换不使绑定表膨胀。
    assert_eq!(router.binding_count(), 1);
}

/// 删除后以同一环境 id 重建，必须使用全新的、更大的代次。
#[test]
fn remove_then_rebind_same_id_never_reuses_epoch() {
    let mut router = Router::new().unwrap();
    let first = bind_online(&mut router, ENV_A, DEV_1);
    assert_eq!(
        router.remove(ENV_A),
        Some(Binding {
            device: DEV_1,
            epoch: first.epoch
        })
    );
    assert_eq!(router.remove(ENV_A), None); // 幂等
    assert!(matches!(
        router.resolve(ENV_A),
        Err(RouterError::UnknownEnvironment(ENV_A))
    ));

    let second = router.bind(ENV_A, DEV_1).expect("重绑应成功");
    assert!(second.epoch > first.epoch);
    assert_eq!(router.validate(first), Err(RouterError::StaleLease(first)));
    assert!(router.validate(second).is_ok());

    // 删除不回收代次：再次重建仍是更大值。
    let _ = router.remove(ENV_A);
    let third = router.bind(ENV_A, DEV_1).expect("第三次绑定应成功");
    assert!(third.epoch > second.epoch);
    assert_eq!(
        router.validate(second),
        Err(RouterError::StaleLease(second))
    );
}

/// 设备离线使其全部绑定失效；重新上线绝不恢复旧 lease。
#[test]
fn device_offline_drops_all_bindings_and_reconnect_does_not_restore() {
    let mut router = Router::new().unwrap();
    let lease_a = bind_online(&mut router, ENV_A, DEV_1);
    let lease_b = bind_online(&mut router, ENV_B, DEV_1);
    let lease_c = bind_online(&mut router, ENV_C, DEV_2);
    assert_eq!(router.binding_count(), 3);

    // DEV_1 离线：它名下 A、B 两条绑定全部失效，DEV_2 上的 C 不受影响。
    assert_eq!(router.set_online(DEV_1, false), 2);
    assert_eq!(router.binding_count(), 1);
    assert_eq!(router.binding_of(ENV_A), None);
    assert_eq!(router.binding_of(ENV_B), None);
    assert!(matches!(
        router.resolve(ENV_A),
        Err(RouterError::UnknownEnvironment(ENV_A))
    ));
    assert_eq!(
        router.validate(lease_a),
        Err(RouterError::UnknownEnvironment(ENV_A))
    );
    assert_eq!(
        router.validate(lease_b),
        Err(RouterError::UnknownEnvironment(ENV_B))
    );
    assert!(router.validate(lease_c).is_ok());

    // 重新上线不恢复旧 lease，必须由上层显式重绑。
    assert_eq!(router.set_online(DEV_1, true), 0);
    assert!(matches!(
        router.resolve(ENV_A),
        Err(RouterError::UnknownEnvironment(ENV_A))
    ));
    assert_eq!(
        router.validate(lease_a),
        Err(RouterError::UnknownEnvironment(ENV_A))
    );
    let rebound = router.bind(ENV_A, DEV_1).expect("上线后重绑应成功");
    assert!(rebound.epoch > lease_a.epoch);
    assert!(router.validate(rebound).is_ok());
    // 旧 lease 在重绑后仍是过期凭据，永远无法复用。
    assert_eq!(
        router.validate(lease_a),
        Err(RouterError::StaleLease(lease_a))
    );
    assert_eq!(router.binding_count(), 2);
}

/// 未上报状态的设备一律离线；显式离线可重复调用且保持幂等。
#[test]
fn unknown_and_double_offline_devices_stay_offline() {
    let mut router = Router::new().unwrap();
    assert!(!router.is_online(DEV_3));
    assert_eq!(router.set_online(DEV_3, false), 0);
    assert!(!router.is_online(DEV_3));
    let lease = bind_online(&mut router, ENV_A, DEV_1);
    assert_eq!(router.set_online(DEV_1, false), 1);
    assert_eq!(router.set_online(DEV_1, false), 0);
    assert_eq!(
        router.validate(lease),
        Err(RouterError::UnknownEnvironment(ENV_A))
    );
    assert!(matches!(
        router.bind(ENV_A, DEV_1),
        Err(RouterError::DeviceOffline(DEV_1))
    ));
}

/// 错误信息的 Display 表现（供上层日志使用，不含任何敏感数据）。
#[test]
fn errors_have_readable_messages() {
    let mut router = Router::new().unwrap();
    assert_eq!(
        router.resolve(ENV_B).unwrap_err().to_string(),
        "环境 EnvironmentId(2) 没有出口绑定"
    );
    assert_eq!(
        router.bind(ENV_B, DEV_2).unwrap_err().to_string(),
        "设备 DeviceId(20) 离线"
    );
    assert_eq!(RouterError::EpochExhausted.to_string(), "绑定代次已耗尽");
}

#[test]
fn fresh_router_rejects_lease_from_previous_instance() {
    let mut previous = Router::new().unwrap();
    let old = bind_online(&mut previous, ENV_A, DEV_1);
    let mut current = Router::new().unwrap();
    bind_online(&mut current, ENV_A, DEV_1);
    assert!(
        current.validate(old).is_err(),
        "重建路由器不能恢复上一实例的旧租约"
    );
}
