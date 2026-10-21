//! 进程入口与静态接线的用例。

use lengsuo_tun::egress::{BindingAuthority, DeviceId, EnvironmentId, OutboundRuntime};
use lengsuo_tun::ingress::Classifier;

use crate::runtime_entry::{main_with_args, run_entry, DemoOutbound, StaticAuthority, StaticClassifier};

use crate::support::{config, tcp_packet, NOW};

/// 命令行演示用的固定接线：归因器与权威来源的语义自洽。
#[test]
fn static_wiring_is_self_consistent() {
    let mut classifier = StaticClassifier {
        environment: 7,
        device: 70,
        epoch: 3,
    };
    let authority = StaticAuthority {
        environment: 7,
        device: 70,
        epoch: 3,
    };
    let info = lengsuo_tun::packet::inspect(&tcp_packet(1000, 0, lengsuo_tun::tcp::segment::Flags::SYN, &[]))
        .expect("报文应可解析");
    let attribution = classifier
        .classify(&info)
        .expect("分类不应失败")
        .expect("应有归属");
    assert_eq!(attribution.environment, EnvironmentId(7));
    let lease = authority
        .resolve(attribution.environment)
        .expect("租约应可解析");
    assert_eq!(lease.device, DeviceId(70));
    assert!(authority.validate(lease).is_ok());
    // 另一个环境没有绑定 ⇒ 显式拒绝。
    assert!(authority.resolve(EnvironmentId(9)).is_err());
}

/// 静态接线由配置推导：环境/设备/代次与配置一致。
#[test]
fn static_wiring_follows_the_config() {
    let config = config();
    let wiring = crate::runtime_entry::StaticWiring::from_config(&config);
    assert_eq!(wiring.classifier.environment, config.environment);
    assert_eq!(wiring.classifier.device, config.device_id);
    assert_eq!(wiring.classifier.epoch, config.epoch);
    assert_eq!(wiring.authority.environment, config.environment);
    assert_eq!(wiring.authority.device, config.device_id);
    assert_eq!(wiring.authority.epoch, config.epoch);
    assert_eq!(wiring.classifier.epoch, wiring.authority.epoch);
}

/// 演示出口运行时如实记账：建连 +1，转发被记账，释放后会话消失。
#[test]
fn demo_outbound_records_what_it_did() {
    let mut outbound = DemoOutbound::new(70, lengsuo_tun::egress::OutboundProtocol::Vless);
    let device = DeviceId(70);
    assert_eq!(
        outbound.protocol_of(device),
        Some(lengsuo_tun::egress::OutboundProtocol::Vless)
    );
    assert!(outbound.is_available(device, lengsuo_tun::egress::OutboundProtocol::Vless));
    // 协议不匹配 ⇒ 不可用（**不静默换协议**）。
    assert!(!outbound.is_available(device, lengsuo_tun::egress::OutboundProtocol::Trojan));

    let session = outbound
        .open(
            device,
            lengsuo_tun::egress::OutboundProtocol::Vless,
            "10.0.0.2:40000".parse().unwrap(),
        )
        .expect("建连应成功");
    assert_eq!(outbound.opens, 1);
    outbound
        .forward(session, b"hello")
        .expect("转发应成功");
    assert_eq!(outbound.forwarded.len(), 1);
    // 释放后再转发 ⇒ 明确失败（不假装成功）。
    outbound.release(session);
    assert!(outbound.forward(session, b"again").is_err());
}

/// 入口的失败路径：配置非法 ⇒ 显式错误，**不**开设备、**不**静默成功。
#[test]
fn entry_rejects_invalid_configuration_before_touching_the_platform() {
    let error = run_entry(vec!["mtu=1500".to_string()], NOW).expect_err("缺设备名必须报错");
    assert!(error.to_string().contains("设备名"), "实际 {error}");
}

/// 入口的失败路径：命令行不是 `key=value` ⇒ 显式错误。
#[test]
fn entry_rejects_malformed_command_line() {
    let error = run_entry(vec!["not-a-pair".to_string()], NOW).expect_err("非法命令行必须报错");
    assert!(error.to_string().contains("key=value"), "实际 {error}");
}

/// 进程主逻辑的退出码：配置非法 ⇒ 非 0。
#[test]
fn main_returns_nonzero_on_invalid_configuration() {
    let code = main_with_args(vec!["mtu=1500".to_string()]);
    assert_ne!(code, 0, "配置非法必须非零退出");
}
