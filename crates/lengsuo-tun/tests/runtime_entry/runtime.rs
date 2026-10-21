//! 运行时事件循环的用例：读循环、完整闭环、fail-closed 语义、统计。
//!
//! 这些用例证明的是**接线语义**，不是「TUN 已实机可用」——设备与出口都是内存替身。

use std::net::IpAddr;
use std::time::Duration;

use lengsuo_tun::egress::{Attribution, DeviceId, EgressSelector, EnvironmentId, OutboundProtocol};
use lengsuo_tun::tcp::connector::RouteTable;
use lengsuo_tun::tcp::listener::{self, TcpListener};
use lengsuo_tun::tcp::segment::Flags;
use lengsuo_tun::tcp::state::Config as ConnConfig;

use crate::runtime_entry::{Limits, Runtime, Step, StopReason};

use crate::support::{
    authority, config, tcp_packet, FakeAuthority, FakeDevice, FakeOutbound, FixedClassifier, NOW,
};

/// 组装一个可运行的运行时（设备 → 归因 → 出口 → 用户态 TCP 栈）。
fn runtime(
    device: FakeDevice,
    outbound: FakeOutbound,
    authority: FakeAuthority,
) -> Runtime<FakeDevice, FixedClassifier, FakeAuthority, FakeOutbound> {
    runtime_with_attribution(
        device,
        outbound,
        authority,
        Some(Attribution {
            environment: EnvironmentId(authority.environment),
            device: DeviceId(authority.device),
            epoch: authority.epoch,
        }),
    )
}

/// 组装一个运行时，但可指定归因（`None` 表示无归属）。
fn runtime_with_attribution(
    device: FakeDevice,
    outbound: FakeOutbound,
    authority: FakeAuthority,
    attribution: Option<Attribution>,
) -> Runtime<FakeDevice, FixedClassifier, FakeAuthority, FakeOutbound> {
    let config = config();
    let routes = config.route_table().expect("路由表应可构造");
    let selector = EgressSelector::new(authority, outbound, routes, 16, NOW);
    let listener = TcpListener::new(listener::Config {
        connection: ConnConfig {
            receive_window: 4096,
            reorder_slots: 4,
            iss_seed: 0,
        },
        session_capacity: 16,
        session_ttl: 60_000,
        interface_mtu: 1500,
        iss_seed_start: 1000,
    });
    Runtime::new(device, FixedClassifier { attribution }, selector, listener)
}

/// 入口能启动：进入读循环、读超时是**正常空闲**而非错误。
#[test]
fn entry_starts_and_enters_the_read_loop() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let mut runtime = runtime(FakeDevice::default(), outbound, authority());

    // 队列为空 ⇒ 收包超时 ⇒ Step::Idle（不是错误）。
    let step = runtime.step(Duration::from_millis(1), NOW);
    assert_eq!(step, Step::Idle);
    assert_eq!(runtime.stats().timeouts, 1);
    assert_eq!(runtime.stats().received, 0);
    assert_eq!(runtime.stats().device_errors, 0);
}

/// 达到步数预算即停止，返回可断言的停止原因与统计。
#[test]
fn run_respects_the_step_budget() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let mut runtime = runtime(FakeDevice::default(), outbound, authority());

    let outcome = runtime.run(
        Duration::from_millis(1),
        Limits {
            max_packets: 0,
            max_steps: 5,
        },
        NOW,
    );
    assert_eq!(outcome.stopped, StopReason::StepBudget);
    assert_eq!(outcome.stats.timeouts, 5);
    assert_eq!(outcome.stats.device_errors, 0);
}

/// 达到报文预算即停止。
#[test]
fn run_respects_the_packet_budget() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let device = FakeDevice::with([tcp_packet(1000, 0, Flags::SYN, &[])]);
    let mut runtime = runtime(device, outbound, authority());

    let outcome = runtime.run(
        Duration::from_millis(1),
        Limits {
            max_packets: 1,
            max_steps: 100,
        },
        NOW,
    );
    assert_eq!(outcome.stopped, StopReason::PacketBudget);
    assert_eq!(outcome.stats.received, 1);
}

/// 一个完整闭环：SYN 进 → 归因 → 选出口 → 用户态 TCP 栈回 SYN-ACK → 写回设备。
#[test]
fn packet_is_classified_routed_and_answered_back_to_the_device() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let device = FakeDevice::with([tcp_packet(1000, 0, Flags::SYN, &[])]);
    let mut runtime = runtime(device, outbound, authority());

    let step = runtime.step(Duration::from_millis(1), NOW);
    match &step {
        Step::Forwarded { written, .. } => assert_eq!(*written, 1, "应写回一个 SYN-ACK"),
        other => panic!("期望已转发，实际 {other:?}"),
    }

    let stats = runtime.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.written, 1);
    assert_eq!(stats.denied, 0, "归因命中不得被拒");
    assert_eq!(stats.malformed, 0);
    assert_eq!(stats.active_connections, 1, "活跃连接数应为 1");

    // 出口确实建立了一条会话（路由查表命中，出接口 7、源地址 10.0.0.1）。
    assert_eq!(runtime.selector().runtime().opens, 1);
    assert_eq!(runtime.selector().session_count(), 1);

    // 写回的包是一份可解析的 IPv4+TCP 报文，方向是 本端 → 对端。
    let written = &runtime.device().written;
    assert_eq!(written.len(), 1);
    let info = lengsuo_tun::packet::inspect(&written[0]).expect("回包应可解析");
    assert_eq!(info.source, IpAddr::V4(crate::support::LOCAL));
    assert_eq!(info.destination, IpAddr::V4(crate::support::REMOTE));
    assert_eq!(info.source_port, crate::support::LOCAL_PORT);
    assert_eq!(info.destination_port, crate::support::REMOTE_PORT);
}

/// 握手完成后送入应用载荷：载荷交给出口运行时（`delivered`），回包写回设备。
#[test]
fn established_payload_is_handed_to_the_outbound_and_answered() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    // SYN → SYN-ACK → ACK → 载荷。
    // 栈的 ISN 种子是 `iss_seed_start = 1000`，故 SYN-ACK 的 seq = 1000、
    // 期望的确认号 = 1001；本端的下一个发送序号同样是 1001。
    let packets = vec![
        tcp_packet(1000, 0, Flags::SYN, &[]),
        tcp_packet(1001, 1001, Flags::ACK, &[]),
        tcp_packet(1001, 1001, Flags::PSH | Flags::ACK, b"hello"),
    ];
    let device = FakeDevice::with(packets);
    let mut runtime = runtime(device, outbound, authority());

    // ① SYN ⇒ 回 SYN-ACK。
    assert!(matches!(
        runtime.step(Duration::from_millis(1), NOW),
        Step::Forwarded { .. }
    ));
    // ② ACK ⇒ 完成握手，进 Established。
    runtime.step(Duration::from_millis(1), NOW);
    // ③ 载荷 ⇒ 交付给出口运行时。
    let step = runtime.step(Duration::from_millis(1), NOW);
    match step {
        Step::Forwarded { delivered, .. } => assert_eq!(delivered, 5, "载荷必须交给出口"),
        other => panic!("期望已转发，实际 {other:?}"),
    }

    let stats = runtime.stats();
    assert_eq!(stats.received, 3);
    assert_eq!(stats.delivered, 5, "载荷应恰好交付一次（5 字节）");
    assert_eq!(stats.egress_errors, 0);

    // 出口运行时确实收到了那段字节。
    let forwarded = &runtime.selector().runtime().forwarded;
    let payloads: Vec<&Vec<u8>> = forwarded.values().flatten().collect();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].as_slice(), b"hello");
}

/// 出口侧回程字节被取回并写回设备（回程闭环）。
#[test]
fn outbound_response_is_written_back_to_the_device() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let device = FakeDevice::with([tcp_packet(1000, 0, Flags::SYN, &[])]);
    let mut runtime = runtime(device, outbound, authority());

    // 先跑一步，建立出口会话（句柄 1）。
    runtime.step(Duration::from_millis(1), NOW);
    assert_eq!(runtime.selector().runtime().opens, 1);

    // 出口侧预置回程字节（模拟对端发来的应用数据）。
    runtime
        .selector_mut()
        .runtime_mut()
        .push_response(1, b"from-peer".to_vec());

    // 再跑一步（设备此时无报文 ⇒ 空闲分支顺带取回程）。
    let step = runtime.step(Duration::from_millis(1), NOW);
    assert_eq!(step, Step::Idle);

    // 回程被编成 IP 回包写回设备。
    let written = &runtime.device().written;
    assert_eq!(written.len(), 2, "SYN-ACK + 回程各一包");
    let last = &written[1];
    let info = lengsuo_tun::packet::inspect(last).expect("回程包应可解析");
    assert_eq!(info.source, IpAddr::V4(crate::support::LOCAL));
    assert_eq!(info.destination, IpAddr::V4(crate::support::REMOTE));
    // 回程载荷必须原样带回对端。
    assert!(last.windows(9).any(|w| w == b"from-peer"));
}

/// 报文校验失败 ⇒ 丢弃，**不进归因器**，更不直连。
#[test]
fn malformed_packet_is_dropped_before_classification() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    // 一个坏校验和的 IPv4 报文（破坏 TCP 校验和字段）。
    let mut packet = tcp_packet(1000, 0, Flags::SYN, &[]);
    let checksum_at = 20 + 16;
    packet[checksum_at] ^= 0xff;
    let device = FakeDevice::with([packet]);
    let mut runtime = runtime(device, outbound, authority());

    let step = runtime.step(Duration::from_millis(1), NOW);
    assert!(matches!(step, Step::Malformed { .. }), "实际 {step:?}");

    let stats = runtime.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.malformed, 1);
    assert_eq!(stats.denied, 0, "畸形包不计入归因拒绝");
    assert_eq!(stats.written, 0, "畸形包不得写回");
    assert_eq!(runtime.selector().runtime().opens, 0, "畸形包不得建连");
}

/// 无归属 ⇒ 丢弃，**不回落直连**（不建连、不写回）。
#[test]
fn unattributed_packet_is_denied_not_sent_direct() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let device = FakeDevice::with([tcp_packet(1000, 0, Flags::SYN, &[])]);
    let mut runtime = runtime_with_attribution(device, outbound, authority(), None);

    let step = runtime.step(Duration::from_millis(1), NOW);
    assert!(matches!(step, Step::Denied { .. }), "实际 {step:?}");

    let stats = runtime.stats();
    assert_eq!(stats.denied, 1);
    assert_eq!(stats.written, 0);
    assert_eq!(runtime.selector().runtime().opens, 0, "未归属不得建连");
    assert_eq!(runtime.active_connections(), 0);
}

/// 查不到出接口 ⇒ 拒绝（`NoRoute`），**不走默认路由**。
#[test]
fn missing_route_is_denied_without_default_route() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let device = FakeDevice::with([tcp_packet(1000, 0, Flags::SYN, &[])]);
    // 空路由表 ⇒ 任何目的地址都查不到出接口。
    let selector = EgressSelector::new(authority(), outbound, RouteTable::new(), 16, NOW);
    let listener = TcpListener::new(listener::Config::default());
    let mut runtime = Runtime::new(
        device,
        FixedClassifier {
            attribution: Some(Attribution {
                environment: EnvironmentId(7),
                device: DeviceId(70),
                epoch: 3,
            }),
        },
        selector,
        listener,
    );

    let step = runtime.step(Duration::from_millis(1), NOW);
    match step {
        Step::Denied { reason, .. } => {
            assert_eq!(reason.as_str(), "no-route");
        }
        other => panic!("期望被拒，实际 {other:?}"),
    }
    assert_eq!(runtime.stats().denied, 1);
    assert_eq!(runtime.selector().runtime().opens, 0, "无出接口不得建连");
}

/// 设备错误是终止性的：事件循环以 `DeviceFailed` 停止。
#[test]
fn device_error_is_terminal() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let device = FakeDevice {
        fail_next: Some("设备读失败".to_string()),
        ..FakeDevice::default()
    };
    let mut runtime = runtime(device, outbound, authority());

    let outcome = runtime.run(
        Duration::from_millis(1),
        Limits {
            max_packets: 0,
            max_steps: 10,
        },
        NOW,
    );
    match outcome.stopped {
        StopReason::DeviceFailed { .. } => {}
        other => panic!("期望设备失败终止，实际 {other:?}"),
    }
    assert_eq!(outcome.stats.device_errors, 1);
}

/// 统计快照可断言：全部可观测点都不需要解析日志。
#[test]
fn stats_expose_every_observable_point() {
    let outbound = FakeOutbound::with_protocol(70, OutboundProtocol::Vless);
    let device = FakeDevice::with([tcp_packet(1000, 0, Flags::SYN, &[])]);
    let mut runtime = runtime(device, outbound, authority());
    runtime.step(Duration::from_millis(1), NOW);
    let stats = runtime.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.written, 1);
    assert_eq!(stats.delivered, 0);
    assert_eq!(stats.denied, 0);
    assert_eq!(stats.malformed, 0);
    assert_eq!(stats.egress_errors, 0);
    assert_eq!(stats.timeouts, 0);
    assert_eq!(stats.device_errors, 0);
    assert_eq!(stats.active_connections, 1);
}
