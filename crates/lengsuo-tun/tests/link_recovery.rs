//! 断线与休眠恢复：设备失效即时回收、恢复重建、时钟跳变全量回收。
//!
//! # 性质（重要，勿误读）
//!
//! 前四个用例**不碰真实网卡、不建真实 socket**：权威来源与出口运行时都是
//! 内存替身，路由表也是内存表。因此它们证明的是**选择层的失效/恢复契约**，
//! **不是**任何外部实现的互通，也不是「真机 TUN 端到端」。
//!
//! 最后一项 `#[ignore]` 用例接**真实参考实现**（Xray 的 shadowsocks 入站）与
//! 真实回程服务，证明「设备失效时真实出口会话被立即关闭、且不泄漏」。
//!
//! # 契约（全部 fail-closed）
//!
//! - 设备断开 ⇒ 在途会话立即失效并释放出口：不等 TTL、不自动换出口、不直连。
//! - 设备恢复 ⇒ `select` 重新 `resolve` 权威租约，新会话可重建；旧会话不复用。
//! - 时钟跳变（休眠唤醒）⇒ `gc(now)` 全量回收过期会话，且不误伤新会话。
//!
//! # 夹具复用
//!
//! 权威来源复用 `tests/egress_wiring/support.rs` 的真实 `Router` 适配；单设备
//! 用例直接复用其中的内存假运行时。多设备用例需要同时承载两台设备的替身，
//! 而 `support.rs` 的假运行时是单设备的且不在本卡可写边界内，故在
//! `link_recovery/harness.rs` 补一个等价的多设备版本。

#[path = "egress_wiring/support.rs"]
#[allow(dead_code)]
mod support;

#[path = "node_runtime/fixtures.rs"]
mod fixtures;

#[path = "link_recovery/harness.rs"]
mod harness;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use lengsuo_tun::egress::{
    DenyReason, DeviceId, EgressSelector, NodeOutboundRuntime, OutboundProtocol, RuntimeError,
};
use lengsuo_tun::session::SessionKey;
use lengsuo_tun::tcp::connector::RouteTable;
use lengsuo_tun::tcp::segment::Flags;

use fixtures::{shadowsocks_node, tcp_packet, EchoServer, XrayPeer, TEST_PASSWORD};
use harness::{link_authority, select_packet, take_response, LinkRuntime};
use support::{
    attribution, info_of, packet_with_source_port, routes, valid_packet, FakeRuntime, TTL,
};

/// 每个内存用例的总超时上限。
const TIMEOUT: Duration = Duration::from_secs(10);
/// 环境 7 / 设备 70 与 环境 8 / 设备 71 的固定布置。
const ENV_A: u64 = 7;
const ENV_B: u64 = 8;
const DEV_A: u64 = 70;
const DEV_B: u64 = 71;

/// 设备断开 ⇒ 在途会话立即失效、出口立即释放；新包 fail-closed，且不换出口、不直连。
#[tokio::test]
async fn device_down_closes_in_flight_and_rejects_new() {
    tokio::time::timeout(TIMEOUT, async {
        let (authority, epochs) = link_authority(&[(ENV_A, DEV_A), (ENV_B, DEV_B)]);
        let runtime = LinkRuntime::with_protocols(&[
            (DEV_A, OutboundProtocol::Vless),
            (DEV_B, OutboundProtocol::Vless),
        ]);
        let mut selector = EgressSelector::new(authority, runtime, routes(), 16, TTL);

        let handle_a = select_packet(
            &mut selector,
            &valid_packet(),
            attribution(ENV_A, DEV_A, epochs[0]),
            1_000,
        )
        .handle()
        .expect("设备 a 应选中出口");
        let handle_b = select_packet(
            &mut selector,
            &packet_with_source_port(40_001),
            attribution(ENV_B, DEV_B, epochs[1]),
            1_000,
        )
        .handle()
        .expect("设备 b 应选中出口");
        assert_eq!(selector.session_count(), 2);
        assert_eq!(selector.runtime().opens, 2);

        selector.authority_mut().device_down(DEV_A);
        assert_eq!(
            selector.invalidate_device(DeviceId(DEV_A)),
            1,
            "应释放设备 a 的一条在途会话"
        );
        assert_eq!(selector.session_count(), 1, "设备 b 的会话必须保留");
        assert_eq!(selector.runtime().live_count(), 1);
        assert_eq!(
            selector.runtime().released,
            vec![handle_a.session.0],
            "运行时应只释放设备 a 的那一条出口"
        );
        assert_eq!(selector.runtime().opens, 2, "不得换出口重连");

        selector
            .forward(&handle_b, b"still-alive")
            .expect("设备 b 的会话应正常转发");
        assert_eq!(
            selector
                .runtime()
                .forwarded
                .get(&handle_b.session.0)
                .map(Vec::len),
            Some(1)
        );
        assert!(
            matches!(
                selector.forward(&handle_a, b"after-down"),
                Err(RuntimeError::UnknownSession)
            ),
            "设备 a 的在途会话必须立即失效"
        );

        let denied = select_packet(
            &mut selector,
            &packet_with_source_port(40_002),
            attribution(ENV_A, DEV_A, epochs[0]),
            1_001,
        );
        assert_eq!(
            denied.deny_reason(),
            Some(DenyReason::DeviceOffline),
            "设备离线时新包必须 fail-closed"
        );
        assert_eq!(selector.runtime().opens, 2, "拒绝不得直连或另开出口");
        assert_eq!(selector.runtime().live_count(), 1);

        assert_eq!(
            selector.invalidate_device(DeviceId(999)),
            0,
            "空设备应返回 0 且不 panic"
        );
    })
    .await
    .expect("用例超时");
}

/// 设备恢复 ⇒ `select` 重新解析租约并重建出口；新会话不复用旧句柄。
#[tokio::test]
async fn device_up_rebuilds_new_session() {
    tokio::time::timeout(TIMEOUT, async {
        let (authority, epochs) = link_authority(&[(ENV_A, DEV_A)]);
        let runtime = FakeRuntime::with_protocol(DEV_A, OutboundProtocol::Vless);
        let mut selector = EgressSelector::new(authority, runtime, routes(), 16, TTL);

        let first = select_packet(
            &mut selector,
            &valid_packet(),
            attribution(ENV_A, DEV_A, epochs[0]),
            1_000,
        )
        .handle()
        .expect("首次应选中出口");
        assert_eq!(selector.runtime().opens, 1);

        selector.authority_mut().device_down(DEV_A);
        let stale = select_packet(
            &mut selector,
            &valid_packet(),
            attribution(ENV_A, DEV_A, epochs[0]),
            1_001,
        );
        assert_eq!(
            stale.deny_reason(),
            Some(DenyReason::DeviceOffline),
            "设备断开后旧会话不得复用"
        );
        assert_eq!(selector.invalidate_device(DeviceId(DEV_A)), 1);

        let new_epoch = selector.authority_mut().device_up(DEV_A);
        assert!(new_epoch > epochs[0], "恢复后应分配新的代次");
        let reborn = select_packet(
            &mut selector,
            &valid_packet(),
            attribution(ENV_A, DEV_A, new_epoch),
            2_000,
        )
        .handle()
        .expect("设备恢复后应能重建出口");
        assert_ne!(reborn.session, first.session, "不得复用旧会话句柄");
        assert_eq!(selector.session_count(), 1);
        assert_eq!(selector.runtime().opens, 2, "恢复应新建出口");
    })
    .await
    .expect("用例超时");
}

/// 失效一台设备只影响它自己的会话；另一台照常转发，重复失效返回 0。
#[tokio::test]
async fn invalidate_device_only_affects_target() {
    tokio::time::timeout(TIMEOUT, async {
        let (authority, epochs) = link_authority(&[(ENV_A, DEV_A), (ENV_B, DEV_B)]);
        let runtime = LinkRuntime::with_protocols(&[
            (DEV_A, OutboundProtocol::Vless),
            (DEV_B, OutboundProtocol::Vless),
        ]);
        let mut selector = EgressSelector::new(authority, runtime, routes(), 16, TTL);

        let handle_a = select_packet(
            &mut selector,
            &valid_packet(),
            attribution(ENV_A, DEV_A, epochs[0]),
            1_000,
        )
        .handle()
        .expect("设备 a 应选中出口");
        let handle_b = select_packet(
            &mut selector,
            &packet_with_source_port(40_001),
            attribution(ENV_B, DEV_B, epochs[1]),
            1_000,
        )
        .handle()
        .expect("设备 b 应选中出口");

        assert_eq!(selector.invalidate_device(DeviceId(DEV_A)), 1);
        assert_eq!(selector.session_count(), 1);
        selector
            .forward(&handle_b, b"b-still-works")
            .expect("设备 b 的会话不受影响");
        assert_eq!(
            selector
                .runtime()
                .forwarded
                .get(&handle_b.session.0)
                .map(Vec::len),
            Some(1)
        );
        assert!(matches!(
            selector.forward(&handle_a, b"x"),
            Err(RuntimeError::UnknownSession)
        ));
        assert_eq!(selector.runtime().live_count(), 1);
        assert_eq!(
            selector.invalidate_device(DeviceId(DEV_A)),
            0,
            "重复失效不应重复释放"
        );
    })
    .await
    .expect("用例超时");
}

/// 时钟跳变（休眠唤醒）⇒ `gc` 全量回收并释放出口；随后新会话可建且不被误伤。
#[tokio::test]
async fn clock_suspend_then_gc_releases_all_keeps_new() {
    tokio::time::timeout(TIMEOUT, async {
        let (authority, epochs) = link_authority(&[(ENV_A, DEV_A)]);
        let runtime = FakeRuntime::with_protocol(DEV_A, OutboundProtocol::Vless);
        let mut selector = EgressSelector::new(authority, runtime, routes(), 16, TTL);

        let old = select_packet(
            &mut selector,
            &valid_packet(),
            attribution(ENV_A, DEV_A, epochs[0]),
            1_000,
        )
        .handle()
        .expect("应选中出口");
        // 休眠 4 小时：远超 TTL，等价于主机唤醒后调用方时钟的跳变。
        let suspended = 1_000 + 4 * 60 * 60 * 1_000;
        assert_eq!(selector.gc(suspended), 1, "唤醒后应全量回收过期会话");
        assert_eq!(selector.session_count(), 0);
        assert_eq!(selector.runtime().live_count(), 0);
        assert_eq!(selector.runtime().released, vec![old.session.0]);

        let fresh = select_packet(
            &mut selector,
            &packet_with_source_port(40_001),
            attribution(ENV_A, DEV_A, epochs[0]),
            suspended,
        )
        .handle()
        .expect("回收后应能建新会话");
        assert_ne!(fresh.session, old.session);
        assert_eq!(selector.session_count(), 1);
        assert_eq!(selector.gc(suspended + 1), 0, "未过期的新会话不得被误伤");
        assert_eq!(selector.session_count(), 1);
        assert_eq!(selector.runtime().live_count(), 1);
    })
    .await
    .expect("用例超时");
}

/// 真机/真对端校验：设备失效时真实出口会话被立即关闭（不泄漏），新包 fail-closed。
///
/// 链路：`EgressSelector` → `NodeOutboundRuntime` → 参考实现（Xray shadowsocks 入站）
/// → 真实回程服务。需要参考实现二进制与真实 socket；`#[ignore]` 隔离：
/// `sudo -n <测试二进制> --ignored`。
#[test]
#[ignore = "需要参考实现（XRAY）与真实 socket；条件允许时 sudo -n <测试二进制> --ignored"]
fn real_peer_device_loss_releases_outbound_connection() {
    let echo = EchoServer::start();
    let peer = XrayPeer::start(TEST_PASSWORD, None);
    let node = shadowsocks_node("peer", peer.port(), TEST_PASSWORD);
    let runtime = NodeOutboundRuntime::new(
        [(DeviceId(DEV_A), node)],
        Duration::from_secs(10),
        Duration::from_secs(1),
    )
    .expect("出口运行时应能建立");
    let (authority, epochs) = link_authority(&[(ENV_A, DEV_A)]);

    let mut routes = RouteTable::new();
    routes
        .insert_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            7,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("主机路由应可插入");
    let mut selector = EgressSelector::new(authority, runtime, routes, 16, TTL);

    let packet = tcp_packet(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::LOCALHOST,
        40_000,
        echo.port(),
        1_000,
        0,
        Flags::SYN,
        &[],
    );
    let info = info_of(&packet);
    let key = SessionKey::from_info(info);
    let handle = selector
        .select(&info, key, attribution(ENV_A, DEV_A, epochs[0]), 1_000)
        .handle()
        .expect("应选中真实出口");

    let payload = b"link-recovery-real-peer";
    selector.forward(&handle, payload).expect("载荷应能送出");
    let echoed = take_response(
        &mut selector,
        handle.session,
        payload.len(),
        Duration::from_secs(20),
    );
    assert_eq!(echoed, payload, "真实对端回程应逐字节一致");

    selector.authority_mut().device_down(DEV_A);
    assert_eq!(
        selector.invalidate_device(DeviceId(DEV_A)),
        1,
        "设备断开应即时释放真实出口"
    );
    assert_eq!(
        selector.runtime().session_count(),
        0,
        "真实出口会话应被关闭"
    );

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && echo.closed() == 0 {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(echo.closed(), 1, "设备断开后真实链路应被关闭（不泄漏）");

    let next = tcp_packet(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::LOCALHOST,
        40_001,
        echo.port(),
        1_000,
        0,
        Flags::SYN,
        &[],
    );
    let info = info_of(&next);
    let key = SessionKey::from_info(info);
    let denied = selector.select(&info, key, attribution(ENV_A, DEV_A, epochs[0]), 2_000);
    assert_eq!(
        denied.deny_reason(),
        Some(DenyReason::DeviceOffline),
        "设备离线时新包必须 fail-closed"
    );
    assert_eq!(
        selector.runtime().session_count(),
        0,
        "设备离线时不得直连或另开出口"
    );
}
