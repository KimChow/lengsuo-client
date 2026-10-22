//! 真实出口运行时（`lengsuo_tun::egress::NodeOutboundRuntime`）的用例。
//!
//! # 性质（重要，勿误读）
//!
//! 本套件**建真实 socket、并与参考实现互通**：回程服务是真实 TCP 服务，对端是
//! 参考实现（Xray 的 shadowsocks 入站）。因此它证明的是**真实协议出口**能不能把
//! 字节送出去并原样收回来，**不是**「接线语义自洽」的证据。
//!
//! 与既有 `runtime_entry` 套件互补：那套件证明**接线语义**（内存设备 + 内存出口），
//! 本套件证明**真实出口**（真实协议栈 + 真实对端 + 真设备）。
//!
//! # 被测代码就是生产代码
//!
//! 本文件用 `#[path]` 直接把 `src/bin/lengsuo-tun-runtime.rs` 包含进来，因此跑的就是
//! bin crate root 那份源码；出口运行时跑的是库里的 `egress::NodeOutboundRuntime`。
//!
//! # 凭据
//!
//! 全部凭据都是**测试专用假值**（见 `fixtures::TEST_PASSWORD`），不对应任何真实节点。
//! 断言与输出里只出现端口与字节数，**不出现**口令。

// The included file is a bin crate root: it has its own `main` behind
// `#[cfg(not(test))]`, so the test harness entry point stays unique.
#[path = "../src/bin/lengsuo-tun-runtime.rs"]
#[allow(dead_code, unused_imports)]
mod runtime_entry;

#[path = "runtime_entry/support.rs"]
mod support;

#[path = "node_runtime/fixtures.rs"]
mod fixtures;

#[path = "node_runtime/real_device.rs"]
mod real_device;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use lengsuo_tun::egress::{
    Attribution, DenyReason, DeviceId, EgressSelector, EnvironmentId, NodeOutboundRuntime,
    OutboundExchange, OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError,
};
use lengsuo_tun::tcp::connector::RouteTable;
use lengsuo_tun::tcp::listener::{self, TcpListener};
use lengsuo_tun::tcp::segment::Flags;
use lengsuo_tun::tcp::state::Config as ConnConfig;

use crate::runtime_entry::{Runtime, StaticAuthority, Step};
use crate::support::{FakeDevice, FixedClassifier};

use fixtures::{
    free_port, loopback_target, shadowsocks_node, tcp_packet, EchoServer, XrayPeer, TEST_PASSWORD,
};

/// 建连/收发的时限。
const TIMEOUT: Duration = Duration::from_secs(10);
/// 会话表容量。
const CAPACITY: usize = 64;
/// 会话 TTL（毫秒）。
const TTL: u64 = 60_000;

/// 真协议栈闭环：设备字节经 `NodeOutboundRuntime` → 参考实现（Xray）→ 回程服务。
///
/// 这一条**不用自家回环冒充互通**：对端是参考实现的 shadowsocks 入站，回程服务是
/// 真实 TCP 服务。目标地址原样透传（`redirect` 缺省），因此「节点把目标地址写对了」
/// 也一并被验证：写错了 Xray 就拨不到回程服务。
#[test]
fn real_protocol_stack_round_trip_via_reference_peer() {
    let echo = EchoServer::start();
    let peer = XrayPeer::start(TEST_PASSWORD, None);
    let node = shadowsocks_node("peer", peer.port(), TEST_PASSWORD);

    let mut runtime =
        NodeOutboundRuntime::new([(DeviceId(1), node)], TIMEOUT, Duration::from_secs(1))
            .expect("出口运行时应能建立");

    let session = runtime
        .open(
            DeviceId(1),
            OutboundProtocol::Shadowsocks,
            loopback_target(echo.port()),
        )
        .expect("出口应能建连");
    assert_eq!(runtime.session_count(), 1);

    let payload = b"lengsuo-node-runtime";
    runtime.forward(session, payload).expect("载荷应能送出");

    let echoed = take_response(
        &mut runtime,
        session,
        payload.len(),
        Duration::from_secs(20),
    );
    assert_eq!(echoed, payload, "回程字节应与去程逐字节一致");
    assert_eq!(echo.accepted(), 1, "参考实现应只连了回程服务一次");
    assert_eq!(echo.received(), payload.len(), "回程服务应收到的字节数");

    runtime.release(session);
    assert_eq!(runtime.session_count(), 0, "释放后不应残留会话");
}

/// 出口建连失败 ⇒ fail-closed：报文被丢弃并计数，**绝不直连**。
///
/// 节点端口没人监听 ⇒ 建连必然失败。目标地址指向一个**活着**的直连探针：若运行时
/// 发生「建连失败就直连」的回落，这个探针就会收到连接。
#[test]
fn dial_failure_is_fail_closed_and_never_falls_back_to_direct() {
    let direct = EchoServer::start();
    let dead_port = free_port();
    let node = shadowsocks_node("dead", dead_port, TEST_PASSWORD);

    let mut runtime = NodeOutboundRuntime::new(
        [(DeviceId(70), node)],
        Duration::from_secs(2),
        Duration::from_secs(1),
    )
    .expect("出口运行时应能建立");

    let result = runtime.open(
        DeviceId(70),
        OutboundProtocol::Shadowsocks,
        loopback_target(direct.port()),
    );
    assert!(
        matches!(result, Err(RuntimeError::Dial)),
        "节点不可达时应报建连失败，实际 {result:?}"
    );
    assert_eq!(runtime.session_count(), 0, "建连失败不应留下会话");

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        direct.accepted(),
        0,
        "出口建连失败绝不能回落到直连（直连探针收到了连接）"
    );
}

/// 出口建连失败 ⇒ 报文在出口层被丢弃并计数，**不进入转发**。
///
/// 这一条走完整的事件循环（设备 → 校验 → 归因 → 选出口 → 转发），因此能断言
/// 「丢弃并计数」这个口径本身：拒绝数增长、交付数不增长。
#[test]
fn dial_failure_denies_the_packet_instead_of_forwarding_it() {
    let direct = EchoServer::start();
    let dead_port = free_port();
    let node = shadowsocks_node("dead", dead_port, TEST_PASSWORD);

    let outbound = NodeOutboundRuntime::new(
        [(DeviceId(70), node)],
        Duration::from_secs(2),
        Duration::from_secs(1),
    )
    .expect("出口运行时应能建立");

    // 路由表覆盖直连探针的地址：一旦发生回落，出口就会拨到这个地址。
    let mut routes = RouteTable::new();
    routes
        .insert_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            7,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("主机路由应可插入");
    let selector = EgressSelector::new(
        StaticAuthority {
            environment: 7,
            device: 70,
            epoch: 3,
        },
        outbound,
        routes,
        CAPACITY,
        TTL,
    );
    let listener = TcpListener::new(listener::Config {
        connection: ConnConfig {
            receive_window: 4096,
            reorder_slots: 4,
            iss_seed: 0,
        },
        session_capacity: CAPACITY,
        session_ttl: TTL,
        interface_mtu: 1500,
        iss_seed_start: 1000,
    });
    // 目标 = 直连探针；源地址是 TEST-NET-1 段（不可路由，纯粹当标识用）。
    let device = FakeDevice::with(vec![tcp_packet(
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::LOCALHOST,
        40_000,
        direct.port(),
        1000,
        0,
        Flags::SYN,
        &[],
    )]);
    let classifier = FixedClassifier {
        attribution: Some(Attribution {
            environment: EnvironmentId(7),
            device: DeviceId(70),
            epoch: 3,
        }),
    };
    let mut runtime = Runtime::new(device, classifier, selector, listener);

    let step = runtime.step(Duration::from_millis(50), 1_000);
    assert!(
        matches!(
            step,
            Step::Denied {
                reason: DenyReason::DialFailed,
                ..
            }
        ),
        "节点不可达时应按建连失败拒绝，实际 {step:?}"
    );
    assert_eq!(runtime.stats().denied, 1, "被拒绝的报文应计数");
    assert_eq!(runtime.stats().delivered, 0, "被拒绝的报文不得进入转发");
    assert_eq!(direct.accepted(), 0, "绝不能回落到直连");
}

/// 会话释放：不泄漏，且释放后句柄失效。
#[test]
fn release_frees_the_session_and_tears_the_peer_connection_down() {
    let echo = EchoServer::start();
    let peer = XrayPeer::start(TEST_PASSWORD, None);
    let node = shadowsocks_node("peer", peer.port(), TEST_PASSWORD);

    let mut runtime =
        NodeOutboundRuntime::new([(DeviceId(1), node)], TIMEOUT, Duration::from_secs(1))
            .expect("出口运行时应能建立");
    let session = runtime
        .open(
            DeviceId(1),
            OutboundProtocol::Shadowsocks,
            loopback_target(echo.port()),
        )
        .expect("出口应能建连");
    runtime.forward(session, b"ping").expect("载荷应能送出");
    let _ = take_response(&mut runtime, session, 4, Duration::from_secs(20));

    runtime.release(session);
    assert_eq!(runtime.session_count(), 0, "释放后不应残留会话");
    assert!(
        matches!(
            runtime.forward(session, b"after-release"),
            Err(RuntimeError::UnknownSession)
        ),
        "释放后的句柄必须失效"
    );
    assert!(
        runtime.take_response(session).is_none(),
        "释放后不应再有回程字节"
    );

    // 链路真的断了：回程服务侧应当看到连接被关闭。
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && echo.closed() == 0 {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(echo.closed(), 1, "释放后对端连接应被关闭（没有泄漏）");
}

/// 多设备隔离：每台设备走自己的节点，载荷不串。
#[test]
fn devices_are_isolated() {
    let echo_a = EchoServer::start();
    let echo_b = EchoServer::start();
    // 两个对端用**不同口令**：跨设备串线必然导致解码失败，而不是「看起来能用」。
    let peer_a = XrayPeer::start(TEST_PASSWORD, None);
    let peer_b = XrayPeer::start("lengsuo-other-test-password", None);
    let node_a = shadowsocks_node("node-a", peer_a.port(), TEST_PASSWORD);
    let node_b = shadowsocks_node("node-b", peer_b.port(), "lengsuo-other-test-password");

    let mut runtime = NodeOutboundRuntime::new(
        [(DeviceId(70), node_a), (DeviceId(71), node_b)],
        TIMEOUT,
        Duration::from_secs(1),
    )
    .expect("出口运行时应能建立");

    let session_a = runtime
        .open(
            DeviceId(70),
            OutboundProtocol::Shadowsocks,
            loopback_target(echo_a.port()),
        )
        .expect("设备 70 应能建连");
    let session_b = runtime
        .open(
            DeviceId(71),
            OutboundProtocol::Shadowsocks,
            loopback_target(echo_b.port()),
        )
        .expect("设备 71 应能建连");

    let payload_a = b"AAA";
    let payload_b = b"BBB";
    runtime
        .forward(session_a, payload_a)
        .expect("设备 70 的载荷应能送出");
    runtime
        .forward(session_b, payload_b)
        .expect("设备 71 的载荷应能送出");

    let echoed_a = take_response(
        &mut runtime,
        session_a,
        payload_a.len(),
        Duration::from_secs(20),
    );
    let echoed_b = take_response(
        &mut runtime,
        session_b,
        payload_b.len(),
        Duration::from_secs(20),
    );
    assert_eq!(echoed_a, payload_a, "设备 70 的回程应只含自己的载荷");
    assert_eq!(echoed_b, payload_b, "设备 71 的回程应只含自己的载荷");
    assert_eq!(
        echo_a.received(),
        payload_a.len(),
        "设备 70 的载荷应只落在自己的对端"
    );
    assert_eq!(
        echo_b.received(),
        payload_b.len(),
        "设备 71 的载荷应只落在自己的对端"
    );

    runtime.release(session_a);
    runtime.release(session_b);
    assert_eq!(runtime.session_count(), 0, "释放后不应残留会话");
}

/// 真设备 → 真出口闭环：内核 TCP 客户端 → 真实 TUN 设备 → 用户态 TCP 栈 →
/// 真实协议出口 → 参考实现（Xray）→ 回程服务。
///
/// 实现放在 `node_runtime/real_device.rs`（免得本文件超 400 行），用例本体留在
/// 这里：用例名保持在测试目标的根上。
///
/// # 运行方式
///
/// 需要 root 与真实 TUN 设备，因此标 `#[ignore]`：
/// `sudo -n <测试二进制> --ignored`。
#[test]
#[ignore = "需要 root 与真实 TUN 设备"]
fn real_device_to_real_protocol_stack_round_trip() {
    real_device::run();
}

/// 取回程字节，直到攒够 `expected` 字节或超时。
fn take_response(
    runtime: &mut NodeOutboundRuntime,
    session: OutboundSession,
    expected: usize,
    budget: Duration,
) -> Vec<u8> {
    let deadline = Instant::now() + budget;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        if let Some(bytes) = runtime.take_response(session) {
            out.extend_from_slice(&bytes);
            if out.len() >= expected {
                return out;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    out
}
