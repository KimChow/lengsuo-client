//! 真设备 → 真出口闭环的实现。
//!
//! 用例本体留在 `tests/node_runtime.rs`（保持用例名在测试目标根上），实现放在这里，
//! 以免单个文件超过 400 行。
//!
//! # 链路
//!
//! 内核 TCP 客户端 → 真实 TUN 设备 → 用户态 TCP 栈 → 真实协议出口 → 参考实现（Xray）
//! → 回程服务。
//!
//! # 为什么目标地址与回程服务不在同一处
//!
//! 内核的**本地表**（优先级 0）对本机地址总是胜出，所以 TUN 的目标必须是**非本机
//! 地址**，报文才会经连接路由进 TUN（本用例用 `10.9.9.2`）。但参考实现在另一侧，
//! 它必须能访问到回程服务（在本机 `127.0.0.1`）——两者只能靠参考实现的
//! `freedom` 出站 `redirect` 解耦：代理把目标改写到回程服务。
//!
//! # 运行方式
//!
//! 需要 root 与真实 TUN 设备，因此用例本体标 `#[ignore]`：
//! `sudo -n <测试二进制> --ignored`。

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use lengsuo_tun::egress::{DeviceId, EgressSelector, NodeOutboundRuntime};
use lengsuo_tun::tcp::listener::{self, TcpListener};
use lengsuo_tun::tcp::state::Config as ConnConfig;

use crate::fixtures::{shadowsocks_node, EchoServer, XrayPeer, TEST_PASSWORD};
use crate::runtime_entry::{
    open_device, RawConfig, RouteRule, Runtime, RuntimeConfig, StaticAuthority, StaticClassifier,
};

/// 建连/收发的时限。
const TIMEOUT: Duration = Duration::from_secs(10);
/// 会话表容量。
const CAPACITY: usize = 64;
/// 会话 TTL（毫秒）。
const TTL: u64 = 60_000;

/// 真设备闭环的正文。由根上的用例本体调用。
pub(super) fn run() {
    let echo = EchoServer::start();
    // 参考实现把目标改写到回程服务：目标与真实访问地址因此可以不同。
    let peer = XrayPeer::start(TEST_PASSWORD, Some(echo.port()));
    let node = shadowsocks_node("peer", peer.port(), TEST_PASSWORD);

    let device_name = "lt-e2e0";
    let config = runtime_config(device_name);
    let device = open_device(&config).expect("应能打开真实 TUN 设备");
    // 内核只有在接口 UP 时才会为地址生成连接路由；`open_device` 已置 UP，
    // 这里补地址即产生 `10.9.9.0/24 dev <设备名>`。
    let _ = run_ip(&["addr", "flush", "dev", device_name]);
    let _ = run_ip(&["addr", "add", "10.9.9.1/24", "dev", device_name]);

    let outbound =
        NodeOutboundRuntime::new([(DeviceId(70), node)], TIMEOUT, Duration::from_secs(1))
            .expect("出口运行时应能建立");
    let selector = EgressSelector::new(
        StaticAuthority {
            environment: 7,
            device: 70,
            epoch: 3,
        },
        outbound,
        config.route_table().expect("路由表应合法"),
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
        interface_mtu: config.mtu,
        iss_seed_start: 1000,
    });
    let classifier = StaticClassifier {
        environment: 7,
        device: 70,
        epoch: 3,
    };
    let mut runtime = Runtime::new(device, classifier, selector, listener);

    // 内核侧：客户端连**非本机**目标 10.9.9.2，报文经连接路由进 TUN。
    let target = SocketAddr::from(([10, 9, 9, 2], 8080));
    let payload = b"real-device-round-trip";
    let (tx, rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();
    let client = std::thread::spawn(move || {
        let outcome = client_round_trip(target, payload);
        let _ = tx.send(outcome);
    });

    // 事件循环：每步推进 10ms 时钟，直到客户端收尾。
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut clock: u64 = 1_000;
    let mut outcome = None;
    while Instant::now() < deadline {
        clock += 10;
        let _ = runtime.step(Duration::from_millis(50), clock);
        if let Ok(result) = rx.try_recv() {
            outcome = Some(result);
            break;
        }
    }
    let _ = client.join();

    let echoed = outcome
        .expect("客户端应在时限内收尾")
        .expect("内核客户端应完成往返");
    assert_eq!(echoed, payload, "回程字节应与去程逐字节一致");
    assert_eq!(echo.accepted(), 1, "参考实现应只连了回程服务一次");
    assert_eq!(echo.received(), payload.len(), "回程服务应收到的字节数");
    // 报文确实经过了真设备与用户态 TCP 栈（否则上面的往返无从谈起）。
    assert!(
        runtime.stats().received >= 3,
        "应至少收到 SYN / ACK / 数据三段，实际 {}",
        runtime.stats().received
    );
    assert_eq!(
        runtime.stats().delivered,
        payload.len() as u64,
        "应用载荷应整段交给出口"
    );
    assert!(
        runtime.stats().written >= 2,
        "应至少写回 SYN-ACK 与回程数据两段，实际 {}",
        runtime.stats().written
    );

    // 收尾：撤地址（接口本身随描述符关闭消失）。
    let _ = run_ip(&["addr", "del", "10.9.9.1/24", "dev", device_name]);
}

/// 构造一份指向 `10.9.9.2` 的运行时配置。
fn runtime_config(device_name: &str) -> RuntimeConfig {
    RawConfig {
        device_name: Some(device_name.to_string()),
        mtu: Some(1500),
        routes: vec![RouteRule {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 9, 9, 2)),
            prefix_len: 32,
            interface_index: 7,
            source: IpAddr::V4(Ipv4Addr::new(10, 9, 9, 1)),
        }],
        environment: Some(7),
        device_id: Some(70),
        epoch: Some(3),
        ..RawConfig::default()
    }
    .into_config()
    .expect("配置应合法")
}

/// 内核侧的 TCP 客户端：连一次、发一段、读一段。
fn client_round_trip(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(20))
        .map_err(|error| format!("连接失败：{error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| format!("设置读超时失败：{error}"))?;
    stream
        .write_all(payload)
        .map_err(|error| format!("写失败：{error}"))?;
    let mut buf = vec![0u8; payload.len()];
    stream
        .read_exact(&mut buf)
        .map_err(|error| format!("读失败：{error}"))?;
    Ok(buf)
}

/// 调一次 `ip` 命令。失败不 panic：调用方自行判断。
fn run_ip(args: &[&str]) -> Result<(), String> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|error| format!("执行 ip 失败：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
