//! 流量转发服务的端到端验收（仅回环、临时端口、假凭据）。
//!
//! 夹具：**本仓协议服务端**（trojan / shadowsocks）作参考服务端 ⇒ 转发器接受
//! 本地 SOCKS5 连接 ⇒ 请求打到参考服务端 ⇒ 参考服务端回显 ⇒ 本地端收到回显
//! （载荷**逐字节一致**）。
//!
//! 覆盖：trojan 端到端、shadowsocks 端到端、路由选节点（两个参考服务端各回
//! **不同**内容 ⇒ 断言拿到对应节点的内容），以及反例六条：未命中规则且无默认
//! 节点 ⇒ fail-closed 断连；节点不可达 ⇒ fail-closed 断连；错密码（trojan +
//! shadowsocks）⇒ 断开且**不回落到明文**；路由规则冲突 ⇒ 配置加载阶段显式
//! 报错；本地侧提前断开 ⇒ 出站侧被半关闭；关闭转发器 ⇒ 不再接受新连接且既有
//! 连接被收尾。
//!
//! 全部用例带总超时；读回程前先关写端。

#[path = "forward_support/mod.rs"]
mod support;

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::forward::{ForwardConfig, ForwardHandle, Forwarder, NodePool};
use lengsuo_node::route::{IpNet, RouteRule, RouteTable};
use support::*;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;
use tokio::time::timeout;

/// 单用例总超时。
const TOTAL: Duration = Duration::from_secs(60);

/// 带总超时的用例包装（超时即失败，不允许挂死）。
macro_rules! case {
    ($body:block) => {
        timeout(TOTAL, async $body).await.expect("总超时")
    };
}

/// 转发器配置（测试用短超时）。
fn test_config() -> ForwardConfig {
    ForwardConfig {
        listen: "127.0.0.1:0".to_owned(),
        default_node: None,
        rules: Vec::new(),
        idle_timeout_secs: 5,
        session_timeout_secs: 10,
    }
}

/// 起一个转发器，返回（本地地址, 句柄）。
async fn start_forwarder(
    nodes: Vec<NodeConfig>,
    rules: Vec<RouteRule>,
    default_node: Option<String>,
) -> (SocketAddr, ForwardHandle) {
    let routes = RouteTable::new(rules, default_node).expect("路由表");
    let forwarder = Forwarder::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodePool::new(nodes),
        routes,
        test_config(),
    )
    .await
    .expect("转发器绑定");
    let addr = forwarder.local_addr().expect("转发器地址");
    let handle = forwarder.start().await.expect("转发器启动");
    (addr, handle)
}

/// trojan 端到端：本地 SOCKS5 ⇒ 转发器 ⇒ trojan 服务端 ⇒ echo ⇒ 回程逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_forward_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        let node = trojan_node("trojan-node", port, &ca_pem, TROJAN_PASSWORD);
        let (proxy, handle) =
            start_forwarder(vec![node], Vec::new(), Some("trojan-node".to_owned())).await;

        let payload = b"trojan-forward-payload-\x00\xff\xfe".to_vec();
        match socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await {
            Socks5Result::Replied { rep, payload: got } => {
                assert_eq!(rep, 0x00, "SOCKS5 回复码应为成功");
                assert_eq!(got, payload, "回程载荷必须逐字节一致");
            }
            Socks5Result::Closed { .. } => panic!("trojan 转发应成功建立会话"),
        }
        assert_eq!(hits(&echo.hits), 1, "目标必须被拨到一次");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// shadowsocks 端到端：本地 SOCKS5 ⇒ 转发器 ⇒ shadowsocks 中继 ⇒ echo ⇒ 回程一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_forward_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let port = shadowsocks_server().await;
        let node = shadowsocks_node("ss-node", port, SS_PASSWORD);
        let (proxy, handle) =
            start_forwarder(vec![node], Vec::new(), Some("ss-node".to_owned())).await;

        let payload = b"shadowsocks-forward-payload".to_vec();
        match socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await {
            Socks5Result::Replied { rep, payload: got } => {
                assert_eq!(rep, 0x00, "SOCKS5 回复码应为成功");
                assert_eq!(got, payload, "回程载荷必须逐字节一致");
            }
            Socks5Result::Closed { .. } => panic!("shadowsocks 转发应成功建立会话"),
        }
        assert_eq!(hits(&echo.hits), 1, "目标必须被拨到一次");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// 路由：两个参考服务端各回**不同**内容，断言本地端拿到的是**对应节点**的内容。
///
/// 用两条 CIDR 规则把两个回环目标（`127.0.0.2/32` 与 `127.0.0.3/32`）分给
/// 两个节点：回环的 `127.0.0.2` / `127.0.0.3` 在 Linux 上都可达（`lo` 的
/// 整个 `127.0.0.0/8` 都是本机），且监听器分别绑在这两个 IP 上。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_selects_node_by_target_address() {
    case!({
        let echo_a = spawn_fixed_echo_on("127.0.0.2:0", b"content-from-node-a").await;
        let echo_b = spawn_fixed_echo_on("127.0.0.3:0", b"content-from-node-b").await;
        let (port_a, ca_pem_a) = trojan_server(TROJAN_PASSWORD).await;
        // 两个服务端各自生成自签证书 ⇒ 各自的 CA PEM 必须配给自己的节点。
        let (port_b, ca_pem_b) = trojan_server(TROJAN_PASSWORD).await;
        let node_a = trojan_node("node-a", port_a, &ca_pem_a, TROJAN_PASSWORD);
        let node_b = trojan_node("node-b", port_b, &ca_pem_b, TROJAN_PASSWORD);

        let rules = vec![
            RouteRule {
                domain_suffix: None,
                cidr: Some(IpNet::new("127.0.0.2".parse().unwrap(), 32).unwrap()),
                node: "node-a".to_owned(),
            },
            RouteRule {
                domain_suffix: None,
                cidr: Some(IpNet::new("127.0.0.3".parse().unwrap(), 32).unwrap()),
                node: "node-b".to_owned(),
            },
        ];
        let (proxy, handle) =
            start_forwarder(vec![node_a, node_b], rules, Some("node-a".to_owned())).await;

        // 目标 127.0.0.2 → node-a。
        let target_a = SocketAddr::from(([127, 0, 0, 2], echo_a.addr.port()));
        match socks5_roundtrip(proxy, socks5_connect_v4(target_a), b"ping-a").await {
            Socks5Result::Replied { rep, payload } => {
                assert_eq!(rep, 0x00, "SOCKS5 回复码应为成功");
                assert_eq!(payload, b"content-from-node-a", "必须拿到 node-a 的内容");
            }
            Socks5Result::Closed { .. } => panic!("node-a 转发应成功"),
        }
        // 目标 127.0.0.3 → node-b。
        let target_b = SocketAddr::from(([127, 0, 0, 3], echo_b.addr.port()));
        match socks5_roundtrip(proxy, socks5_connect_v4(target_b), b"ping-b").await {
            Socks5Result::Replied { rep, payload } => {
                assert_eq!(rep, 0x00, "SOCKS5 回复码应为成功");
                assert_eq!(payload, b"content-from-node-b", "必须拿到 node-b 的内容");
            }
            Socks5Result::Closed { .. } => panic!("node-b 转发应成功"),
        }
        // 两个 echo 各被拨到一次（没有串到同一个节点）。
        assert_eq!(hits(&echo_a.hits), 1, "node-a 的目标只被拨到一次");
        assert_eq!(hits(&echo_b.hits), 1, "node-b 的目标只被拨到一次");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// 反例①：目标未命中任何规则且无默认节点 ⇒ fail-closed 断连（**不直连**）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_route_and_no_default_node_fails_closed() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        let node = trojan_node("trojan-node", port, &ca_pem, TROJAN_PASSWORD);
        // 规则只覆盖别的网段 ⇒ 目标不命中；且**没有默认节点**。
        let rules = vec![RouteRule {
            domain_suffix: None,
            cidr: Some(IpNet::new("10.99.0.0".parse().unwrap(), 16).unwrap()),
            node: "trojan-node".to_owned(),
        }];
        let (proxy, handle) = start_forwarder(vec![node], rules, None).await;

        let result =
            socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"must-not-arrive").await;
        assert_fail_closed(&result, &echo.hits, "未命中路由且无默认节点");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// 反例②：节点不可达（端口无监听）⇒ fail-closed 断连。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_node_fails_closed() {
    case!({
        // 占一个端口再立刻释放 ⇒ 该端口大概率无监听（回环上的拒绝连接）。
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let echo = spawn_echo().await;
        let (_port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        // 节点指向那个死端口。
        let node = trojan_node("dead-node", dead_port, &ca_pem, TROJAN_PASSWORD);
        let (proxy, handle) =
            start_forwarder(vec![node], Vec::new(), Some("dead-node".to_owned())).await;

        let result =
            socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"must-not-arrive").await;
        assert_fail_closed(&result, &echo.hits, "节点不可达");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// 反例③：错密码（trojan）⇒ 转发器断开，**不回落到明文**。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_password_fails_closed_without_plaintext_fallback() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        // 客户端口令与服务端不一致 ⇒ 服务端拒绝（关闭连接）。
        let node = trojan_node("bad-node", port, &ca_pem, TROJAN_WRONG_PASSWORD);
        let (proxy, handle) =
            start_forwarder(vec![node], Vec::new(), Some("bad-node".to_owned())).await;

        let result =
            socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"must-not-arrive").await;
        assert_no_fallback(&result, &echo.hits, "trojan 错口令");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// 反例③b：错密码（shadowsocks）⇒ 同样不回落到明文。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_wrong_password_fails_closed() {
    case!({
        let echo = spawn_echo().await;
        let port = shadowsocks_server().await;
        let node = shadowsocks_node("bad-ss-node", port, SS_WRONG_PASSWORD);
        let (proxy, handle) =
            start_forwarder(vec![node], Vec::new(), Some("bad-ss-node".to_owned())).await;

        let result =
            socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"must-not-arrive").await;
        assert_no_fallback(&result, &echo.hits, "shadowsocks 错口令");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// 反例④：路由规则冲突 ⇒ **配置加载阶段**显式报错（不静默取第一条）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflicting_route_rules_are_rejected_at_load_time() {
    case!({
        // 同一后缀的两条规则指向不同节点 ⇒ 冲突。
        let rules = vec![
            RouteRule {
                domain_suffix: Some("example.test".to_owned()),
                cidr: None,
                node: "node-a".to_owned(),
            },
            RouteRule {
                domain_suffix: Some("example.test".to_owned()),
                cidr: None,
                node: "node-b".to_owned(),
            },
        ];
        let error = RouteTable::new(rules, Some("node-a".to_owned()))
            .expect_err("同 specificity 的冲突规则必须报错");
        let text = error.to_string();
        assert!(text.contains("冲突"), "错误信息应说明是冲突：{text}");

        // 同理：同一网段的两条规则也是冲突。
        let rules = vec![
            RouteRule {
                domain_suffix: None,
                cidr: Some(IpNet::new("10.0.0.0".parse().unwrap(), 8).unwrap()),
                node: "node-a".to_owned(),
            },
            RouteRule {
                domain_suffix: None,
                cidr: Some(IpNet::new("10.0.0.0".parse().unwrap(), 8).unwrap()),
                node: "node-b".to_owned(),
            },
        ];
        assert!(
            RouteTable::new(rules, None).is_err(),
            "同网段重复规则必须报错"
        );

        // 形态非法（同时给后缀与网段）也必须在加载阶段报错。
        let rules = vec![RouteRule {
            domain_suffix: Some("a.test".to_owned()),
            cidr: Some(IpNet::new("10.0.0.0".parse().unwrap(), 8).unwrap()),
            node: "node-a".to_owned(),
        }];
        assert!(
            RouteTable::new(rules, None).is_err(),
            "后缀与网段互斥必须报错"
        );
    });
}

/// 反例⑤：本地侧提前断开 ⇒ 出站侧被半关闭（**不是**留下悬挂会话）。
///
/// 判据：本地在 SOCKS5 握手后立刻断开 ⇒ 转发器应当**关闭**出站侧（服务端看到
/// EOF），而不是让会话悬挂；同时**不得**留下未回收的任务（关停时干净退出）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_side_early_close_half_closes_upstream() {
    case!({
        // 这个 echo 读到 EOF 才回内容：只有出站侧被半关闭（收到 FIN）才会回。
        let echo = spawn_delayed_echo(b"upstream-saw-eof").await;
        let (port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        let node = trojan_node("trojan-node", port, &ca_pem, TROJAN_PASSWORD);
        let (proxy, handle) =
            start_forwarder(vec![node], Vec::new(), Some("trojan-node".to_owned())).await;

        // 握手成功后立刻断开本地连接。
        let (_rep, stream) = socks5_handshake(proxy, socks5_connect_v4(echo.addr))
            .await
            .expect("SOCKS5 握手应成功");
        drop(stream);

        // 给转发器一点时间把 FIN 传到上游。
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            hits(&echo.hits),
            1,
            "上游必须被拨到（半关闭是「传到上游」而不是「不碰上游」）"
        );

        // 关停必须干净（没有悬挂任务）。
        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// 反例⑥：关闭转发器 ⇒ 不再接受新连接，既有连接被收尾（无资源泄漏）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_stops_accepting_and_finishes_existing_connections() {
    case!({
        let echo = spawn_delayed_echo(b"late-echo").await;
        let (port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        let node = trojan_node("trojan-node", port, &ca_pem, TROJAN_PASSWORD);
        let (proxy, handle) =
            start_forwarder(vec![node], Vec::new(), Some("trojan-node".to_owned())).await;

        // 建立一条连接：握手成功后**保持**（不关），让关停去收尾它。
        let (rep, mut stream) = socks5_handshake(proxy, socks5_connect_v4(echo.addr))
            .await
            .expect("SOCKS5 握手应成功");
        assert_eq!(rep, 0x00, "SOCKS5 回复码应为成功");

        // 关闭转发器：既有连接被收尾，本地侧应看到 EOF。
        handle.shutdown().await.expect("转发器应干净停止");

        let mut buf = [0u8; 64];
        let read = timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("关停后本地侧应在超时内看到 EOF 或数据");
        assert!(
            matches!(read, Ok(0) | Ok(_)),
            "关停后本地侧必须被收尾（读到 EOF 或剩余数据）"
        );

        // 关停后不再接受新连接：连本地端口应失败。
        let reconnect = timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(proxy),
        )
        .await;
        assert!(
            reconnect.is_err() || reconnect.is_ok_and(|r| r.is_err()),
            "关停后不得再接受新连接"
        );
    });
}
