//! ① 用例：UDP over REALITY 的正向路径。
//!
//! 本仓 REALITY 服务端 ↔ 本仓 REALITY 客户端：UDP 报文经 REALITY 承载往返。
//! 参考语义：VLESS 出站把 UDP 业务改写成 `Command::Mux` + `v1.mux.cool` 选择器，
//! 之后由 XUDP 包封承载（参考 `proxy/vless/outbound/outbound.go`）。

use std::sync::Arc;

use crate::support::*;
use lengsuo_vless::reality::udp::UdpSession;
use ss_core::target::TargetAddr;
use tokio::time::timeout;

/// 回显目标回回的字节必须逐字节一致。
fn payloads() -> Vec<Vec<u8>> {
    vec![vec![0xff], vec![0x42], vec![0x42; 512], vec![0x19; 1200]]
}

/// **自环**：UDP 报文经 REALITY 承载往返，回程数据逐字节一致、目标归属一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_over_reality_roundtrip_ipv4() {
    timeout(DEADLINE, async {
        let server = Arc::new(Server::new());
        let port = reserve_port();
        let dials = DialLog::default();
        let tasks = start_servers(server.clone(), port, dials.clone(), 1, STEP).await;

        let (echo_addr, _echo) = start_echo(any_v4()).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

        let mut stream = connect_client(&server.client_config(), port).await.unwrap();
        let mut session = UdpSession::client(target.clone());

        for payload in payloads() {
            session.send(&mut stream, &payload, STEP).await.unwrap();
            let (back_target, back) = session
                .receive(&mut stream, PAYLOAD_LIMIT, STEP)
                .await
                .unwrap();
            assert_eq!(
                back_target, target,
                "回程目标必须与请求目标一致（归属不串包）"
            );
            assert_eq!(back, payload, "回程数据必须逐字节一致");
        }

        // 先关客户端写方向，服务端才会看到包封边界上的 EOF。
        stream.shutdown().await.unwrap();
        let served = tasks.into_iter().next().unwrap().await.unwrap();
        assert_eq!(served.packets.len(), payloads().len(), "服务端应逐包收齐");
        for (index, (got_target, got_payload)) in served.packets.iter().enumerate() {
            assert_eq!(*got_target, target, "服务端侧目标归属错误");
            assert_eq!(*got_payload, payloads()[index], "服务端侧载荷不一致");
        }
        assert!(
            matches!(served.stop, Stop::Closed),
            "会话应在包封边界正常结束：{:?}",
            served.stop
        );
        assert_eq!(
            dials.lock().unwrap().len(),
            payloads().len(),
            "服务端应逐包拨号一次"
        );
    })
    .await
    .expect("用例总超时");
}

/// **IPv6 目标**（`::1`）：地址编码与拨号都走 IPv6。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_over_reality_roundtrip_ipv6() {
    timeout(DEADLINE, async {
        let server = Arc::new(Server::new());
        let port = reserve_port();
        let dials = DialLog::default();
        let tasks = start_servers(server.clone(), port, dials.clone(), 1, STEP).await;

        let (echo_addr, _echo) = start_echo(any_v6()).await;
        let target = TargetAddr::V6(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            echo_addr.port(),
        );

        let mut stream = connect_client(&server.client_config(), port).await.unwrap();
        let mut session = UdpSession::client(target.clone());

        let payload = vec![0x5a; 300];
        session.send(&mut stream, &payload, STEP).await.unwrap();
        let (back_target, back) = session
            .receive(&mut stream, PAYLOAD_LIMIT, STEP)
            .await
            .unwrap();
        assert_eq!(back_target, target, "IPv6 回程目标必须一致");
        assert_eq!(back, payload, "IPv6 回程数据必须逐字节一致");

        stream.shutdown().await.unwrap();
        let served = tasks.into_iter().next().unwrap().await.unwrap();
        assert_eq!(served.packets.len(), 1);
        assert_eq!(served.packets[0].0, target);
        assert_eq!(dials.lock().unwrap()[0].addr.port(), echo_addr.port());
    })
    .await
    .expect("用例总超时");
}

/// **域名目标**：假域名经 hosts 静态表映射到回环，**不依赖公网 DNS**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_over_reality_roundtrip_domain() {
    timeout(DEADLINE, async {
        let server = Arc::new(Server::new());
        let port = reserve_port();
        let dials = DialLog::default();
        let tasks = start_servers(server.clone(), port, dials.clone(), 1, STEP).await;

        let (echo_addr, _echo) = start_echo(any_v4()).await;
        let target = TargetAddr::Domain(FAKE_DOMAIN.to_owned(), echo_addr.port());

        let mut stream = connect_client(&server.client_config(), port).await.unwrap();
        let mut session = UdpSession::client(target.clone());

        let payload = vec![0x77; 64];
        session.send(&mut stream, &payload, STEP).await.unwrap();
        let (back_target, back) = session
            .receive(&mut stream, PAYLOAD_LIMIT, STEP)
            .await
            .unwrap();
        assert_eq!(back_target, target, "域名目标的回程归属必须一致");
        assert_eq!(back, payload, "域名目标的回程数据必须逐字节一致");

        stream.shutdown().await.unwrap();
        let served = tasks.into_iter().next().unwrap().await.unwrap();
        assert_eq!(served.packets[0].0, target, "服务端侧域名目标必须原样保留");
        assert_eq!(
            dials.lock().unwrap()[0].addr,
            std::net::SocketAddr::from(([127, 0, 0, 1], echo_addr.port())),
            "假域名必须静态映射到回环，不得走公网 DNS"
        );
    })
    .await
    .expect("用例总超时");
}

/// **目标归属不串包**：同一条 REALITY 服务端上跑两条独立连接，各带各的目标；
/// 每条连接的回程只属于它自己的目标。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_over_reality_keeps_targets_apart() {
    timeout(DEADLINE, async {
        let server = Arc::new(Server::new());
        let port = reserve_port();
        let dials = DialLog::default();
        let tasks = start_servers(server.clone(), port, dials.clone(), 2, STEP).await;

        let (echo_a, _a) = start_echo(any_v4()).await;
        let (echo_b, _b) = start_echo(any_v4()).await;
        let target_a = TargetAddr::V4([127, 0, 0, 1], echo_a.port());
        let target_b = TargetAddr::V4([127, 0, 0, 1], echo_b.port());
        assert_ne!(target_a, target_b, "两个回显目标必须落在不同端口");

        let mut stream_a = connect_client(&server.client_config(), port).await.unwrap();
        let mut stream_b = connect_client(&server.client_config(), port).await.unwrap();
        let mut session_a = UdpSession::client(target_a.clone());
        let mut session_b = UdpSession::client(target_b.clone());

        let payload_a = vec![0xaa; 32];
        let payload_b = vec![0xbb; 32];
        session_a
            .send(&mut stream_a, &payload_a, STEP)
            .await
            .unwrap();
        session_b
            .send(&mut stream_b, &payload_b, STEP)
            .await
            .unwrap();

        let (back_a_target, back_a) = session_a
            .receive(&mut stream_a, PAYLOAD_LIMIT, STEP)
            .await
            .unwrap();
        let (back_b_target, back_b) = session_b
            .receive(&mut stream_b, PAYLOAD_LIMIT, STEP)
            .await
            .unwrap();

        assert_eq!(back_a_target, target_a, "连接 A 的回程目标串到了别处");
        assert_eq!(back_b_target, target_b, "连接 B 的回程目标串到了别处");
        assert_eq!(back_a, payload_a, "连接 A 的回程数据被污染");
        assert_eq!(back_b, payload_b, "连接 B 的回程数据被污染");

        stream_a.shutdown().await.unwrap();
        stream_b.shutdown().await.unwrap();
        for task in tasks {
            let served = task.await.unwrap();
            assert_eq!(served.packets.len(), 1);
        }
        let dials = dials.lock().unwrap();
        assert_eq!(dials.len(), 2, "两个目标各拨号一次");
        // 按目标归属配对：每个目标必须只拨自己的回显端口。
        let dial_a = dials
            .iter()
            .find(|dial| dial.target == target_a)
            .expect("目标 A 必须被拨号");
        let dial_b = dials
            .iter()
            .find(|dial| dial.target == target_b)
            .expect("目标 B 必须被拨号");
        assert_eq!(dial_a.addr.port(), echo_a.port(), "目标 A 拨错了回显端口");
        assert_eq!(dial_b.addr.port(), echo_b.port(), "目标 B 拨错了回显端口");
        assert_ne!(dial_a.addr.port(), dial_b.addr.port());
    })
    .await
    .expect("用例总超时");
}
