//! DNS 语义的纯内存验证：UDP 端口 53 识别、绑定出口强制、跨环境拒绝、
//! 响应只回发起环境。流分类与会话表上限见 `tests/classify.rs`。

use lengsuo_environment::{
    classify::Classifier, DenyReason, Direction, FlowKey, Timestamp, TrafficKind, DNS_PORT,
};
use std::time::Duration;

mod support;
use support::{
    dns_pair, guard, info, online_router, tcp_pair, CLIENT, DEV_A, DEV_B, DEV_C, DNS_SERVER, ENV_A,
    ENV_B, HARD, IDLE, SERVER, T0,
};

/// UDP 端口 53 判定为 DNS，且只能走该环境绑定的出口设备。
#[tokio::test]
async fn dns_query_only_uses_environment_egress() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        let mut classifier = Classifier::new(8, IDLE, HARD).expect("容量合法");
        let (query, _) = dns_pair(CLIENT, DNS_SERVER, 50_000, b"\x00\x01");

        let decision = classifier
            .register(&router, &info(&query), ENV_A, T0)
            .expect("DNS 查询登记成功");
        assert_eq!(decision.kind, TrafficKind::DnsQuery);
        assert!(decision.is_dns());
        assert_eq!(decision.egress(), DEV_A);
        classifier.authorize(decision, DEV_A).expect("绑定出口放行");
        assert_eq!(
            classifier
                .authorize(decision, DEV_B)
                .expect_err("非授权出口必须拒绝"),
            DenyReason::DnsEgressDenied(ENV_A, DEV_A, DEV_B)
        );
        assert_eq!(
            classifier
                .authorize(decision, DEV_C)
                .expect_err("第三台出口同样被拒"),
            DenyReason::DnsEgressDenied(ENV_A, DEV_A, DEV_C)
        );

        // 同为 UDP 但端口不是 53，则不算 DNS（拒绝原因也不同）。
        let plain = support::udp_packet(CLIENT, SERVER, 50_001, 9_999, b"\x00\x02");
        let flow = classifier
            .register(&router, &info(&plain), ENV_A, Timestamp(1_100))
            .expect("普通 UDP 登记成功");
        assert_eq!(flow.kind, TrafficKind::UdpFlow);
        assert!(!flow.is_dns());
        assert_eq!(
            classifier
                .authorize(flow, DEV_B)
                .expect_err("普通流的跨出口拒绝"),
            DenyReason::EgressDenied(ENV_A, DEV_A, DEV_B)
        );
        // 目的端口 53 才算 DNS：源端口 53 的普通出站流不算。
        let spoofed = support::udp_packet(CLIENT, SERVER, DNS_PORT, 9_999, b"\x00\x04");
        let spoofed_key = FlowKey::from_packet(&info(&spoofed), Direction::Egress);
        assert!(!spoofed_key.dns());
        assert_eq!(
            classifier
                .classify(
                    &router,
                    &info(&spoofed),
                    Direction::Egress,
                    Timestamp(1_200)
                )
                .expect_err("未登记的 DNS 伪装流必须拒绝"),
            DenyReason::NoAttribution(spoofed_key)
        );
        assert_eq!(DNS_PORT, 53);
    })
    .await;
}

/// 跨环境抢占同一条 DNS 会话：后来者被拒且不影响发起方。
#[tokio::test]
async fn cross_environment_dns_session_is_denied() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("A 绑定");
        router.bind(ENV_B, DEV_B).expect("B 绑定");
        let mut classifier = Classifier::new(8, IDLE, HARD).expect("容量合法");
        let (query, _) = dns_pair(CLIENT, DNS_SERVER, 51_000, b"\x00\x03");

        let key = classifier
            .register(&router, &info(&query), ENV_A, T0)
            .expect("A 发起 DNS")
            .key;
        assert_eq!(
            classifier
                .register(&router, &info(&query), ENV_B, Timestamp(1_200))
                .expect_err("同一会话不能归属两个环境"),
            DenyReason::SessionOccupied(key, ENV_A)
        );
        assert_eq!(classifier.session_count(), 1);

        // 该会话仍只归 A，出口仍是 A 的设备。
        let again = classifier
            .classify(&router, &info(&query), Direction::Egress, Timestamp(1_200))
            .expect("A 的续期判定应通过");
        assert_eq!(again.attribution.environment, ENV_A);
        assert_eq!(again.egress(), DEV_A);
        // B 想用这条会话交付自己的响应同样被拒。
        assert_eq!(
            classifier
                .deliver_dns_response(&router, key, ENV_B, Timestamp(1_200))
                .expect_err("B 不能收 A 的响应"),
            DenyReason::DnsResponseNotInitiator(key, ENV_A, ENV_B)
        );
        // B 自己也发起一条 DNS：不同五元组，独立归属、独立出口。
        let (b_query, _) = dns_pair(CLIENT, DNS_SERVER, 51_001, b"\x00\x05");
        let b_decision = classifier
            .register(&router, &info(&b_query), ENV_B, Timestamp(1_300))
            .expect("B 可发起自己的 DNS");
        assert_eq!(b_decision.egress(), DEV_B);
        assert_eq!(classifier.session_count(), 2);
    })
    .await;
}

/// DNS 响应只交付给发起查询的环境；收件方不符或键未登记即拒绝。
#[tokio::test]
async fn dns_response_delivered_only_to_initiator() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("A 绑定");
        router.bind(ENV_B, DEV_B).expect("B 绑定");
        let mut classifier = Classifier::new(8, IDLE, HARD).expect("容量合法");
        let (query, response) = dns_pair(CLIENT, DNS_SERVER, 52_000, b"\x00\x04");
        let decision = classifier
            .register(&router, &info(&query), ENV_A, T0)
            .expect("A 发起 DNS");

        assert_eq!(
            classifier
                .deliver_dns_response(&router, decision.key, ENV_B, Timestamp(2_000))
                .expect_err("响应不能交付给非发起环境"),
            DenyReason::DnsResponseNotInitiator(decision.key, ENV_A, ENV_B)
        );
        let right = classifier
            .deliver_dns_response(&router, decision.key, ENV_A, Timestamp(2_000))
            .expect("响应交付给发起环境");
        assert_eq!(right.kind, TrafficKind::DnsResponse);
        assert!(right.is_dns());
        assert_eq!(right.attribution.environment, ENV_A);
        assert_eq!(right.direction, Direction::Ingress);
        assert_eq!(
            right.key,
            FlowKey::from_packet(&info(&response), Direction::Ingress)
        );
        classifier
            .authorize(right, DEV_A)
            .expect("响应只可经发起环境的绑定出口送回");
        assert_eq!(
            classifier
                .authorize(right, DEV_B)
                .expect_err("经他人出口送回必须拒绝"),
            DenyReason::DnsEgressDenied(ENV_A, DEV_A, DEV_B)
        );

        // 未登记的响应键根本无从归属。
        let orphan = FlowKey::from_packet(
            &info(&support::udp_packet(
                DNS_SERVER,
                CLIENT,
                DNS_PORT,
                52_001,
                b"\x00\x06",
            )),
            Direction::Ingress,
        );
        assert_eq!(
            classifier
                .deliver_dns_response(&router, orphan, ENV_A, Timestamp(2_000))
                .expect_err("孤儿响应必须拒绝"),
            DenyReason::NoAttribution(orphan)
        );
        // 环境撤销后其响应也不再交付。
        assert_eq!(classifier.revoke(ENV_A), 1);
        assert_eq!(
            classifier
                .deliver_dns_response(&router, decision.key, ENV_A, Timestamp(2_100))
                .expect_err("撤销后无会话可交付"),
            DenyReason::NoAttribution(decision.key)
        );
    })
    .await;
}

/// DNS 会话同样受寿命与容量约束：到期后响应不得再交付。
#[tokio::test]
async fn dns_session_expiry_blocks_response_delivery() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        let idle = Duration::from_millis(100);
        let mut classifier = Classifier::new(8, idle, Duration::from_millis(100)).expect("合法");
        let (query, _) = dns_pair(CLIENT, DNS_SERVER, 54_000, b"\x00\x07");
        let decision = classifier
            .register(&router, &info(&query), ENV_A, T0)
            .expect("登记成功");

        assert_eq!(
            classifier
                .deliver_dns_response(&router, decision.key, ENV_A, Timestamp(1_100))
                .expect_err("会话到期后响应必须拒绝"),
            DenyReason::NoAttribution(decision.key)
        );
        // 未登记的普通 TCP 流不能伪装成 DNS 会话被交付。
        let tcp_key = FlowKey::from_packet(
            &info(&tcp_pair(CLIENT, SERVER, 54_001, 443).0),
            Direction::Egress,
        );
        assert_eq!(
            classifier
                .deliver_dns_response(&router, tcp_key, ENV_A, T0)
                .expect_err("TCP 会话不可作为 DNS 交付"),
            DenyReason::NoAttribution(tcp_key)
        );
    })
    .await;
}
