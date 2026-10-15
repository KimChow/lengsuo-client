//! 流分类与出口归属的纯内存验证：每条 fail-closed 分支都实测，
//! 用例统一在超时保护内运行（不建套接字、不碰真实设备、不做真实等待）。
//! DNS 端口语义与会话表上限见 `tests/dns.rs`。

use lengsuo_environment::{DenyReason, Direction, FlowKey, Timestamp, TrafficKind};
use std::time::Duration;

mod support;
use support::{
    classifier, dns_pair, guard, info, online_router, tcp_pair, v6, CLIENT, DEV_A, DEV_B, DEV_C,
    DNS_SERVER, ENV_A, ENV_B, HARD, IDLE, SERVER, SLACK, T0, V6_CLIENT, V6_DNS, V6_SERVER,
};

/// 已注册环境的出站流归类到其绑定出口；反向报文落在同一归属。
#[tokio::test]
async fn registered_flow_classifies_to_bound_egress() {
    guard(async move {
        let mut router = online_router();
        let lease = router.bind(ENV_A, DEV_A).expect("在线设备可绑定");
        let mut classifier = classifier();
        let (outbound, inbound) = tcp_pair(CLIENT, SERVER, 41_000, 443);

        let decision = classifier
            .register(&router, &info(&outbound), ENV_A, T0)
            .expect("已登记环境的流应放行");
        assert_eq!(decision.attribution.environment, ENV_A);
        assert_eq!(decision.egress(), DEV_A);
        assert_eq!(decision.attribution.epoch, lease.epoch);
        assert_eq!(decision.kind, TrafficKind::TcpStream);
        assert_eq!(decision.direction, Direction::Egress);
        assert!(!decision.is_dns());
        classifier.authorize(decision, DEV_A).expect("授权出口放行");
        assert_eq!(
            classifier
                .authorize(decision, DEV_C)
                .expect_err("其他出口一律拒绝"),
            DenyReason::EgressDenied(ENV_A, DEV_A, DEV_C)
        );

        let reply = classifier
            .classify(
                &router,
                &info(&inbound),
                Direction::Ingress,
                Timestamp(1_500),
            )
            .expect("反向报文命中同一条会话");
        assert_eq!(reply.attribution, decision.attribution);
        assert_eq!(reply.direction, Direction::Ingress);
        assert_eq!(classifier.session_count(), 1);
        assert_eq!(
            decision.key,
            FlowKey::from_packet(&info(&inbound), Direction::Ingress)
        );
    })
    .await;
}

/// 无归属的流一律拒绝，且不留下任何可被「直连」利用的状态。
#[tokio::test]
async fn unregistered_flow_is_denied_without_direct_fallback() {
    guard(async move {
        let router = online_router();
        let mut classifier = classifier();
        let (outbound, _) = tcp_pair(CLIENT, SERVER, 45_000, 8_080);

        let denied = classifier
            .classify(&router, &info(&outbound), Direction::Egress, T0)
            .expect_err("未登记的流必须拒绝");
        assert_eq!(
            denied,
            DenyReason::NoAttribution(FlowKey::from_packet(&info(&outbound), Direction::Egress))
        );
        assert_eq!(classifier.session_count(), 0, "拒绝不得凭空建立会话");
        assert!(classifier
            .classify(&router, &info(&outbound), Direction::Ingress, T0)
            .is_err());
        // 权威路由侧同样没有任何默认出口可退回。
        assert!(router.resolve(ENV_B).is_err());
        assert!(router.is_online(DEV_A));
    })
    .await;
}

/// 环境撤销后：新流一律拒绝，存量会话一并失效并被清除。
#[tokio::test]
async fn revoked_environment_denies_new_and_existing_flows() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        let mut classifier = classifier();
        let (outbound, inbound) = tcp_pair(CLIENT, SERVER, 42_000, 443);
        classifier
            .register(&router, &info(&outbound), ENV_A, T0)
            .expect("登记成功");

        assert!(router.remove(ENV_A).is_some());

        let stale = classifier
            .classify(
                &router,
                &info(&inbound),
                Direction::Ingress,
                Timestamp(2_000),
            )
            .expect_err("撤销后存量会话必须拒绝");
        assert_eq!(stale, DenyReason::UnknownEnvironment(ENV_A));
        assert_eq!(classifier.session_count(), 0, "失效会话应被清除");

        let fresh = classifier
            .register(&router, &info(&outbound), ENV_A, Timestamp(2_000))
            .expect_err("撤销后新流必须拒绝");
        assert_eq!(fresh, DenyReason::UnknownEnvironment(ENV_A));
        assert_eq!(classifier.session_count(), 0, "被拒的登记不应留痕");
        // 显式撤销入口同样幂等。
        assert_eq!(classifier.revoke(ENV_A), 0);
    })
    .await;
}

/// 会话表满时拒绝新会话，且不驱逐任何既有会话。
#[tokio::test]
async fn session_table_capacity_denies_without_eviction() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        let mut classifier =
            lengsuo_environment::SessionTable::new(2, IDLE, HARD).expect("容量合法");
        let key_of = |port: u16| {
            FlowKey::from_packet(
                &info(&tcp_pair(CLIENT, SERVER, port, 443).0),
                Direction::Egress,
            )
        };
        let first = key_of(46_000);
        let second = key_of(46_001);
        let third = key_of(46_002);

        for key in [first, second] {
            classifier.open(key, ENV_A, 1, T0).expect("前两条应登记");
        }
        assert_eq!(
            classifier
                .open(third, ENV_A, 1, Timestamp(1_100))
                .expect_err("满表应拒绝"),
            lengsuo_environment::SessionError::Full
        );
        assert_eq!(classifier.len(), 2, "满表不得驱逐既有条目");
        assert!(classifier.get(first, Timestamp(1_100)).is_some());
        // 只能显式撤销腾出槽位，之后新会话才可登记。
        assert_eq!(classifier.revoke(ENV_A), 2);
        assert!(classifier.open(third, ENV_A, 1, Timestamp(1_200)).is_ok());
        assert!(lengsuo_environment::SessionTable::new(0, IDLE, HARD).is_err());
    })
    .await;
}

/// 分类器层的满表拒绝同样不得建立归属。
#[tokio::test]
async fn classifier_capacity_denies_new_flow() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        let mut classifier = lengsuo_environment::Classifier::new(1, IDLE, HARD).expect("容量合法");
        let (first, _) = tcp_pair(CLIENT, SERVER, 46_100, 443);
        let (second, _) = tcp_pair(CLIENT, SERVER, 46_101, 443);
        classifier
            .register(&router, &info(&first), ENV_A, T0)
            .expect("第一条登记成功");
        assert_eq!(
            classifier
                .register(&router, &info(&second), ENV_A, Timestamp(1_100))
                .expect_err("满表必须拒绝新流"),
            DenyReason::SessionFull
        );
        assert_eq!(classifier.session_count(), 1);
        // 既有条目仍可续期使用。
        assert!(classifier
            .classify(&router, &info(&first), Direction::Egress, Timestamp(1_100))
            .is_ok());
        assert_eq!(
            classifier
                .register(&router, &info(&second), ENV_A, Timestamp(1_100))
                .expect_err("拒绝可重复且稳定"),
            DenyReason::SessionFull
        );
    })
    .await;
}

/// IPv6 五元组同样归类，且与 IPv4 上同名端口互不混淆。
#[tokio::test]
async fn ipv6_five_tuple_is_classified() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        let mut classifier = classifier();
        let (v6_outbound, v6_inbound) = tcp_pair(V6_CLIENT, V6_SERVER, 47_000, 443);
        let (v4_outbound, _) = tcp_pair(CLIENT, SERVER, 47_000, 443);

        let decision = classifier
            .register(&router, &info(&v6_outbound), ENV_A, T0)
            .expect("IPv6 流登记成功");
        assert_eq!(decision.attribution.environment, ENV_A);
        assert_eq!(decision.attribution.device, DEV_A);
        assert_eq!(decision.key.source, V6_CLIENT);
        assert_eq!(decision.key.destination, V6_SERVER);
        assert_eq!(
            decision.key,
            FlowKey::from_packet(&info(&v6_inbound), Direction::Ingress)
        );
        assert_ne!(
            decision.key,
            FlowKey::from_packet(&info(&v4_outbound), Direction::Egress)
        );
        assert!(classifier
            .classify(
                &router,
                &info(&v6_inbound),
                Direction::Ingress,
                Timestamp(1_500)
            )
            .is_ok());
        assert!(classifier
            .classify(
                &router,
                &info(&v4_outbound),
                Direction::Egress,
                Timestamp(1_500)
            )
            .is_err());

        // IPv6 的 DNS 语义同样成立。
        let (query, _) = dns_pair(V6_CLIENT, V6_DNS, 53_000, b"\x00\x06");
        let dns = classifier
            .register(&router, &info(&query), ENV_A, Timestamp(1_600))
            .expect("IPv6 DNS 登记成功");
        assert_eq!(dns.kind, TrafficKind::DnsQuery);
        assert_eq!(dns.egress(), DEV_A);
        assert!(v6([0, 0, 0, 0, 0, 0, 0, 1]).is_ipv6());
        assert_eq!(DNS_SERVER.to_string(), "203.0.113.53");
    })
    .await;
}

/// 路由更新（换设备产生新代次）后：旧会话按失效拒绝，新流按新出口归类。
#[tokio::test]
async fn epoch_update_rejects_old_session_and_routes_new_flows() {
    guard(async move {
        let mut router = online_router();
        let old = router.bind(ENV_A, DEV_A).expect("初次绑定");
        let mut classifier = classifier();
        let (outbound, inbound) = tcp_pair(CLIENT, SERVER, 48_000, 443);
        let key = classifier
            .register(&router, &info(&outbound), ENV_A, T0)
            .expect("旧路由下登记")
            .key;

        let fresh = router.bind(ENV_A, DEV_B).expect("换设备重绑");
        assert!(fresh.epoch > old.epoch);

        let stale = classifier
            .classify(
                &router,
                &info(&inbound),
                Direction::Ingress,
                Timestamp(2_000),
            )
            .expect_err("旧代次会话必须拒绝");
        assert_eq!(stale, DenyReason::StaleSession(key, old.epoch, fresh.epoch));
        assert_eq!(classifier.session_count(), 0);

        let rerouted = classifier
            .register(&router, &info(&outbound), ENV_A, Timestamp(2_100))
            .expect("新流按新路由登记");
        assert_eq!(rerouted.key, key, "同一条双向流应落在同一个归一化键上");
        assert_eq!(rerouted.egress(), DEV_B);
        assert_eq!(rerouted.attribution.epoch, fresh.epoch);
        classifier.authorize(rerouted, DEV_B).expect("新出口放行");
        assert_eq!(
            classifier
                .authorize(rerouted, DEV_A)
                .expect_err("旧出口此时应被拒"),
            DenyReason::EgressDenied(ENV_A, DEV_B, DEV_A)
        );
    })
    .await;
}

/// 设备离线使存量会话失效；prune 周期回收同样生效。
#[tokio::test]
async fn device_offline_denies_and_prune_reclaims() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        router.bind(ENV_B, DEV_B).expect("绑定成功");
        let mut classifier = classifier();
        let (a, _) = tcp_pair(CLIENT, SERVER, 49_000, 443);
        let (b, _) = tcp_pair(CLIENT, SERVER, 49_001, 443);
        classifier
            .register(&router, &info(&a), ENV_A, T0)
            .expect("A 登记");
        classifier
            .register(&router, &info(&b), ENV_B, T0)
            .expect("B 登记");

        assert_eq!(router.set_online(DEV_A, false), 1, "A 的绑定应随之失效");
        assert_eq!(classifier.prune(&router, Timestamp(1_500)), 1);
        assert_eq!(classifier.session_count(), 1, "无关环境的会话应保留");
        assert_eq!(
            classifier
                .classify(&router, &info(&a), Direction::Egress, Timestamp(1_500))
                .expect_err("离线环境的流必须拒绝"),
            DenyReason::NoAttribution(FlowKey::from_packet(&info(&a), Direction::Egress))
        );
        assert!(classifier
            .classify(&router, &info(&b), Direction::Egress, Timestamp(1_500))
            .is_ok());

        // 重新上线不恢复旧绑定；未重绑前 A 的新流仍被拒。
        router.set_online(DEV_A, true);
        assert_eq!(
            classifier
                .register(&router, &info(&a), ENV_A, Timestamp(1_600))
                .expect_err("未重绑前必须拒绝"),
            DenyReason::UnknownEnvironment(ENV_A)
        );
    })
    .await;
}

/// 会话寿命：窗口内可续期，但绝不越过绝对上限；到期后必须重新登记。
#[tokio::test]
async fn session_ttl_hard_cap_and_expiry() {
    guard(async move {
        let mut router = online_router();
        router.bind(ENV_A, DEV_A).expect("绑定成功");
        let idle = Duration::from_millis(SLACK.as_millis() as u64 / 50);
        let hard = Duration::from_millis(idle.as_millis() as u64 * 3 / 2);
        let mut classifier = lengsuo_environment::Classifier::new(4, idle, hard).expect("TTL 合法");
        let (outbound, _) = tcp_pair(CLIENT, SERVER, 53_000, 9_999);

        let opened = classifier
            .register(&router, &info(&outbound), ENV_A, T0)
            .expect("登记成功");
        let session = classifier.session_of(opened.key, T0).expect("会话存在");
        assert_eq!(
            session.hard_deadline,
            T0.checked_add(hard).expect("上限可计算")
        );
        assert_eq!(
            session.expires_at,
            T0.checked_add(idle).expect("idle 可计算")
        );

        // 窗口内有流量：续期到 now + idle，仍在上限之内。
        let midway = T0.checked_add(idle / 2).expect("中点可计算");
        let renewed = classifier
            .classify(&router, &info(&outbound), Direction::Egress, midway)
            .expect("续期成功");
        assert_eq!(
            classifier
                .session_of(renewed.key, midway)
                .expect("会话存在")
                .expires_at,
            midway.checked_add(idle).expect("续期可计算"),
            "窗口内续期应前移到期时刻"
        );

        // 逼近上限时：now + idle 已越过 hard，被硬上限截断而非后移。
        let near = session
            .hard_deadline
            .checked_sub(idle / 2)
            .expect("逼近点可计算");
        classifier
            .classify(&router, &info(&outbound), Direction::Egress, near)
            .expect("上限前仍可续期");
        assert_eq!(
            classifier
                .session_of(opened.key, near)
                .expect("会话存在")
                .expires_at,
            session.hard_deadline,
            "绝对上限不可被续期突破"
        );

        let past = session.hard_deadline;
        assert_eq!(
            classifier
                .classify(&router, &info(&outbound), Direction::Egress, past)
                .expect_err("到达绝对上限后必须到期"),
            DenyReason::SessionExpired(opened.key)
        );
        // 到期后同一五元组必须重新登记才可用。
        assert!(classifier
            .register(&router, &info(&outbound), ENV_A, past)
            .is_ok());
        assert!(
            classifier
                .register(&router, &info(&outbound), ENV_A, Timestamp(u64::MAX))
                .is_err(),
            "时间算术溢出应 fail-closed"
        );
    })
    .await;
}
