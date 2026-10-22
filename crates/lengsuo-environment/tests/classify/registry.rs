// ---- 归属登记：已注册放行、未注册拒绝、撤销即失效 ----

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
