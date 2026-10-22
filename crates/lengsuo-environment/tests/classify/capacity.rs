// ---- 容量上限：会话表满不驱逐，分类器满表拒绝新流 ----

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
