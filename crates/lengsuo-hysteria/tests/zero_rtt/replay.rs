// ⑤ 服务端拒绝 → 回退 1-RTT 且只交付一次；被接受则不重放。
// ---- ⑤ 服务端拒绝 → 回退 1-RTT 且不重复交付 ----

#[test]
fn rejection_falls_back_to_one_rtt_without_duplicate_delivery() {
    let fake = FakeConn::default();
    let (value, outcome) = run_early(
        OperationKind::Idempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("early")
        }),
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("1-rtt")
        },
        false,
    )
    .expect("幂等操作允许显式重放");
    assert_eq!(value, "1-rtt", "被拒后使用 1-RTT 结果");
    assert_eq!(
        outcome,
        ZeroRttOutcome::Rejected(ZeroRttRejected),
        "拒绝必须如实上报"
    );
    assert_eq!(fake.early_sends.load(Ordering::SeqCst), 1);
    assert_eq!(
        fake.one_rtt_sends.load(Ordering::SeqCst),
        1,
        "应用层只交付一次，不得重复发送"
    );
}

#[test]
fn accepted_early_data_is_not_replayed() {
    let fake = FakeConn::default();
    let (value, outcome) = run_early(
        OperationKind::Idempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("early")
        }),
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("1-rtt")
        },
        true,
    )
    .expect("幂等操作");
    assert_eq!(value, "early");
    assert_eq!(outcome, ZeroRttOutcome::Accepted);
    assert_eq!(fake.early_sends.load(Ordering::SeqCst), 1);
    assert_eq!(fake.one_rtt_sends.load(Ordering::SeqCst), 0);
}
