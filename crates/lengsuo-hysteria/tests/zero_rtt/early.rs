// ③ 非幂等操作在 0-RTT 路径 fail-closed（不得静默改走 1-RTT）。
// ---- ③ 非幂等操作在 0-RTT 路径 fail-closed ----

#[derive(Default)]
struct FakeConn {
    early_sends: AtomicUsize,
    one_rtt_sends: AtomicUsize,
}

#[test]
fn non_idempotent_is_rejected_without_sending() {
    let fake = FakeConn::default();
    let result: Result<((), ZeroRttOutcome), EarlyError<&'static str>> = run_early(
        OperationKind::NonIdempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        true,
    );
    assert_eq!(result, Err(EarlyError::NonIdempotent));
    assert_eq!(fake.early_sends.load(Ordering::SeqCst), 0, "早数据不得发送");
    assert_eq!(
        fake.one_rtt_sends.load(Ordering::SeqCst),
        0,
        "不得静默改走 1-RTT"
    );
}
