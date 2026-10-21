// ② `ZeroRttOutcome` 三态映射与拒绝的可观测性。
// ---- ② ZeroRttOutcome 三态映射 ----

#[test]
fn outcome_three_states_map_correctly() {
    assert_eq!(
        ZeroRttOutcome::from_handshake(false, true),
        ZeroRttOutcome::NotAttempted,
        "未尝试时即使握手成功也不是 Accepted"
    );
    assert_eq!(
        ZeroRttOutcome::from_handshake(true, true),
        ZeroRttOutcome::Accepted
    );
    assert_eq!(
        ZeroRttOutcome::from_handshake(true, false),
        ZeroRttOutcome::Rejected(ZeroRttRejected)
    );
    assert!(ZeroRttOutcome::from_handshake(true, false).is_rejected());
    assert!(!ZeroRttOutcome::from_handshake(true, true).is_rejected());

    let pending = ZeroRttStatus::attempted();
    assert_eq!(pending.current(), None, "握手完成前必须为 pending");
    pending.record(false);
    assert_eq!(
        pending.current(),
        Some(ZeroRttOutcome::Rejected(ZeroRttRejected))
    );
    let not_attempted = ZeroRttStatus::not_attempted();
    assert_eq!(not_attempted.current(), Some(ZeroRttOutcome::NotAttempted));
}

#[tokio::test]
async fn status_wait_observes_rejection() {
    let status = ZeroRttStatus::attempted();
    let recorder = status.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        recorder.record(false);
    });
    assert_eq!(
        status.wait().await,
        ZeroRttOutcome::Rejected(ZeroRttRejected),
        "拒绝必须可观测，不得静默吞掉"
    );
}
