//! Run tokens: increment, staleness, future forging, exhaustion, persistence.

mod support;

use lengsuo_browser_lifecycle::{
    LifecycleError, Phase, Rejected, RunGeneration, Stage, Supervisor,
};
use support::{expect_rejected, wrap_counter, Driver, BUDGET};

#[test]
fn each_accepted_start_increments_the_generation_once() {
    let mut h = Driver::new(10);
    let first = h.begin();
    assert_eq!(first.value(), 11);
    h.timeout();
    h.cleanup();
    let second = h.begin();
    assert_eq!(second.value(), 12, "generation reused across restart");
    assert_eq!(h.sup().stored_generation(), 12);
}

#[test]
fn token_comparison_is_by_counter_not_by_identity_fields() {
    assert_eq!(wrap_counter(5), wrap_counter(5));
    assert_ne!(wrap_counter(5), wrap_counter(6));
    assert_eq!(wrap_counter(u64::MAX).value(), u64::MAX);
}

#[test]
fn stale_callback_from_the_previous_run_is_ignored_as_an_error() {
    let mut h = Driver::new(0);
    let old = h.begin();
    h.timeout();
    h.cleanup();
    assert_eq!(h.sup().phase(), Phase::Stopped);

    let _new = h.begin();
    expect_rejected(
        &h.complete_with(old, Stage::Authorization),
        LifecycleError::Run(Rejected::UnknownRun),
    );
    // The stale completion must not have moved the new run forward.
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert_eq!(
        h.sup().deadline().expect("armed").stage(),
        Stage::Authorization
    );
    assert!(!h.sup().resources().install_held());
}

#[test]
fn stale_callback_cannot_confirm_cleanup_of_a_later_run() {
    let mut h = Driver::new(4);
    let old = h.begin();
    h.timeout();
    h.cleanup();
    let _new = h.begin();
    expect_rejected(
        &h.cleanup_using(old),
        LifecycleError::Run(Rejected::UnknownRun),
    );
    assert_eq!(h.sup().phase(), Phase::Authorizing);
}

#[test]
fn future_token_is_rejected_without_mutating_state() {
    let mut h = Driver::new(0);
    h.begin();
    let future = RunGeneration::from_stored(h.sup().stored_generation() + 5);
    let phase_before = h.sup().phase();
    let clock_before = h.now();
    expect_rejected(
        &h.complete_with(future, Stage::Authorization),
        LifecycleError::Run(Rejected::UnknownRun),
    );
    assert_eq!(h.sup().phase(), phase_before);
    assert_eq!(h.now(), clock_before, "harness clock moved on rejection");
    assert_eq!(h.sup().stored_generation(), 1);
}

#[test]
fn begin_start_with_a_wrong_token_is_rejected_and_consumes_nothing() {
    let mut h = Driver::new(2);
    let wrong = wrap_counter(99);
    let clock = h.now();
    expect_rejected(
        &h.sup_mut().begin_start(wrong, clock, BUDGET),
        LifecycleError::Run(Rejected::UnknownRun),
    );
    assert_eq!(h.sup().phase(), Phase::Stopped);
    assert_eq!(
        h.sup().stored_generation(),
        2,
        "generation consumed by a rejection"
    );
    assert_eq!(h.sup().current_run(), None);
}

#[test]
fn generation_overflow_refuses_to_start_a_new_run() {
    let mut sup = Supervisor::new(u64::MAX);
    assert_eq!(sup.phase(), Phase::Stopped);
    assert_eq!(sup.stored_generation(), u64::MAX);
    let outcome = sup.begin_start(wrap_counter(0), 1_000, BUDGET);
    match outcome {
        Err(LifecycleError::GenerationExhausted) => {}
        other => panic!("expected GenerationExhausted, got {other:?}"),
    }
    assert_eq!(sup.phase(), Phase::Stopped);
    assert_eq!(sup.stored_generation(), u64::MAX);
    assert_eq!(sup.current_run(), None);
    assert!(!sup.resources().cleanup_outstanding());
}

#[test]
fn checked_add_on_a_token_wraps_nothing_and_reports_none() {
    let top = RunGeneration::from_stored(u64::MAX);
    assert_eq!(top.checked_add(1), None);
    assert_eq!(top.checked_add(0), Some(top));
    assert_eq!(
        RunGeneration::from_stored(5).checked_add(3),
        Some(RunGeneration::from_stored(8))
    );
    assert_eq!(
        RunGeneration::from_stored(7)
            .checked_next()
            .map(|t| t.value()),
        Some(8)
    );
    assert_eq!(top.checked_next(), None);
}

#[test]
fn generation_survives_a_full_stop_cleanup_restart_cycle() {
    let mut sup = Supervisor::new(0);
    let mut seen = vec![sup.stored_generation()];
    for round in 1..=4 {
        let wanted = RunGeneration::next_for(sup.stored_generation()).expect("counter");
        sup.begin_start(wanted, 1_000 * round, 100)
            .expect("start accepted");
        sup.timeout(1_000 * round + 200).expect("timeout accepted");
        sup.cleanup_completed(wanted, 1_000 * round + 300)
            .expect("cleanup accepted");
        seen.push(sup.stored_generation());
        assert_eq!(sup.phase(), Phase::Stopped);
        // Never reusable: every later run must out-number every earlier token.
        assert_eq!(sup.stored_generation(), round);
    }
    let distinct: std::collections::HashSet<u64> = seen.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        seen.len(),
        "generation values repeated: {seen:?}"
    );
}

#[test]
fn stopping_a_run_never_reissues_the_same_token() {
    let mut h = Driver::new(0);
    let mut tokens = Vec::new();
    for _ in 0..3 {
        let run = h.begin();
        tokens.push(run.value());
        h.timeout();
        h.cleanup();
        assert_eq!(h.sup().phase(), Phase::Stopped);
    }
    tokens.dedup();
    assert_eq!(tokens.len(), 3, "tokens reused: {tokens:?}");
}

#[test]
fn next_for_reports_exhaustion_at_the_limit() {
    assert_eq!(
        RunGeneration::next_for(u64::MAX - 1).unwrap().value(),
        u64::MAX
    );
    assert!(RunGeneration::next_for(u64::MAX).is_err());
    if let Err(err) = RunGeneration::next_for(u64::MAX) {
        assert_eq!(err, LifecycleError::GenerationExhausted);
        assert_eq!(err.code(), "generation:exhausted");
    }
}

#[test]
fn completed_run_still_holds_its_token_for_stop_and_cleanup() {
    let mut h = Driver::new(0);
    let run = h.reach_running();
    let (phase, demand) = h.stop();
    assert_eq!(phase, Phase::Stopping);
    assert!(demand.is_some(), "isolation was established");
    assert_eq!(h.sup().current_run(), Some(run), "token dropped too early");
    assert_eq!(h.cleanup(), Phase::Stopped);
    assert_eq!(h.sup().current_run(), None);
}
