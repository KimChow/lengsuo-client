//! Injected-clock rules: exact expiry boundary, zero/overflow budgets,
//! backwards observations, and no wall-clock reads.

mod support;

use lengsuo_browser_lifecycle::{
    DeadlineRejected, LifecycleError, Phase, Rejected, Stage, Supervisor,
};
use support::{expect_deadline_rejected, expect_rejected, BUDGET, START_CLOCK};

#[test]
fn deadline_is_armed_from_the_injected_clock_and_budget() {
    let mut sup = Supervisor::new(0);
    sup.begin_start(
        lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap(),
        START_CLOCK,
        2_500,
    )
    .expect("start accepted");
    let armed = sup.deadline().expect("deadline armed");
    assert_eq!(armed.deadline_ms(), START_CLOCK + 2_500);
    assert_eq!(armed.stage(), Stage::Authorization);
}

#[test]
fn expiry_boundary_is_inclusive_and_exact() {
    let mut h = support::Driver::new(0);
    h.begin();
    // Deadline starts at begin_start observation, before the harness advances.
    let expires_at = h.sup().deadline().expect("armed").deadline_ms();
    assert_eq!(expires_at, START_CLOCK + BUDGET);

    assert_eq!(
        h.deadline_check_at(expires_at - 1).unwrap(),
        None,
        "one millisecond early must not fail the run"
    );
    assert_eq!(h.sup().phase(), Phase::Authorizing);

    let demand = h
        .deadline_check_at(expires_at)
        .unwrap()
        .expect("expiry at the exact deadline");
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert!(!demand.isolation_established());
    assert_eq!(demand.identity(), None);
    assert_eq!(h.sup().pending_cleanup(), Some(demand));
    assert!(h.sup().resources().cleanup_outstanding());
    assert!(h.sup().deadline().is_none(), "deadline cleared on expiry");
}

#[test]
fn deadline_check_one_tick_early_leaves_the_run_untouched() {
    let mut h = support::Driver::new(0);
    let run = h.begin();
    let expires_at = h.sup().deadline().expect("armed").deadline_ms();
    assert_eq!(h.deadline_check_at(expires_at - 1).unwrap(), None);
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert_eq!(h.sup().current_run(), Some(run));
    assert_eq!(h.sup().pending_cleanup(), None);
}

#[test]
fn zero_budget_is_rejected_without_consuming_a_generation() {
    let mut sup = Supervisor::new(5);
    let outcome = sup.begin_start(
        lengsuo_browser_lifecycle::RunGeneration::next_for(5).unwrap(),
        1_000,
        0,
    );
    expect_deadline_rejected(&outcome, DeadlineRejected::ZeroBudget);
    assert_eq!(sup.phase(), Phase::Stopped);
    assert_eq!(sup.stored_generation(), 5);
    assert_eq!(sup.current_run(), None);
}

#[test]
fn overflowing_budget_is_rejected_without_partial_mutation() {
    let mut h = support::Driver::new(0);
    h.begin();
    let run = h.run();
    let outcome = h.complete_using(run, Stage::Authorization, u64::MAX);
    expect_deadline_rejected(&outcome, DeadlineRejected::Overflow);
    // The authorization stage must NOT have advanced.
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert_eq!(
        h.sup().deadline().expect("still armed").stage(),
        Stage::Authorization
    );
}

#[test]
fn overflowing_budget_is_rejected_at_start_too() {
    let mut sup = Supervisor::new(0);
    let outcome = sup.begin_start(
        lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap(),
        u64::MAX,
        1,
    );
    expect_deadline_rejected(&outcome, DeadlineRejected::Overflow);
    assert_eq!(sup.phase(), Phase::Stopped);
    assert_eq!(sup.stored_generation(), 0);
}

#[test]
fn zero_budget_on_a_later_stage_does_not_advance_the_ladder() {
    let mut h = support::Driver::new(0);
    h.begin();
    let run = h.run();
    expect_deadline_rejected(
        &h.complete_using(run, Stage::Authorization, 0),
        DeadlineRejected::ZeroBudget,
    );
    assert_eq!(h.sup().phase(), Phase::Authorizing);
}

#[test]
fn backwards_observation_clock_is_rejected_and_state_is_unchanged() {
    let mut sup = Supervisor::new(0);
    let wanted = lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap();
    sup.begin_start(wanted, 10_000, BUDGET)
        .expect("start accepted");
    let before = sup.phase();
    let outcome = sup.complete(wanted, Stage::Authorization, 9_999, BUDGET);
    expect_deadline_rejected(&outcome, DeadlineRejected::Backwards);
    assert_eq!(sup.phase(), before);
    assert_eq!(sup.stored_generation(), 1);
    assert_eq!(
        sup.deadline().expect("armed").deadline_ms(),
        10_000 + BUDGET
    );
}

#[test]
fn backwards_clock_is_rejected_for_deadline_observation() {
    let mut sup = Supervisor::new(0);
    let wanted = lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap();
    sup.begin_start(wanted, 8_000, BUDGET)
        .expect("start accepted");
    let outcome = sup.deadline_expired(7_999);
    expect_deadline_rejected(&outcome, DeadlineRejected::Backwards);
    assert_eq!(sup.phase(), Phase::Authorizing);
    assert!(sup.pending_cleanup().is_none());
}

#[test]
fn backwards_clock_is_rejected_for_timeout() {
    let mut sup = Supervisor::new(0);
    let wanted = lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap();
    sup.begin_start(wanted, 5_000, BUDGET)
        .expect("start accepted");
    let outcome = sup.timeout(4_999);
    expect_deadline_rejected(&outcome, DeadlineRejected::Backwards);
    assert_eq!(sup.phase(), Phase::Authorizing);
    assert!(sup.pending_cleanup().is_none());
}

#[test]
fn equal_clock_is_accepted_as_not_moving_backwards() {
    let mut sup = Supervisor::new(0);
    let wanted = lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap();
    sup.begin_start(wanted, 3_000, BUDGET)
        .expect("start accepted");
    // Same millisecond observation: allowed, and the stage is still in time.
    assert_eq!(sup.deadline_expired(3_000).unwrap(), None);
    assert_eq!(sup.phase(), Phase::Authorizing);
}

#[test]
fn each_accepted_stage_rearms_the_deadline_for_the_next_stage() {
    let mut sup = Supervisor::new(0);
    let wanted = lengsuo_browser_lifecycle::RunGeneration::next_for(0).unwrap();
    sup.begin_start(wanted, 1_000, 100).expect("start");
    assert_eq!(sup.deadline().expect("armed").deadline_ms(), 1_100);
    sup.complete(wanted, Stage::Authorization, 1_050, 200)
        .expect("authorization done");
    let armed = sup.deadline().expect("rearmed");
    assert_eq!(armed.stage(), Stage::Install);
    assert_eq!(
        armed.deadline_ms(),
        1_250,
        "budget is relative to observation"
    );
    sup.complete(wanted, Stage::Install, 1_100, 300)
        .expect("install done");
    assert_eq!(sup.deadline().expect("rearmed").stage(), Stage::Network);
}

#[test]
fn expiry_while_installing_reports_install_held_but_no_isolation() {
    let mut h = support::Driver::new(0);
    h.begin();
    h.complete(Stage::Authorization);
    assert_eq!(h.sup().phase(), Phase::Installing);
    let expiry = h.sup().deadline().expect("armed").deadline_ms();
    let demand = h.deadline_check_at(expiry).unwrap().expect("expiry demand");
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert!(!demand.isolation_established());
    assert_eq!(demand.identity(), None);
    assert!(h.sup().resources().install_held());
    // Install artifact is unaccounted for: restart is blocked until cleanup.
    let wanted = h.seeded_next();
    let clock = h.now();
    expect_rejected(
        &h.sup_mut().begin_start(wanted, clock, BUDGET),
        LifecycleError::Run(Rejected::IllegalForPhase),
    );
    assert_eq!(h.sup().phase(), Phase::Failed);
    h.cleanup();
    assert_eq!(h.sup().phase(), Phase::Stopped);
    assert!(!h.sup().resources().install_held());
}

#[test]
fn expiry_after_isolation_reports_both_isolation_and_identity() {
    let mut h = support::Driver::new(0);
    h.begin();
    h.complete(Stage::Authorization);
    h.complete(Stage::Install);
    h.complete(Stage::Network);
    let run = h.run();
    let expiry = h.sup().deadline().expect("armed").deadline_ms();
    let demand = h
        .deadline_check_at(expiry)
        .unwrap()
        .expect("spawn never reported");
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert!(demand.isolation_established());
    assert_eq!(demand.identity(), None);
    assert_eq!(demand.run(), run);
    assert_eq!(h.sup().current_run(), Some(run), "token needed for cleanup");
}
