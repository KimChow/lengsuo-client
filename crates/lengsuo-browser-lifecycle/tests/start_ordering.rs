//! Ordering, phase-skip and duplicate-completion behaviour of the start ladder.

mod support;

use lengsuo_browser_lifecycle::{LifecycleError, Phase, Rejected, Stage, Supervisor};
use support::{expect_rejected, identity, next_for_stored, Driver, BUDGET, START_CLOCK};

#[test]
fn new_supervisor_is_stopped_with_seeded_generation() {
    let sup = Supervisor::new(7);
    assert_eq!(sup.phase(), Phase::Stopped);
    assert_eq!(sup.stored_generation(), 7);
    assert_eq!(sup.current_run(), None);
    assert_eq!(sup.process(), None);
    assert!(sup.deadline().is_none());
    assert!(sup.pending_cleanup().is_none());
    assert!(!sup.resources().any_held());
    assert!(!sup.resources().cleanup_outstanding());
}

#[test]
fn begin_start_enters_authorizing_and_arms_first_deadline() {
    let mut h = Driver::new(0);
    let run = h.begin();
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert_eq!(h.sup().current_run(), Some(run));
    assert_eq!(h.sup().stored_generation(), 1, "generation not incremented");
    assert_eq!(run.value(), 1);
    let armed = h.sup().deadline().expect("authorization deadline armed");
    assert_eq!(armed.stage(), Stage::Authorization);
    assert_eq!(armed.deadline_ms(), START_CLOCK + BUDGET);
}

#[test]
fn duplicate_start_is_rejected_without_consuming_a_generation() {
    let mut h = Driver::new(3);
    let run = h.begin();
    let before = h.sup().stored_generation();
    let clock = h.now();
    expect_rejected(
        &h.sup_mut()
            .begin_start(next_for_stored(before), clock, BUDGET),
        LifecycleError::Run(Rejected::IllegalForPhase),
    );
    assert_eq!(
        h.sup().stored_generation(),
        before,
        "generation advanced twice"
    );
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert_eq!(h.sup().current_run(), Some(run));
}

#[test]
fn full_start_ladder_walks_every_phase_in_order() {
    let mut h = Driver::new(0);
    h.begin();
    assert_eq!(h.complete(Stage::Authorization), Phase::Installing);
    assert_eq!(h.sup().deadline().expect("armed").stage(), Stage::Install);
    assert_eq!(h.complete(Stage::Install), Phase::PreparingNetwork);
    assert!(h.sup().resources().install_held(), "artifact untracked");
    assert_eq!(h.complete(Stage::Network), Phase::StartingProcess);
    assert!(
        h.sup().resources().isolation_held(),
        "isolation must be recorded as established"
    );
    assert_eq!(h.spawn(42), Phase::Probing);
    assert_eq!(h.sup().process().expect("identity").pid(), 42);
    assert_eq!(h.complete(Stage::Probe), Phase::Running);
    assert_eq!(h.sup().deadline(), None, "no stage deadline while running");
    assert!(!h.sup().resources().cleanup_outstanding());
}

#[test]
fn install_cannot_be_completed_before_authorization() {
    let mut h = Driver::new(0);
    let run = h.begin();
    expect_rejected(
        &h.complete_with(run, Stage::Install),
        LifecycleError::Run(Rejected::StageMismatch),
    );
    assert_eq!(h.sup().phase(), Phase::Authorizing, "phase skipped");
    assert!(!h.sup().resources().install_held());
    assert_eq!(
        h.sup().deadline().expect("still armed").stage(),
        Stage::Authorization
    );
}

#[test]
fn network_cannot_be_completed_before_install() {
    let mut h = Driver::new(0);
    let run = h.begin();
    expect_rejected(
        &h.complete_with(run, Stage::Network),
        LifecycleError::Run(Rejected::StageMismatch),
    );
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert!(!h.sup().resources().isolation_held());
}

#[test]
fn spawn_identity_cannot_be_supplied_before_isolation() {
    let mut h = Driver::new(0);
    let run = h.begin();
    let clock = h.now();
    let outcome = h.sup_mut().report_identity(run, identity(9), clock, BUDGET);
    expect_rejected(&outcome, LifecycleError::Run(Rejected::StageMismatch));
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert_eq!(h.sup().process(), None, "identity adopted out of order");
}

#[test]
fn probe_cannot_be_completed_before_spawn_identity() {
    let mut h = Driver::new(0);
    h.begin();
    h.complete(Stage::Authorization);
    h.complete(Stage::Install);
    h.complete(Stage::Network);
    let run = h.run();
    expect_rejected(
        &h.complete_with(run, Stage::Probe),
        LifecycleError::Run(Rejected::StageMismatch),
    );
    assert_eq!(h.sup().phase(), Phase::StartingProcess);
}

#[test]
fn starting_process_refuses_a_bare_spawn_completion() {
    let mut h = Driver::new(0);
    h.begin();
    h.complete(Stage::Authorization);
    h.complete(Stage::Install);
    h.complete(Stage::Network);
    let run = h.run();
    // The only way out of StartingProcess is a real identity: no phase may be
    // entered with an unstarted process.
    expect_rejected(
        &h.complete_with(run, Stage::Spawn),
        LifecycleError::Run(Rejected::IllegalForPhase),
    );
    assert_eq!(h.sup().phase(), Phase::StartingProcess);
    assert_eq!(h.sup().process(), None);
    assert_eq!(h.sup().current_run(), Some(run));
}

#[test]
fn each_stage_completes_only_once() {
    let mut h = Driver::new(0);
    let run = h.begin();
    assert_eq!(h.complete(Stage::Authorization), Phase::Installing);
    expect_rejected(
        &h.complete_with(run, Stage::Authorization),
        LifecycleError::Run(Rejected::Duplicate),
    );
    assert_eq!(h.sup().phase(), Phase::Installing);
    assert_eq!(
        h.sup().deadline().expect("still armed").stage(),
        Stage::Install
    );
}

#[test]
fn stage_rank_increases_along_the_start_ladder() {
    let ranks = [
        Stage::Authorization.rank(),
        Stage::Install.rank(),
        Stage::Network.rank(),
        Stage::Spawn.rank(),
        Stage::Probe.rank(),
    ];
    for pair in ranks.windows(2) {
        assert!(pair[0] < pair[1], "ladder rank must increase");
    }
    assert!(!Stage::Teardown.is_start_stage());
    assert!(Stage::Probe.is_start_stage());
    assert!(Stage::Spawn.is_start_stage());
}

#[test]
fn running_rejects_a_bare_complete() {
    let mut h = Driver::new(0);
    let run = h.reach_running();
    expect_rejected(
        &h.complete_with(run, Stage::Probe),
        LifecycleError::Run(Rejected::IllegalForPhase),
    );
    assert_eq!(h.sup().phase(), Phase::Running);
}
