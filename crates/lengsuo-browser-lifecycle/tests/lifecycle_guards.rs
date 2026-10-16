mod support;

use lengsuo_browser_lifecycle::{Failure, LifecycleError, Phase, Rejected, Stage};
use support::{identity, Driver, BUDGET};

#[test]
fn stop_requires_cleanup_at_every_live_start_phase() {
    for phase in [
        Phase::Authorizing,
        Phase::Installing,
        Phase::PreparingNetwork,
        Phase::StartingProcess,
        Phase::Probing,
        Phase::Running,
    ] {
        let mut h = Driver::new(0);
        h.reach_phase(phase);
        let run = h.run();
        let generation = h.sup().stored_generation();
        let (stopping, cleanup) = h.stop();
        assert_eq!(stopping, Phase::Stopping);
        assert_eq!(cleanup.unwrap().run(), run);
        assert!(h.sup().resources().cleanup_outstanding());
        let wanted = h.seeded_next();
        let now = h.now();
        assert_eq!(
            h.sup_mut().begin_start(wanted, now, BUDGET),
            Err(LifecycleError::Run(Rejected::IllegalForPhase))
        );
        assert_eq!(h.cleanup(), Phase::Stopped);
        assert!(!h.sup().resources().any_held());
        assert_eq!(h.sup().stored_generation(), generation);
        assert_eq!(h.begin().value(), generation + 1);
    }
}

#[test]
fn install_failure_keeps_staging_accounted_without_claiming_isolation() {
    let mut h = Driver::new(0);
    h.reach_phase(Phase::Installing);
    let run = h.run();
    let now = h.now();
    let cleanup = h.sup_mut().stage_failed(run, Stage::Install, now).unwrap();
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert!(h.sup().resources().install_held());
    assert!(!cleanup.isolation_established());
    assert_eq!(cleanup.identity(), None);
    assert_eq!(
        h.sup().last_error(),
        Some(LifecycleError::Failure(Failure::StageFailed(
            Stage::Install
        )))
    );
}

#[test]
fn network_loss_fails_closed_in_running_and_retains_exact_process() {
    let mut h = Driver::new(0);
    h.reach_running();
    let process = h.sup().process();
    let demand = h.network_lost();
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert!(demand.isolation_established());
    assert_eq!(demand.identity(), process);
    assert_eq!(h.sup().process(), process);
    assert!(h.sup().resources().cleanup_outstanding());
}

#[test]
fn revocation_aborts_authorization_and_running_without_clearing_resources() {
    for phase in [Phase::Authorizing, Phase::Running] {
        let mut h = Driver::new(0);
        h.reach_phase(phase);
        let process = h.sup().process();
        let demand = h.revoked();
        assert_eq!(h.sup().phase(), Phase::Failed);
        assert_eq!(demand.identity(), process);
        assert!(h.sup().resources().cleanup_outstanding());
    }
}

#[test]
fn late_spawn_identity_is_retained_for_cleanup_instead_of_being_lost() {
    let mut h = Driver::new(0);
    h.reach_phase(Phase::StartingProcess);
    let expiry = h.sup().deadline().unwrap().deadline_ms();
    let run = h.run();
    let process = identity(901);
    assert_eq!(
        h.sup_mut().report_identity(run, process, expiry, BUDGET),
        Err(LifecycleError::Failure(Failure::DeadlineExpired))
    );
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert_eq!(h.sup().pending_cleanup().unwrap().identity(), Some(process));
}

#[test]
fn late_network_readiness_retains_isolation_for_cleanup() {
    let mut h = Driver::new(0);
    h.reach_phase(Phase::PreparingNetwork);
    let expiry = h.sup().deadline().unwrap().deadline_ms();
    let run = h.run();
    assert!(h
        .sup_mut()
        .complete(run, Stage::Network, expiry, BUDGET)
        .is_err());
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert!(h.sup().pending_cleanup().unwrap().isolation_established());
}

#[test]
fn stale_callback_and_backwards_cleanup_cannot_change_a_stopping_run() {
    let mut h = Driver::new(0);
    h.reach_running();
    h.stop();
    let before = format!("{:?}", h.sup());
    let run = h.run();
    let stale = lengsuo_browser_lifecycle::RunGeneration::from_stored(run.value() - 1);
    assert!(h.cleanup_using(stale).is_err());
    assert_eq!(format!("{:?}", h.sup()), before);
    assert!(h.sup_mut().cleanup_completed(run, 0).is_err());
    assert_eq!(format!("{:?}", h.sup()), before);
    assert_eq!(h.cleanup(), Phase::Stopped);
}

#[test]
fn reused_pid_with_a_different_creation_nonce_cannot_report_exit() {
    let mut h = Driver::new(0);
    h.reach_running();
    let recorded = h.sup().process().unwrap();
    let other = lengsuo_browser_lifecycle::ProcessIdentity::new(recorded.pid(), [7; 16]).unwrap();
    let run = h.run();
    let before = format!("{:?}", h.sup());
    assert!(h.try_process_exited(run, other).is_err());
    assert_eq!(format!("{:?}", h.sup()), before);
}

#[test]
fn teardown_has_a_deadline_and_expiry_never_claims_cleanup_succeeded() {
    let mut h = Driver::new(0);
    let run = h.reach_running();
    let process = h.sup().process();
    let now = h.now();
    h.sup_mut().stop_with_budget(run, now, 7).unwrap();
    assert_eq!(h.sup().deadline().unwrap().stage(), Stage::Teardown);
    let demand = h
        .sup_mut()
        .deadline_expired_for(run, now + 7)
        .unwrap()
        .unwrap();
    assert_eq!(h.sup().phase(), Phase::Failed);
    assert_eq!(demand.identity(), process);
    assert!(h.sup().resources().cleanup_outstanding());
    assert_eq!(
        h.sup_mut().cleanup_completed(run, now + 8).unwrap(),
        Phase::Stopped
    );
}

#[test]
fn invalid_teardown_budget_has_no_partial_mutation() {
    let mut h = Driver::new(0);
    let run = h.reach_running();
    let now = h.now();
    let before = format!("{:?}", h.sup());
    assert!(h.sup_mut().stop_with_budget(run, now, 0).is_err());
    assert_eq!(format!("{:?}", h.sup()), before);
    assert!(h.sup_mut().stop_with_budget(run, u64::MAX, 1).is_err());
    assert_eq!(format!("{:?}", h.sup()), before);
}

#[test]
fn stale_watchdog_cannot_fail_a_new_generation() {
    let mut h = Driver::new(0);
    let old = h.reach_running();
    h.stop();
    h.cleanup();
    h.reach_running();
    let before = format!("{:?}", h.sup());
    let now = h.now();
    assert!(h.sup_mut().deadline_expired_for(old, now + BUDGET).is_err());
    assert!(h.sup_mut().timeout_for(old, now).is_err());
    assert_eq!(format!("{:?}", h.sup()), before);
}
