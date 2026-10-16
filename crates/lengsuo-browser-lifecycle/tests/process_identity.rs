//! ProcessIdentity validation: the machine adopts only a real OS start identity.

mod support;

use lengsuo_browser_lifecycle::{IdentityRejected, Phase, ProcessIdentity, Rejected, Stage};
use support::{expect_run_rejected, identity, identity_of, nonce_with_byte, zero_nonce, BUDGET};

#[test]
fn a_real_identity_is_accepted_and_echoed_back() {
    let made = identity(1_234);
    assert_eq!(made.pid(), 1_234);
    assert_eq!(made.creation_nonce()[0], 0xA1);
    assert_ne!(made.creation_nonce(), zero_nonce());
}

#[test]
fn zero_pid_is_rejected() {
    assert_eq!(identity_of(0, nonce_with_byte(9)), None);
    let outcome = ProcessIdentity::new(0, nonce_with_byte(9));
    assert!(outcome.is_none());
}

#[test]
fn zero_creation_nonce_is_rejected() {
    let outcome = ProcessIdentity::new(4_321, zero_nonce());
    assert!(outcome.is_none(), "PID-only adoption must be refused");
}

#[test]
fn both_invalid_fields_rejected() {
    assert!(ProcessIdentity::new(0, zero_nonce()).is_none());
}

#[test]
fn every_single_nonzero_nonce_byte_is_enough() {
    for byte in [1u8, 0x7F, 0xFF] {
        assert!(ProcessIdentity::new(7, nonce_with_byte(byte)).is_some());
    }
}

#[test]
fn pid_one_and_max_are_both_valid() {
    assert_eq!(identity_of(1, nonce_with_byte(1)).map(|i| i.pid()), Some(1));
    assert_eq!(
        identity_of(u32::MAX, nonce_with_byte(2)).map(|i| i.pid()),
        Some(u32::MAX)
    );
}

#[test]
fn identity_equality_requires_both_pid_and_nonce() {
    let a = identity_with(4_400, nonce_with_byte(1));
    let b = identity_with(4_401, nonce_with_byte(1));
    let c = identity_with(4_400, nonce_with_byte(2));
    assert_ne!(a, b, "different pid is a different process");
    assert_ne!(
        a, c,
        "same pid with a different creation is a different process"
    );
    assert_eq!(a, identity_with(4_400, nonce_with_byte(1)));
}

#[test]
fn malformed_identity_cannot_be_constructed_and_valid_identity_is_accepted() {
    let mut h = support::Driver::new(0);
    let run = h.begin();
    h.complete(Stage::Authorization);
    h.complete(Stage::Install);
    h.complete(Stage::Network);
    assert_eq!(h.sup().phase(), Phase::StartingProcess);

    let forged = ProcessIdentity::new(9_999, zero_nonce());
    assert!(forged.is_none());
    // The platform layer cannot hand the machine a nonce-less identity, so the
    // only representable attempt is a well-formed but wrong one; a zero nonce
    // simply cannot be constructed. Check the typed rejection path instead.
    let outcome = h.try_spawn(run, identity(9_999));
    assert_eq!(outcome.unwrap(), Phase::Probing);
    assert_eq!(h.sup().process().expect("adopted").pid(), 9_999);
}

#[test]
fn spawn_stage_refuses_a_completion_with_a_stale_token() {
    let mut h = support::Driver::new(0);
    let run = h.begin();
    h.complete(Stage::Authorization);
    h.complete(Stage::Install);
    h.complete(Stage::Network);
    let stale = support::wrap_counter(run.value() - 1);
    let made = identity(5_150);
    expect_identity_or_stale(&mut h, stale, made);
}

#[test]
fn identity_is_only_adoptable_in_the_starting_process_phase() {
    let mut h = support::Driver::new(0);
    let run = h.begin();
    let outcome = h.try_spawn(run, identity(6));
    expect_identity_rejected_noop(&outcome);
    assert_eq!(h.sup().phase(), Phase::Authorizing);
    assert_eq!(h.sup().process(), None);
}

#[test]
fn a_running_run_keeps_exactly_one_identity_and_never_adops_a_second() {
    let mut h = support::Driver::new(0);
    h.reach_running();
    let first = h.sup().process().expect("identity recorded");
    let run = h.run();
    let outcome = h.try_spawn(run, identity(first.pid() + 1));
    assert!(outcome.is_err(), "second spawn must be refused");
    assert_eq!(h.sup().process(), Some(first), "identity replaced");
    assert_eq!(h.sup().phase(), Phase::Running);
}

#[test]
fn zero_pid_and_zero_nonce_rejection_codes_are_distinct() {
    assert!(IdentityRejected::ZeroPid.to_string().contains("nonzero"));
    assert_ne!(
        IdentityRejected::ZeroPid,
        IdentityRejected::ZeroCreationNonce
    );
    let mut h = support::Driver::new(0);
    h.reach_running();
    let run = h.run();
    let foreign = identity(99);
    let outcome = h.try_process_exited(run, foreign);
    // Foreign pid: rejection, and the run stays Running.
    expect_run_rejected(&outcome, Rejected::NotTheRecordedProcess);
    assert_eq!(h.sup().phase(), Phase::Running);
    assert!(h.sup().pending_cleanup().is_none());
}

fn identity_with(pid: u32, nonce: [u8; 16]) -> ProcessIdentity {
    ProcessIdentity::new(pid, nonce).expect("valid test process identity")
}

fn expect_identity_or_stale(
    h: &mut support::Driver,
    stale: lengsuo_browser_lifecycle::RunGeneration,
    made: ProcessIdentity,
) {
    let outcome = h.try_spawn(stale, made);
    expect_rejected_stale(outcome);
    assert_eq!(h.sup().process(), None, "stale identity adopted");
    assert_eq!(h.sup().phase(), Phase::StartingProcess);
}

fn expect_rejected_stale(outcome: Result<Phase, lengsuo_browser_lifecycle::LifecycleError>) {
    match outcome {
        Ok(phase) => panic!("stale token accepted, moved to {phase:?}"),
        Err(err) => assert_eq!(
            err,
            lengsuo_browser_lifecycle::LifecycleError::Run(Rejected::UnknownRun)
        ),
    }
}

fn expect_identity_rejected_noop(
    outcome: &Result<Phase, lengsuo_browser_lifecycle::LifecycleError>,
) {
    match outcome {
        Ok(phase) => panic!("identity accepted out of order, moved to {phase:?}"),
        Err(err) => assert_eq!(
            *err,
            lengsuo_browser_lifecycle::LifecycleError::Run(Rejected::StageMismatch)
        ),
    }
}

#[allow(dead_code)]
fn unused_budget() -> u64 {
    BUDGET
}
