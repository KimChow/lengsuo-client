//! Shared test harness: fixed injected clock, forged tokens and full-state
//! snapshots used to prove that rejected operations mutate nothing.

#![allow(dead_code)]

use lengsuo_browser_lifecycle::{
    ArmedDeadline, CleanupRequired, DeadlineRejected, IdentityRejected, LifecycleError, Phase,
    ProcessIdentity, Rejected, ResourceOwnership, RunGeneration, Stage, Supervisor,
};

pub const BUDGET: u64 = 1_000;
pub const ZERO: RunGeneration = RunGeneration::from_stored(0);

pub fn wrap_counter(value: u64) -> RunGeneration {
    RunGeneration::from_stored(value)
}

pub fn zero_nonce() -> [u8; 16] {
    [0; 16]
}

pub fn nonce_with_byte(byte: u8) -> [u8; 16] {
    let mut nonce = [0; 16];
    nonce[0] = byte;
    nonce
}

pub fn identity_with_nonce(pid: u32, nonce: [u8; 16]) -> ProcessIdentity {
    ProcessIdentity::new(pid, nonce).expect("test identity must be valid")
}

pub fn identity(pid: u32) -> ProcessIdentity {
    identity_with_nonce(pid, nonce_with_byte(0xA1))
}

pub fn identity_of(pid: u32, nonce: [u8; 16]) -> Option<ProcessIdentity> {
    ProcessIdentity::new(pid, nonce)
}

/// Everything observable about a supervisor, compared for rollback proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub stored_generation: u64,
    pub current_run: Option<RunGeneration>,
    pub process: Option<ProcessIdentity>,
    pub resources: ResourceOwnership,
    pub deadline: Option<ArmedDeadline>,
    pub pending_cleanup: Option<CleanupRequired>,
    pub last_error: Option<LifecycleError>,
}

/// Driver owning one supervisor and one monotonic injected clock.
pub struct Driver {
    sup: Supervisor,
    clock: u64,
}

impl Driver {
    pub fn new(seed: u64) -> Self {
        Self {
            sup: Supervisor::new(seed),
            clock: 0,
        }
    }

    pub fn now(&self) -> u64 {
        self.clock
    }

    pub fn advance(&mut self) {
        self.clock += 1;
    }

    pub fn at(&mut self, clock: u64) {
        self.clock = clock;
    }

    pub fn sup(&self) -> &Supervisor {
        &self.sup
    }

    pub fn sup_mut(&mut self) -> &mut Supervisor {
        &mut self.sup
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            phase: self.sup.phase(),
            stored_generation: self.sup.stored_generation(),
            current_run: self.sup.current_run(),
            process: self.sup.process(),
            resources: self.sup.resources(),
            deadline: self.sup.deadline(),
            pending_cleanup: self.sup.pending_cleanup(),
            last_error: self.sup.last_error(),
        }
    }

    /// Token of the open run.
    pub fn run(&self) -> RunGeneration {
        self.sup.current_run().expect("no open run")
    }

    /// Counter value a successful start is expected to issue.
    pub fn next_wanted(&self) -> u64 {
        self.sup.stored_generation().wrapping_add(1)
    }

    pub fn begin(&mut self) -> RunGeneration {
        let wanted = self.next_wanted();
        let clock = self.now();
        self.sup
            .begin_start(wanted, clock, BUDGET)
            .expect("begin_start must be accepted")
    }

    pub fn begin_expect_err(&mut self, expected: LifecycleError) {
        let wanted = self.next_wanted();
        let clock = self.now();
        let outcome = self.sup.begin_start(wanted, clock, BUDGET);
        expect_rejected_gen(&outcome, expected);
    }

    pub fn complete(&mut self, stage: Stage) -> Phase {
        let outcome = self.try_complete(stage);
        outcome.expect("in-order completion must be accepted")
    }

    pub fn try_complete(&mut self, stage: Stage) -> Result<Phase, LifecycleError> {
        let run = self.run();
        self.advance();
        self.sup.complete(run, stage, self.now(), BUDGET)
    }

    pub fn complete_with(&mut self, stage: Stage, budget: u64) -> Result<Phase, LifecycleError> {
        let run = self.run();
        self.advance();
        self.sup.complete(run, stage, self.now(), budget)
    }

    pub fn complete_expect_err(&mut self, stage: Stage, expected: Rejected) {
        let before = self.snapshot();
        let run = self.run();
        self.advance();
        let outcome = self.sup.complete(run, stage, self.now(), BUDGET);
        expect_rejected(&outcome, LifecycleError::Run(expected));
        assert_eq!(self.snapshot(), before, "rejection mutated state");
    }

    pub fn spawn(&mut self, token: RunGeneration, made: ProcessIdentity) -> Phase {
        self.advance();
        self.sup
            .report_identity(token, made, self.now(), BUDGET)
            .expect("identity must be adopted")
    }

    pub fn try_spawn(
        &mut self,
        token: RunGeneration,
        made: ProcessIdentity,
    ) -> Result<Phase, LifecycleError> {
        self.advance();
        self.sup.report_identity(token, made, self.now(), BUDGET)
    }

    /// Drives the full legal ladder and returns the adopted identity.
    pub fn reach_running(&mut self) -> ProcessIdentity {
        let token = self.run();
        self.complete(Stage::Authorization);
        self.complete(Stage::Install);
        self.complete(Stage::Network);
        let made = identity(4_096);
        self.spawn(token, made);
        self.complete(Stage::Probe);
        assert_eq!(self.sup.phase(), Phase::Running);
        made
    }

    pub fn deadline_check(&mut self) -> Result<Option<CleanupRequired>, LifecycleError> {
        let clock = self.now();
        self.sup.deadline_expired(clock)
    }

    pub fn check_now(&mut self, clock: u64) -> Result<Option<CleanupRequired>, LifecycleError> {
        self.clock = clock;
        self.sup.deadline_expired(clock)
    }

    pub fn timeout(&mut self) -> CleanupRequired {
        let clock = self.now();
        self.sup.timeout(clock).expect("timeout must be accepted")
    }

    pub fn timeout_at(&mut self, clock: u64) -> Result<CleanupRequired, LifecycleError> {
        self.clock = clock;
        self.sup.timeout(clock)
    }

    pub fn network_lost(&mut self) -> CleanupRequired {
        let token = self.run();
        let clock = self.now();
        self.sup
            .network_lost(token, clock)
            .expect("network loss must be accepted")
    }

    pub fn revoked(&mut self) -> CleanupRequired {
        let token = self.run();
        let clock = self.now();
        self.sup
            .authorization_revoked(token, clock)
            .expect("revocation must be accepted")
    }

    pub fn process_exited(
        &mut self,
        token: RunGeneration,
        made: ProcessIdentity,
    ) -> Result<CleanupRequired, LifecycleError> {
        let clock = self.now();
        self.sup.process_exited(token, made, clock)
    }

    pub fn try_process_exited(
        &mut self,
        token: RunGeneration,
        made: ProcessIdentity,
    ) -> Result<CleanupRequired, LifecycleError> {
        self.process_exited(token, made)
    }

    pub fn stop(&mut self, token: RunGeneration) -> Result<Phase, LifecycleError> {
        let clock = self.now();
        self.sup.stop(token, clock)
    }

    pub fn stop_now(&mut self) -> Phase {
        let token = self.run();
        self.stop(token).expect("stop must be accepted")
    }

    pub fn cleanup(&mut self, token: RunGeneration) -> Result<Phase, LifecycleError> {
        let clock = self.now();
        self.sup.cleanup_completed(token, clock)
    }

    pub fn cleanup_ok(&mut self, token: RunGeneration) -> Phase {
        self.cleanup(token).expect("cleanup must be accepted")
    }

    pub fn next_run(&mut self, wanted: u64) -> Result<RunGeneration, LifecycleError> {
        let clock = self.now();
        self.sup.begin_start(wanted, clock, BUDGET)
    }
}

pub fn expect_rejected(outcome: &Result<Phase, LifecycleError>, expected: LifecycleError) {
    match outcome {
        Ok(phase) => panic!("expected {expected:?}, accepted transition to {phase:?}"),
        Err(err) => assert_eq!(*err, expected, "wrong rejection code"),
    }
}

pub fn expect_rejected_gen(
    outcome: &Result<RunGeneration, LifecycleError>,
    expected: LifecycleError,
) {
    match outcome {
        Ok(token) => panic!("expected {expected:?}, accepted new run {token:?}"),
        Err(err) => assert_eq!(*err, expected, "wrong rejection code"),
    }
}

pub fn expect_rejected_cleanup(
    outcome: &Result<CleanupRequired, LifecycleError>,
    expected: LifecycleError,
) {
    match outcome {
        Ok(demand) => panic!("expected {expected:?}, accepted cleanup {demand:?}"),
        Err(err) => assert_eq!(*err, expected, "wrong rejection code"),
    }
}

pub fn expect_identity_rejected(
    outcome: &Result<CleanupRequired, LifecycleError>,
    expected: IdentityRejected,
) {
    match outcome {
        Ok(_) => panic!("expected identity rejection {expected:?}, got cleanup demand"),
        Err(err) => assert_eq!(*err, LifecycleError::Identity(expected)),
    }
}

pub fn expect_deadline_rejected(
    outcome: &Result<Phase, LifecycleError>,
    expected: DeadlineRejected,
) {
    match outcome {
        Ok(phase) => panic!("expected {expected:?}, accepted transition to {phase:?}"),
        Err(err) => assert_eq!(*err, LifecycleError::Deadline(expected)),
    }
}
