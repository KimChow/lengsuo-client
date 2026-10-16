//! Shared helpers for lifecycle tests.
//!
//! A [`Driver`] walks the machine with a strictly increasing injected clock so
//! ordering tests stay readable. Clock-hostile cases build a `Supervisor`
//! directly and pass explicit values.

#![allow(dead_code)]

use lengsuo_browser_lifecycle::{
    CleanupRequired, DeadlineRejected, IdentityRejected, LifecycleError, Phase, ProcessIdentity,
    Rejected, RunGeneration, Stage, Supervisor,
};

/// Milliseconds added to the injected clock after each accepted step.
pub const STEP: u64 = 100;
/// Deadline budget used by the happy-path helpers.
pub const BUDGET: u64 = 5_000;
/// Injected clock at driver construction.
pub const START_CLOCK: u64 = 1_000;

/// Wraps a raw counter as a run identifier.
pub fn wrap_counter(value: u64) -> RunGeneration {
    RunGeneration::from_stored(value)
}

/// The run identifier a supervisor seeded with `stored` must be handed next.
pub fn next_for_stored(stored: u64) -> RunGeneration {
    RunGeneration::next_for(stored).expect("generation counter not exhausted")
}

/// A valid process identity with a distinguishable nonce.
pub fn identity(pid: u32) -> ProcessIdentity {
    let mut nonce = [0u8; 16];
    nonce[0] = 0xA1;
    nonce[15] = pid as u8;
    ProcessIdentity::new(pid, nonce).expect("test identity is valid")
}

/// A nonce of all zeros, i.e. the PID-only adoption shape.
pub fn zero_nonce() -> [u8; 16] {
    [0u8; 16]
}

/// An all-zero nonce with one byte set, for equality assertions.
pub fn nonce_with_byte(byte: u8) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    nonce[7] = byte;
    nonce
}

/// An identity built from an explicit pair, for rejection-shape tests.
pub fn identity_of(pid: u32, nonce: [u8; 16]) -> Option<ProcessIdentity> {
    ProcessIdentity::new(pid, nonce)
}

/// Drives one supervisor with its own monotonically increasing clock.
pub struct Driver {
    sup: Supervisor,
    now: u64,
    next_pid: u32,
}

impl Driver {
    /// New stopped supervisor seeded with `stored`, clock at [`START_CLOCK`].
    pub fn new(stored: u64) -> Self {
        Self {
            sup: Supervisor::new(stored),
            now: START_CLOCK,
            next_pid: 4_000,
        }
    }

    /// Borrows the machine for assertions.
    pub fn sup(&self) -> &Supervisor {
        &self.sup
    }

    /// Borrows the machine mutably for direct calls.
    pub fn sup_mut(&mut self) -> &mut Supervisor {
        &mut self.sup
    }

    /// Current injected clock value.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Moves the injected clock forward.
    pub fn advance(&mut self, ms: u64) {
        self.now += ms;
    }

    /// Identifier the next accepted start must carry.
    pub fn seeded_next(&self) -> RunGeneration {
        next_for_stored(self.sup.stored_generation())
    }

    /// Identifier of the currently open run; panics when none is open.
    pub fn run(&self) -> RunGeneration {
        self.sup
            .current_run()
            .expect("a run must be open at this point in the test")
    }

    /// Opens a run at the current clock with [`BUDGET`].
    pub fn begin(&mut self) -> RunGeneration {
        let started = self
            .sup
            .begin_start(self.seeded_next(), self.now, BUDGET)
            .unwrap_or_else(|err| panic!("begin_start rejected: {}", err.code()));
        self.advance(STEP);
        started
    }

    /// Opens a run with an explicit first budget, reporting rejection.
    pub fn try_begin_with_budget(&mut self, budget: u64) -> Result<RunGeneration, LifecycleError> {
        let outcome = self.sup.begin_start(self.seeded_next(), self.now, budget);
        if outcome.is_ok() {
            self.advance(STEP);
        }
        outcome
    }

    /// Completes `stage` for `which` with an explicit next-stage budget.
    pub fn complete_using(
        &mut self,
        which: RunGeneration,
        stage: Stage,
        budget: u64,
    ) -> Result<Phase, LifecycleError> {
        let outcome = self.sup.complete(which, stage, self.now, budget);
        if outcome.is_ok() {
            self.advance(STEP);
        }
        outcome
    }

    /// Completes `stage` for `which` with [`BUDGET`].
    pub fn complete_with(
        &mut self,
        which: RunGeneration,
        stage: Stage,
    ) -> Result<Phase, LifecycleError> {
        self.complete_using(which, stage, BUDGET)
    }

    /// Completes `stage` for the open run, panicking on rejection.
    pub fn complete(&mut self, stage: Stage) -> Phase {
        let outcome = self.complete_with(self.run(), stage);
        outcome.unwrap_or_else(|err| panic!("complete({stage:?}) rejected: {}", err.code()))
    }

    /// Reports a spawn identity for `pid`, panicking on rejection.
    pub fn spawn(&mut self, pid: u32) -> Phase {
        let outcome = self
            .sup
            .report_identity(self.run(), identity(pid), self.now, BUDGET)
            .unwrap_or_else(|err| panic!("report_identity rejected: {}", err.code()));
        self.advance(STEP);
        outcome
    }

    /// Reports `made` as the spawn identity, returning the raw outcome.
    pub fn try_spawn(
        &mut self,
        which: RunGeneration,
        made: ProcessIdentity,
    ) -> Result<Phase, LifecycleError> {
        self.try_spawn_budget(which, made, BUDGET)
    }

    /// Reports `made` with an explicit probe budget.
    pub fn try_spawn_budget(
        &mut self,
        which: RunGeneration,
        made: ProcessIdentity,
        budget: u64,
    ) -> Result<Phase, LifecycleError> {
        let outcome = self.sup.report_identity(which, made, self.now, budget);
        if outcome.is_ok() {
            self.advance(STEP);
        }
        outcome
    }

    /// Walks the start ladder until `target` is reached.
    pub fn reach_phase(&mut self, target: Phase) {
        let mut guard = 0usize;
        while self.sup.phase() != target {
            guard += 1;
            assert!(guard < 32, "ladder walk failed to converge");
            match self.sup.phase() {
                Phase::Stopped => {
                    self.begin();
                }
                Phase::Authorizing => {
                    self.complete(Stage::Authorization);
                }
                Phase::Installing => {
                    self.complete(Stage::Install);
                }
                Phase::PreparingNetwork => {
                    self.complete(Stage::Network);
                }
                Phase::StartingProcess => {
                    let pid = self.next_pid;
                    self.next_pid += 1;
                    self.spawn(pid);
                }
                Phase::Probing => {
                    self.complete(Stage::Probe);
                }
                other => panic!("cannot reach {target:?} from {other:?}"),
            }
        }
    }

    /// Walks the whole start ladder and returns the open run identifier.
    pub fn reach_running(&mut self) -> RunGeneration {
        self.reach_phase(Phase::Running);
        self.run()
    }

    /// Stops the open run and returns its phase plus cleanup demand.
    pub fn stop(&mut self) -> (Phase, Option<CleanupRequired>) {
        let outcome = self.stop_using(self.run());
        outcome.unwrap_or_else(|err| panic!("stop rejected: {}", err.code()))
    }

    /// Stops the run identified by `which`, reporting rejection.
    pub fn stop_using(
        &mut self,
        which: RunGeneration,
    ) -> Result<(Phase, Option<CleanupRequired>), LifecycleError> {
        let outcome = self.sup.stop(which, self.now);
        if outcome.is_ok() {
            self.advance(STEP);
        }
        outcome
    }

    /// Confirms teardown for `which`.
    pub fn cleanup_using(&mut self, which: RunGeneration) -> Result<Phase, LifecycleError> {
        let outcome = self.sup.cleanup_completed(which, self.now);
        if outcome.is_ok() {
            self.advance(STEP);
        }
        outcome
    }

    /// Confirms teardown for the open run, panicking on rejection.
    pub fn cleanup(&mut self) -> Phase {
        let outcome = self.cleanup_using(self.run());
        outcome.unwrap_or_else(|err| panic!("cleanup_completed rejected: {}", err.code()))
    }

    /// Forces an explicit timeout at the current clock.
    pub fn timeout(&mut self) -> CleanupRequired {
        let outcome = self
            .sup
            .timeout(self.now)
            .unwrap_or_else(|err| panic!("timeout rejected: {}", err.code()));
        self.advance(STEP);
        outcome
    }

    /// Forces an explicit timeout at an arbitrary clock.
    pub fn timeout_at(&mut self, when: u64) -> Result<CleanupRequired, LifecycleError> {
        self.sup.timeout(when)
    }

    /// Observes the armed deadline at the current clock.
    pub fn deadline_check(&mut self) -> Option<CleanupRequired> {
        let outcome = self
            .sup
            .deadline_expired(self.now)
            .unwrap_or_else(|err| panic!("deadline_expired rejected: {}", err.code()));
        if outcome.is_some() {
            self.advance(STEP);
        }
        outcome
    }

    /// Observes the armed deadline at an arbitrary clock.
    pub fn deadline_check_at(
        &mut self,
        when: u64,
    ) -> Result<Option<CleanupRequired>, LifecycleError> {
        let outcome = self.sup.deadline_expired(when);
        if outcome.is_ok() {
            self.now = when;
        }
        outcome
    }

    /// Reports network loss for the open run.
    pub fn network_lost(&mut self) -> CleanupRequired {
        let outcome = self.try_network_lost(self.run());
        outcome.unwrap_or_else(|err| panic!("network_lost rejected: {}", err.code()))
    }

    /// Reports network loss for `which`.
    pub fn try_network_lost(
        &mut self,
        which: RunGeneration,
    ) -> Result<CleanupRequired, LifecycleError> {
        let outcome = self.sup.network_lost(which, self.now);
        if outcome.is_ok() {
            self.advance(STEP);
        }
        outcome
    }

    /// Reports revocation for the open run.
    pub fn revoked(&mut self) -> CleanupRequired {
        let outcome = self
            .sup
            .authorization_revoked(self.run(), self.now)
            .unwrap_or_else(|err| panic!("authorization_revoked rejected: {}", err.code()));
        self.advance(STEP);
        outcome
    }

    /// Reports an unexpected exit of `pid` for the open run.
    pub fn process_exited(&mut self, pid: u32) -> CleanupRequired {
        let outcome = self.try_process_exited(self.run(), identity(pid));
        outcome.unwrap_or_else(|err| panic!("process_exited rejected: {}", err.code()))
    }

    /// Reports an unexpected exit for `which`, carrying `made`.
    pub fn try_process_exited(
        &mut self,
        which: RunGeneration,
        made: ProcessIdentity,
    ) -> Result<CleanupRequired, LifecycleError> {
        let outcome = self.sup.process_exited(which, made, self.now);
        if outcome.is_ok() {
            self.advance(STEP);
        }
        outcome
    }
}

/// Asserts a call was rejected with exactly `want`.
#[track_caller]
pub fn expect_rejected<T: std::fmt::Debug>(
    outcome: &Result<T, LifecycleError>,
    want: LifecycleError,
) {
    match outcome {
        Ok(value) => panic!("expected {want:?}, got Ok({value:?})"),
        Err(error) => assert_eq!(*error, want, "wrong rejection"),
    }
}

/// Asserts a rejection carrying a specific run guard reason.
#[track_caller]
pub fn expect_run_rejected<T: std::fmt::Debug>(
    outcome: &Result<T, LifecycleError>,
    want: Rejected,
) {
    expect_rejected(outcome, LifecycleError::Run(want));
}

/// Asserts a rejection carrying a specific clock or budget reason.
#[track_caller]
pub fn expect_deadline_rejected<T: std::fmt::Debug>(
    outcome: &Result<T, LifecycleError>,
    want: DeadlineRejected,
) {
    expect_rejected(outcome, LifecycleError::Deadline(want));
}

/// Asserts a rejection carrying a specific identity reason.
#[track_caller]
pub fn expect_identity_rejected<T: std::fmt::Debug>(
    outcome: &Result<T, LifecycleError>,
    want: IdentityRejected,
) {
    expect_rejected(outcome, LifecycleError::Identity(want));
}

/// Redacted tag of a rejection, for log-safety checks.
#[track_caller]
pub fn code_of<T: std::fmt::Debug>(outcome: &Result<T, LifecycleError>) -> &'static str {
    match outcome {
        Ok(_) => panic!("expected a rejection"),
        Err(error) => error.code(),
    }
}
