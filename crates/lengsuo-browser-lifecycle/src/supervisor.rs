//! Ordered startup and accounting; the caller owns real resources.
use crate::{
    ArmedDeadline, CleanupRequired, DeadlineRejected, Failure, LifecycleError, Phase,
    ProcessIdentity, Rejected, ResourceOwnership, RunGeneration, Stage,
};

mod events;

/// Default teardown budget; integrations may select an explicit positive budget.
pub const DEFAULT_CLEANUP_BUDGET_MS: u64 = 30_000;

/// One environment's lifecycle. Completion callbacks are trusted observations.
#[derive(Debug, Clone)]
pub struct Supervisor {
    phase: Phase,
    stored_generation: u64,
    current: Option<RunGeneration>,
    identity: Option<ProcessIdentity>,
    install_held: bool,
    isolation_held: bool,
    cleanup_outstanding: bool,
    deadline: Option<ArmedDeadline>,
    last_clock_ms: u64,
    last_cleanup: Option<CleanupRequired>,
    last_error: Option<LifecycleError>,
}

impl Supervisor {
    /// Restore the durable generation counter in a clean stopped state.
    pub fn new(stored_generation: u64) -> Self {
        Self {
            phase: Phase::Stopped,
            stored_generation,
            current: None,
            identity: None,
            install_held: false,
            isolation_held: false,
            cleanup_outstanding: false,
            deadline: None,
            last_clock_ms: 0,
            last_cleanup: None,
            last_error: None,
        }
    }

    /// Current lifecycle phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Counter the owner persists before permitting an external start.
    pub fn stored_generation(&self) -> u64 {
        self.stored_generation
    }
    /// Token retained until cleanup has been acknowledged.
    pub fn current_run(&self) -> Option<RunGeneration> {
        self.current
    }
    /// Exact process identity reported by the platform.
    pub fn process(&self) -> Option<ProcessIdentity> {
        self.identity
    }
    /// Resource accounting; this is not proof of OS ownership.
    pub fn resources(&self) -> ResourceOwnership {
        if self.phase == Phase::Stopped {
            ResourceOwnership::none()
        } else {
            ResourceOwnership::new(
                self.install_held,
                self.identity.is_some(),
                self.isolation_held,
                self.cleanup_outstanding,
            )
        }
    }
    /// Deadline of the currently pending start stage.
    pub fn deadline(&self) -> Option<ArmedDeadline> {
        self.deadline
    }
    /// Cleanup required after a stop or accepted failure.
    pub fn pending_cleanup(&self) -> Option<CleanupRequired> {
        self.last_cleanup
    }
    /// Last accepted failure; rejected callbacks do not change this field.
    pub fn last_error(&self) -> Option<LifecycleError> {
        self.last_error
    }

    /// Begin a new generation after all previous cleanup has completed.
    /// Rejected clocks, budgets and tokens consume no generation.
    pub fn begin_start(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
        authorization_budget_ms: u64,
    ) -> Result<RunGeneration, LifecycleError> {
        if self.phase != Phase::Stopped {
            return Err(Rejected::IllegalForPhase.into());
        }
        let next = RunGeneration::next_for(self.stored_generation)?;
        if token != next {
            return Err(Rejected::UnknownRun.into());
        }
        self.check_clock(now_ms)?;
        let deadline = ArmedDeadline::arm(Stage::Authorization, now_ms, authorization_budget_ms)?;
        self.stored_generation = next.value();
        self.current = Some(next);
        self.phase = Phase::Authorizing;
        self.deadline = Some(deadline);
        self.last_clock_ms = now_ms;
        self.last_error = None;
        Ok(next)
    }

    /// Complete one pending stage. Spawn requires `report_identity` instead.
    /// A late callback fails closed; next-stage budget errors change no state.
    pub fn complete(
        &mut self,
        token: RunGeneration,
        stage: Stage,
        now_ms: u64,
        budget_ms: u64,
    ) -> Result<Phase, LifecycleError> {
        self.check_token(token)?;
        if !self.phase.is_pending() || stage == Stage::Spawn || stage == Stage::Teardown {
            return Err(Rejected::IllegalForPhase.into());
        }
        self.check_stage(stage)?;
        self.check_clock(now_ms)?;
        let (phase, next_stage) = match stage {
            Stage::Authorization => (Phase::Installing, Some(Stage::Install)),
            Stage::Install => (Phase::PreparingNetwork, Some(Stage::Network)),
            Stage::Network => (Phase::StartingProcess, Some(Stage::Spawn)),
            Stage::Probe => (Phase::Running, None),
            _ => return Err(Rejected::IllegalForPhase.into()),
        };
        let deadline = next_stage
            .map(|next| ArmedDeadline::arm(next, now_ms, budget_ms))
            .transpose()?;
        // Readiness reports a real resource, even when the callback is late.
        if stage == Stage::Network {
            self.isolation_held = true;
        }
        if self.deadline.is_some_and(|d| d.is_expired_at(now_ms)) {
            self.fail(Failure::DeadlineExpired, now_ms);
            return Err(LifecycleError::Failure(Failure::DeadlineExpired));
        }
        if stage == Stage::Authorization {
            self.install_held = true;
        }
        self.phase = phase;
        self.deadline = deadline;
        self.last_clock_ms = now_ms;
        Ok(phase)
    }

    /// Adopt the OS identity only after isolation is ready, then arm probing.
    /// A late report retains the identity for cleanup. On a rejected token,
    /// clock or budget, the caller remains responsible for its process handle.
    pub fn report_identity(
        &mut self,
        token: RunGeneration,
        identity: ProcessIdentity,
        now_ms: u64,
        probe_budget_ms: u64,
    ) -> Result<Phase, LifecycleError> {
        self.check_token(token)?;
        if !self.phase.is_pending() {
            return Err(Rejected::IllegalForPhase.into());
        }
        self.check_stage(Stage::Spawn)?;
        self.check_clock(now_ms)?;
        let deadline = ArmedDeadline::arm(Stage::Probe, now_ms, probe_budget_ms)?;
        self.identity = Some(identity);
        if self.deadline.is_some_and(|d| d.is_expired_at(now_ms)) {
            self.fail(Failure::DeadlineExpired, now_ms);
            return Err(LifecycleError::Failure(Failure::DeadlineExpired));
        }
        self.phase = Phase::Probing;
        self.deadline = Some(deadline);
        self.last_clock_ms = now_ms;
        Ok(self.phase)
    }

    fn check_token(&self, token: RunGeneration) -> Result<(), LifecycleError> {
        if self.current != Some(token) {
            return Err(Rejected::UnknownRun.into());
        }
        Ok(())
    }

    fn check_clock(&self, now_ms: u64) -> Result<(), LifecycleError> {
        if now_ms < self.last_clock_ms {
            return Err(DeadlineRejected::Backwards.into());
        }
        Ok(())
    }

    fn check_stage(&self, stage: Stage) -> Result<(), LifecycleError> {
        let pending = self.deadline.ok_or(Rejected::IllegalForPhase)?.stage();
        if pending != stage {
            return Err(if stage.rank() < pending.rank() {
                Rejected::Duplicate
            } else {
                Rejected::StageMismatch
            }
            .into());
        }
        Ok(())
    }
}
