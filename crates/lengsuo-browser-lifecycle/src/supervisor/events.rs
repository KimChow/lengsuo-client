//! Failure, expiry and acknowledged teardown transitions.
use super::*;

impl Supervisor {
    /// Check a per-run deadline callback, rejecting stale generations first.
    pub fn deadline_expired_for(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
    ) -> Result<Option<CleanupRequired>, LifecycleError> {
        self.check_token(token)?;
        self.deadline_expired(now_ms)
    }

    /// A per-run watchdog failure that cannot abort a later generation.
    pub fn timeout_for(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
    ) -> Result<CleanupRequired, LifecycleError> {
        self.check_token(token)?;
        self.timeout(now_ms)
    }

    /// Observe the central clock, not an old run's untagged timer callback.
    /// Expiry is inclusive; the resource owner still performs actual teardown.
    pub fn deadline_expired(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<CleanupRequired>, LifecycleError> {
        self.check_clock(now_ms)?;
        if self.deadline.is_some_and(|d| d.is_expired_at(now_ms)) {
            return Ok(Some(self.fail(Failure::DeadlineExpired, now_ms)));
        }
        self.last_clock_ms = now_ms;
        Ok(None)
    }

    /// Force failure of the currently live run, for an external watchdog.
    /// The owner must not route an older run's timer through this operation.
    pub fn timeout(&mut self, now_ms: u64) -> Result<CleanupRequired, LifecycleError> {
        if self.phase != Phase::Stopping {
            self.check_live()?;
        }
        self.check_clock(now_ms)?;
        Ok(self.fail(Failure::DeadlineExpired, now_ms))
    }

    /// Fail a named pending operation, including package verification failure.
    pub fn stage_failed(
        &mut self,
        token: RunGeneration,
        stage: Stage,
        now_ms: u64,
    ) -> Result<CleanupRequired, LifecycleError> {
        self.check_token(token)?;
        if !self.phase.is_pending() {
            return Err(Rejected::IllegalForPhase.into());
        }
        self.check_stage(stage)?;
        self.check_clock(now_ms)?;
        Ok(self.fail(Failure::StageFailed(stage), now_ms))
    }

    /// Isolation loss never permits an unprotected fallback network path.
    pub fn network_lost(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
    ) -> Result<CleanupRequired, LifecycleError> {
        self.check_token(token)?;
        self.check_live()?;
        if !self.isolation_held {
            return Err(Rejected::IllegalForPhase.into());
        }
        self.check_clock(now_ms)?;
        Ok(self.fail(Failure::NetworkLost, now_ms))
    }

    /// Revocation aborts every live phase, including preparation before spawn.
    pub fn authorization_revoked(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
    ) -> Result<CleanupRequired, LifecycleError> {
        self.check_token(token)?;
        self.check_live()?;
        self.check_clock(now_ms)?;
        Ok(self.fail(Failure::AuthorizationRevoked, now_ms))
    }

    /// Reject foreign identities/PID reuse; account for the recorded process exit.
    pub fn process_exited(
        &mut self,
        token: RunGeneration,
        identity: ProcessIdentity,
        now_ms: u64,
    ) -> Result<CleanupRequired, LifecycleError> {
        self.check_token(token)?;
        self.check_live()?;
        if self.identity != Some(identity) {
            return Err(Rejected::NotTheRecordedProcess.into());
        }
        self.check_clock(now_ms)?;
        Ok(self.fail(Failure::ProcessExited, now_ms))
    }

    /// Cancel a live run. Pre-spawn operations must also drain before restart.
    pub fn stop(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
    ) -> Result<(Phase, Option<CleanupRequired>), LifecycleError> {
        self.stop_with_budget(token, now_ms, DEFAULT_CLEANUP_BUDGET_MS)
    }

    /// Cancel a live run and arm an explicit positive teardown deadline.
    /// Expiry retains the cleanup demand; it never certifies resources released.
    pub fn stop_with_budget(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
        cleanup_budget_ms: u64,
    ) -> Result<(Phase, Option<CleanupRequired>), LifecycleError> {
        self.check_token(token)?;
        self.check_live()?;
        self.check_clock(now_ms)?;
        let deadline = ArmedDeadline::arm(Stage::Teardown, now_ms, cleanup_budget_ms)?;
        let cleanup = self.cleanup_record();
        self.phase = Phase::Stopping;
        self.deadline = Some(deadline);
        self.cleanup_outstanding = true;
        self.last_cleanup = Some(cleanup);
        self.last_clock_ms = now_ms;
        Ok((self.phase, Some(cleanup)))
    }

    /// Acknowledge real teardown by the trusted owner, then permit restart.
    /// This call itself cannot prove a process died or a lease was released.
    pub fn cleanup_completed(
        &mut self,
        token: RunGeneration,
        now_ms: u64,
    ) -> Result<Phase, LifecycleError> {
        self.check_token(token)?;
        if !matches!(self.phase, Phase::Stopping | Phase::Failed) || !self.cleanup_outstanding {
            return Err(Rejected::IllegalForPhase.into());
        }
        self.check_clock(now_ms)?;
        self.phase = Phase::Stopped;
        self.current = None;
        self.identity = None;
        self.install_held = false;
        self.isolation_held = false;
        self.cleanup_outstanding = false;
        self.deadline = None;
        self.last_cleanup = None;
        self.last_clock_ms = now_ms;
        Ok(self.phase)
    }

    fn check_live(&self) -> Result<(), LifecycleError> {
        if !self.phase.is_live() {
            return Err(Rejected::IllegalForPhase.into());
        }
        Ok(())
    }

    fn cleanup_record(&self) -> CleanupRequired {
        CleanupRequired::new(
            self.current.expect("live phase has a run"),
            self.isolation_held,
            self.identity,
        )
    }

    pub(super) fn fail(&mut self, reason: Failure, now_ms: u64) -> CleanupRequired {
        let cleanup = self.cleanup_record();
        self.phase = Phase::Failed;
        self.deadline = None;
        self.cleanup_outstanding = true;
        self.last_cleanup = Some(cleanup);
        self.last_error = Some(LifecycleError::Failure(reason));
        self.last_clock_ms = now_ms;
        cleanup
    }
}
