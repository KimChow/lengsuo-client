//! Injected-clock deadline bookkeeping for one pending stage.
//!
//! There are no wall-clock calls anywhere in this crate. Every observation of
//! time arrives as `now_ms` from the caller, which also supplies a positive
//! budget. Deadlines are computed with `checked_add` only, so a bogus budget
//! cannot silently wrap into a deadline in the past.

use crate::stage::Stage;

/// A deadline armed for one pending stage of the current run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmedDeadline {
    stage: Stage,
    armed_at_ms: u64,
    deadline_ms: u64,
}

impl ArmedDeadline {
    /// Arms `now_ms + budget_ms`, failing closed on zero budget or overflow.
    pub fn arm(
        stage: Stage,
        now_ms: u64,
        budget_ms: u64,
    ) -> Result<Self, crate::error::DeadlineRejected> {
        if budget_ms == 0 {
            return Err(crate::DeadlineRejected::ZeroBudget);
        }
        let deadline_ms = now_ms
            .checked_add(budget_ms)
            .ok_or(crate::DeadlineRejected::Overflow)?;
        Ok(Self {
            stage,
            armed_at_ms: now_ms,
            deadline_ms,
        })
    }

    /// The stage this deadline belongs to.
    #[must_use]
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Absolute expiry, inclusive: `now_ms >= deadline_ms` is an expiry.
    #[must_use]
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// Inclusive expiry test against an injected observation.
    #[must_use]
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.armed_at_ms && now_ms >= self.deadline_ms
    }

    /// True when `now_ms` moves backwards relative to `seen_at_ms`.
    #[must_use]
    pub fn goes_backwards(now_ms: u64, seen_at_ms: u64) -> bool {
        now_ms < seen_at_ms
    }
}
