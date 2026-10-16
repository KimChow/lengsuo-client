//! Opaque run token issued by [`crate::Supervisor`].
//!
//! Every completion callback handed to the machine must carry the token of the
//! run it belongs to. Tokens for older or newer runs are rejected and never
//! mutate state. The counter is durable: it is seeded from stored generation and
//! is never reused across stop/restart, so a stale callback from a previous run
//! can never match a later one.

use crate::error::LifecycleError;

/// Generation counter for one accepted start of an environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunGeneration {
    value: u64,
}

impl RunGeneration {
    /// Reconstructs a token from a persisted counter.
    ///
    /// This is the trusted-internal boundary, not an authorization mechanism:
    /// a durable counter read back by the platform supervisor (and, in tests, a
    /// forged future token) is re-wrapped here. It only names a run; the
    /// machine still rejects anything that is not the run it has open.
    #[must_use]
    pub fn from_stored(value: u64) -> Self {
        Self { value }
    }

    /// Raw counter, for durable storage by the caller.
    #[must_use]
    pub fn value(self) -> u64 {
        self.value
    }

    /// `self + delta` using `checked_add`; `None` on overflow.
    #[must_use]
    pub fn checked_add(self, delta: u64) -> Option<Self> {
        self.value.checked_add(delta).map(Self::from_stored)
    }

    /// Counter plus one, or `None` on overflow.
    #[must_use]
    pub fn checked_next(self) -> Option<Self> {
        self.checked_add(1)
    }

    /// Expected token for the next accepted start of this supervisor.
    ///
    /// Fails with [`LifecycleError::GenerationExhausted`] at the counter limit
    /// rather than reusing a token.
    pub fn next_for(stored_generation: u64) -> Result<Self, LifecycleError> {
        Self::from_stored(stored_generation)
            .checked_next()
            .ok_or(LifecycleError::GenerationExhausted)
    }
}
