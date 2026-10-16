//! What the machine hands to the external owner when resources are unaccounted
//! for.
//!
//! The machine is a pure transition function. It cannot touch an OS process, a
//! network stack or a Job Object, so it never claims teardown happened. On any
//! path that leaves pending resources behind it returns this record instead, and
//! the caller is obliged to do the actual work and then report
//! `cleanup_completed(token)`.

use crate::generation::RunGeneration;
use crate::identity::ProcessIdentity;

/// Unaccounted resources left behind by a failed or stopped run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupRequired {
    run: RunGeneration,
    isolation_established: bool,
    identity: Option<ProcessIdentity>,
}

impl CleanupRequired {
    pub(crate) fn new(
        run: RunGeneration,
        isolation_established: bool,
        identity: Option<ProcessIdentity>,
    ) -> Self {
        Self {
            run,
            isolation_established,
            identity,
        }
    }

    /// Run whose resources are outstanding; pass it back to `cleanup_completed`.
    #[must_use]
    pub fn run(&self) -> RunGeneration {
        self.run
    }

    /// Whether network isolation had been established and must be torn down.
    #[must_use]
    pub fn isolation_established(&self) -> bool {
        self.isolation_established
    }

    /// Process identity to kill, if a real spawn was ever reported.
    #[must_use]
    pub fn identity(&self) -> Option<ProcessIdentity> {
        self.identity
    }
}

/// Resource accounting view for integration code.
///
/// Fields stay private; integration reads them through accessors so the machine
/// remains the only place that decides what "held" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceOwnership {
    install_held: bool,
    process_held: bool,
    isolation_held: bool,
    cleanup_outstanding: bool,
}

impl ResourceOwnership {
    /// Builds an accounting record. Crate-internal: only the supervisor decides
    /// what is held.
    pub(crate) fn new(
        install_held: bool,
        process_held: bool,
        isolation_held: bool,
        cleanup_outstanding: bool,
    ) -> Self {
        Self {
            install_held,
            process_held,
            isolation_held,
            cleanup_outstanding,
        }
    }

    /// A verified install artifact exists and is not yet accounted for.
    #[must_use]
    pub fn install_held(self) -> bool {
        self.install_held
    }

    /// A process identity is held and not yet cleaned up.
    #[must_use]
    pub fn process_held(self) -> bool {
        self.process_held
    }

    /// Network isolation is established and not yet cleaned up.
    #[must_use]
    pub fn isolation_held(self) -> bool {
        self.isolation_held
    }

    /// Cleanup completion is still owed before the run may return to stopped.
    #[must_use]
    pub fn cleanup_outstanding(self) -> bool {
        self.cleanup_outstanding
    }

    /// True when any real resource may still exist and cleanup is owed.
    #[must_use]
    pub fn any_held(self) -> bool {
        self.install_held || self.process_held || self.isolation_held || self.cleanup_outstanding
    }

    /// All-false record for a clean stopped run.
    pub(crate) const fn none() -> Self {
        Self {
            install_held: false,
            process_held: false,
            isolation_held: false,
            cleanup_outstanding: false,
        }
    }
}
