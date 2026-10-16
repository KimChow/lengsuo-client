//! Phase model for one browser environment run.
//!
//! The variants are a strict start ladder: authorization, package install,
//! network isolation, process spawn, probe, then running. Teardown and failure
//! are separate states because neither may be elided.

/// Lifecycle phase of a single supervised environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Quiescent: no run open, no unaccounted resources.
    Stopped,
    /// Waiting for the authorization callback of the current run.
    Authorizing,
    /// Waiting for the package verification callback of the current run.
    Installing,
    /// Waiting for the network isolation callback of the current run.
    PreparingNetwork,
    /// Waiting for the actual process identity of the current run.
    StartingProcess,
    /// Waiting for the health probe of the current run.
    Probing,
    /// Fully started; only failure or stop moves out of this phase.
    Running,
    /// Stop accepted; teardown acknowledgement still outstanding.
    Stopping,
    /// Fail-closed; teardown acknowledgement outstanding or being supplied.
    Failed,
}

impl Phase {
    /// Fixed ladder rank used for ordering documentation and tests.
    #[must_use]
    pub fn rank(self) -> u8 {
        self as u8
    }

    /// True while a start-stage deadline is armed for this phase.
    #[must_use]
    pub fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Authorizing
                | Self::Installing
                | Self::PreparingNetwork
                | Self::StartingProcess
                | Self::Probing
        )
    }

    /// True for phases where a run is open and may be stopped or failed.
    #[must_use]
    pub fn is_live(self) -> bool {
        self.is_pending() || self == Self::Running
    }
}
