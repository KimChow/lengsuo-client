//! Start-stage identity of a pending completion, used for deadlines and
//! for rejecting callbacks that belong to a different stage.

/// One step of the strict start ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Authorization of the run.
    Authorization,
    /// Package installation and verification.
    Install,
    /// Network isolation preparation.
    Network,
    /// Process spawn, awaiting the real identity.
    Spawn,
    /// Health probe of the started process.
    Probe,
    /// Stop accepted, awaiting teardown accounting.
    Teardown,
}

impl Stage {
    /// Ladder rank; strictly increasing along the start path.
    #[must_use]
    pub fn rank(self) -> u8 {
        self as u8
    }

    /// True for the five start stages that arm a deadline.
    #[must_use]
    pub fn is_start_stage(self) -> bool {
        self != Self::Teardown
    }
}
