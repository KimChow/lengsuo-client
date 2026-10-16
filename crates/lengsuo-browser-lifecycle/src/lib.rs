//! The pure lifecycle state transition core for one browser environment.
//!
//! # What this is
//!
//! A deterministic state machine: given a phase, an injected clock and a
//! callback, it decides the next phase and whether real resources are
//! unaccounted for. It is one [`Supervisor`] per environment.
//!
//! # What this is NOT
//!
//! It owns no Windows Job Object, no network stack, no process handle, no
//! lease and no authority. It never spawns or kills a process, and it never
//! claims that a kill or a teardown succeeded: any path that may leave
//! resources behind returns [`CleanupRequired`] so the external owner can do
//! the actual work and report [`Supervisor::cleanup_completed`].
//!
//! # Trusted internal boundary
//!
//! Clock values, completion callbacks, process identities and cleanup
//! acknowledgements arrive from the caller. The machine trusts them as the
//! observed truth of one environment because it has no way to verify them; it
//! only enforces that they are self-consistent (monotonic injected clocks,
//! matching run tokens, ordered stages, valid identity fields) and rejects
//! anything that is not. It is *not* an authentication boundary: an attacker who
//! can drive the machine can also lie about having killed a process. Platform
//! integration must therefore supply the real Windows objects and treat this
//! machine as the ordering/accounting authority only.
//!
//! ```text
//! Stopped -> Authorizing -> Installing -> PreparingNetwork
//!         -> StartingProcess -> Probing -> Running
//! Running -> Stopping -> Stopped
//! any pending/live phase -> Failed -> (cleanup_completed) -> Stopped
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod deadline;
mod error;
mod failure;
mod generation;
mod identity;
mod phase;
mod resource;
mod stage;
mod supervisor;

pub use deadline::ArmedDeadline;
pub use error::{DeadlineRejected, IdentityRejected, LifecycleError, Rejected};
pub use failure::Failure;
pub use generation::RunGeneration;
pub use identity::ProcessIdentity;
pub use phase::Phase;
pub use resource::{CleanupRequired, ResourceOwnership};
pub use stage::Stage;
pub use supervisor::{Supervisor, DEFAULT_CLEANUP_BUDGET_MS};
