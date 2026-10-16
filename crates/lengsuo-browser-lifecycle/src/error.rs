//! Typed guard failures.
//!
//! Rejections are coded reasons, never free text: there is no path by which an
//! external diagnostic (message, OS error string, command line, credential) can
//! be attached to an error and later reach a log. Every error in this crate is a
//! small `Copy` enum. Callers who want detail must redact it at their own layer.
//!
//! Guard rejections leave state unchanged. Accepted failures retain a cleanup
//! demand and return a typed failure; callers still own the actual resources.

use thiserror::Error;

/// A completion callback that does not match the open run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Rejected {
    /// The token names no current run: stale, or forged from the future.
    #[error("run token does not match the current run")]
    UnknownRun,
    /// The token is current but the operation does not belong to this phase.
    #[error("operation illegal in the current phase")]
    IllegalForPhase,
    /// The token is current but that stage is not the one being awaited.
    #[error("callback stage does not match the pending stage")]
    StageMismatch,
    /// The requested generation was not the next one; no skipping or reuse.
    #[error("requested generation is not the next generation")]
    GenerationMismatch,
    /// The reported process identity is not the one recorded for this run.
    #[error("process identity is not the one recorded for this run")]
    NotTheRecordedProcess,
    /// A start stage has already completed during this run.
    #[error("callback stage was already completed")]
    Duplicate,
}

/// The supplied process identity was not a real, usable identity.
///
/// Reporting one fails the run closed (a bogus identity means the platform
/// could not tell us what it started, and an unkillable process may exist), so
/// this is a transition, not a no-op rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IdentityRejected {
    /// PID was zero.
    #[error("identity rejected: pid must be nonzero")]
    ZeroPid,
    /// Creation nonce was all zeros, i.e. PID-only adoption.
    #[error("identity rejected: creation nonce must be nonzero")]
    ZeroCreationNonce,
}

/// The injected clock or deadline budget was unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeadlineRejected {
    /// Budget was zero; a zero-length window cannot be armed.
    #[error("deadline rejected: budget must be positive")]
    ZeroBudget,
    /// `now_ms + budget_ms` overflowed.
    #[error("deadline rejected: deadline calculation overflowed")]
    Overflow,
    /// Observation went backwards relative to the last accepted clock.
    #[error("deadline rejected: clock moved backwards")]
    Backwards,
}

/// Any guard failure produced by the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LifecycleError {
    /// An accepted fail-closed transition; cleanup is still owed.
    #[error("run failed: {0:?}")]
    Failure(crate::Failure),
    /// Stale/future token, wrong stage, illegal phase or bad generation.
    #[error(transparent)]
    Run(#[from] Rejected),
    /// Bad process identity; the run failed closed into Failed.
    #[error(transparent)]
    Identity(#[from] IdentityRejected),
    /// Bad clock or budget; state was not touched.
    #[error(transparent)]
    Deadline(#[from] DeadlineRejected),
    /// The generation counter is exhausted. A new run would reuse a token that
    /// stale callbacks could match, so starting is refused.
    #[error("generation counter exhausted; refusing to reuse a run token")]
    GenerationExhausted,
}

impl LifecycleError {
    /// Short stable tag suitable for a redacted log field.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Failure(reason) => reason.code(),
            Self::Run(Rejected::UnknownRun) => "run:unknown",
            Self::Run(Rejected::IllegalForPhase) => "run:phase",
            Self::Run(Rejected::StageMismatch) => "run:stage",
            Self::Run(Rejected::GenerationMismatch) => "run:generation",
            Self::Run(Rejected::NotTheRecordedProcess) => "run:foreign_process",
            Self::Run(Rejected::Duplicate) => "run:duplicate",
            Self::Identity(IdentityRejected::ZeroPid) => "identity:pid",
            Self::Identity(IdentityRejected::ZeroCreationNonce) => "identity:nonce",
            Self::Deadline(DeadlineRejected::ZeroBudget) => "deadline:budget",
            Self::Deadline(DeadlineRejected::Overflow) => "deadline:overflow",
            Self::Deadline(DeadlineRejected::Backwards) => "deadline:backwards",
            Self::GenerationExhausted => "generation:exhausted",
        }
    }
}
