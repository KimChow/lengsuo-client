//! Typed reason for a fail-closed entry into [`crate::Phase::Failed`].
//!
//! Rejections (stale token, wrong stage, bad clock) never reach this type: they
//! leave the machine untouched and are returned to the caller only. This record
//! describes an *accepted* transition that failed the run closed, so integration
//! knows why teardown is owed without any external diagnostic string reaching a
//! log.

use crate::error::IdentityRejected;

/// Why the open run failed closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// An armed start-stage deadline was reached.
    DeadlineExpired,
    /// Network isolation dropped while the run was live.
    NetworkLost,
    /// Authorization was revoked while the run was live.
    AuthorizationRevoked,
    /// The recorded process exited before being stopped.
    ProcessExited,
    /// A pending platform operation failed before completion.
    StageFailed(crate::Stage),
    /// The platform reported an identity that is not a usable real identity, so
    /// the run cannot be named and is abandoned fail-closed.
    Identity(IdentityRejected),
}

impl Failure {
    /// Short stable tag for redacted diagnostics.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::DeadlineExpired => "failure:timeout",
            Self::NetworkLost => "failure:network",
            Self::AuthorizationRevoked => "failure:revoked",
            Self::ProcessExited => "failure:process_exit",
            Self::StageFailed(_) => "failure:stage",
            Self::Identity(crate::IdentityRejected::ZeroPid) => "identity:pid",
            Self::Identity(crate::IdentityRejected::ZeroCreationNonce) => "identity:nonce",
        }
    }
}
