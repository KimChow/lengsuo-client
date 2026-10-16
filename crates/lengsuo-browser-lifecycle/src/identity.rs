//! Process identity supplied by the platform layer.
//!
//! The machine never invents or guesses an identity, and it cannot kill what it
//! has not been given. A PID alone is not an identity: a recycled PID adopted by
//! a later run is exactly the confusion this type exists to prevent, so a
//! creation nonce is mandatory and both fields must be non-trivial.

/// Actual OS process identity, as observed by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    pid: u32,
    creation_nonce: [u8; 16],
}

impl ProcessIdentity {
    /// Accepts only a nonzero PID with a nonzero creation nonce.
    ///
    /// Zero PID and all-zero nonce are rejected outright; there is no partial
    /// acceptance and no synthetic identity.
    #[must_use]
    pub fn new(pid: u32, creation_nonce: [u8; 16]) -> Option<Self> {
        if pid == 0 || creation_nonce == [0; 16] {
            None
        } else {
            Some(Self {
                pid,
                creation_nonce,
            })
        }
    }

    /// The reported PID. Guaranteed nonzero for any constructed value.
    #[must_use]
    pub fn pid(self) -> u32 {
        self.pid
    }

    /// The reported creation nonce. Guaranteed nonzero for any constructed value.
    #[must_use]
    pub fn creation_nonce(self) -> [u8; 16] {
        self.creation_nonce
    }
}
