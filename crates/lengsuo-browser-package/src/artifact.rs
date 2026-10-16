//! Streaming artifact verification: exact length and exact SHA-256, bounded
//! memory, no filesystem and no network.
//!
//! [`verify_reader`] is the whole module. It consumes a [`Read`] and a
//! validated [`KernelManifestV1`] and reports whether the bytes are exactly the
//! bytes the manifest describes.

use crate::error::VerifyError;

/// Size of the buffer used to hash the artifact, in bytes.
///
/// Verification never holds more than this much artifact data at once, so a
/// 16 GiB declared package costs the same memory as a 1 KiB one.
pub const MIN_ARTIFACT_BYTES: u64 = 1;

pub const READ_CHUNK_BYTES: usize = 8 * 1024;

/// What a successful verification proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Bytes consumed, equal to the manifest's `size_bytes`.
    pub bytes_read: u64,
    /// SHA-256 computed over those bytes, lowercase hex.
    pub sha256: String,
}

impl VerifyReport {
    /// Bytes consumed.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Computed digest, lowercase hex.
    ///
    /// Returned for logging and for cross-checking a second copy of a manifest.
    /// It is a digest, not a signature: logging it must never be described as
    /// proof of where the bytes came from.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Stream `reader` to completion against `manifest`'s `size_bytes` and
/// `sha256`.
///
/// The manifest is re-validated first, so a hand-built value cannot skip the
/// grammar checks and drive the hash loop with an absurd declared size.
///
/// Behaviour, all of it fail-closed:
/// * reads never exceed `READ_CHUNK_BYTES` buffered;
/// * stops at the first byte past the declared size, so a hostile server cannot
///   make the client stream an endless body;
/// * end-of-stream early is [`VerifyError::Truncated`], never a silent
///   "short file is probably fine";
/// * a genuine read failure is [`VerifyError::Io`] with the byte offset, kept
///   distinct from truncation so corruption and transport failure stay
///   distinguishable in logs;
/// * right length, wrong bytes is [`VerifyError::DigestMismatch`].
///
/// This proves integrity only. See the crate-level trust boundary.
pub fn verify_reader<R: std::io::Read>(
    manifest: &crate::KernelManifestV1,
    mut reader: R,
) -> Result<VerifyReport, VerifyError> {
    use sha2::{Digest, Sha256};
    manifest.validate()?;
    let mut buffer = [0u8; READ_CHUNK_BYTES];
    let mut read = 0u64;
    let mut hash = Sha256::new();
    loop {
        // At most one byte beyond the declaration is consumed.
        let capacity = (manifest.size_bytes - read + 1).min(READ_CHUNK_BYTES as u64) as usize;
        let n = match reader.read(&mut buffer[..capacity]) {
            Ok(n) => n,
            Err(source) => return Err(VerifyError::Io { read, source }),
        };
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > manifest.size_bytes {
            return Err(VerifyError::Oversize {
                expected: manifest.size_bytes,
                got: read,
            });
        }
        hash.update(&buffer[..n]);
    }
    if read != manifest.size_bytes {
        return Err(VerifyError::Truncated {
            expected: manifest.size_bytes,
            got: read,
        });
    }
    let sha256 = hex::encode(hash.finalize());
    if sha256 != manifest.sha256 {
        return Err(VerifyError::DigestMismatch {
            expected: manifest.sha256.clone(),
            actual: sha256,
        });
    }
    Ok(VerifyReport {
        bytes_read: read,
        sha256,
    })
}
