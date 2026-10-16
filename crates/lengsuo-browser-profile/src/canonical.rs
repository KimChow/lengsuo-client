//! Deterministic canonical byte encoding and identity digest.
//!
//! The encoding is deliberately *not* JSON. Field order is fixed by
//! [`encode`] below (matching the declaration order of [`ProfileSpecV1`]),
//! integers are big-endian, strings are `u16` length-prefixed UTF-8, and the
//! slot map is written in `BTreeMap` (lexicographic) key order. Consequences:
//!
//! * two profiles that compare `Equal` produce identical bytes;
//! * serializing the same value repeatedly is stable (no hash-map ordering, no
//!   float formatting, no locale-dependent casing);
//! * adding a field to this writer is a schema-version change, not a silent one.
//!
//! Digest: `SHA-256(CANONICAL_DOMAIN || canonical_bytes)`. The digest includes
//! `environment_id` on purpose. Excluding it would make two environments with
//! otherwise identical fingerprint settings hash to the same value, which
//! invites accidental identity confusion (logs, caches and dedup keyed by
//! digest would silently merge distinct environments). Creating a second
//! environment identity is instead an explicit
//! [`clone_as_environment`](crate::ProfileSpecV1::clone_as_environment) call,
//! and the resulting profile necessarily has a different digest.

use sha2::{Digest, Sha256};

use crate::error::ProfileError;
use crate::spec::ProfileSpecV1;

/// Prefix mixed into the digest so a profile digest is not interchangeable with
/// the bare SHA-256 of some other byte string. Terminated by `0x00`.
pub const CANONICAL_DOMAIN: &[u8] = b"lengsuo-browser-profile/v1/identity\0";

/// Magic of the canonical byte encoding.
pub const CANONICAL_HEADER: &[u8] = b"LBPF1";

/// Length ceiling for a length-prefixed string in the canonical form (the
/// `u16` prefix must be able to hold it).
const MAX_CANONICAL_STR: usize = u16::MAX as usize;

/// Stable numeric codes for [`Platform`]. Never renumber: doing so changes every
/// digest.
fn platform_code(p: crate::spec::Platform) -> u8 {
    use crate::spec::Platform::*;
    match p {
        Windows => 0,
        Linux => 1,
        Macos => 2,
        Android => 3,
        Ios => 4,
    }
}

pub(crate) fn encode(spec: &ProfileSpecV1) -> Result<Vec<u8>, ProfileError> {
    let mut out: Vec<u8> = Vec::with_capacity(96);
    out.extend_from_slice(CANONICAL_HEADER);
    out.extend_from_slice(&spec.schema_version.to_be_bytes());
    out.extend_from_slice(&spec.noise_version.to_be_bytes());
    push_str(&mut out, &spec.environment_id)?;
    push_str(&mut out, &spec.pool_version)?;
    // Seed is written as its decoded bytes, so a differently-cased or padded
    // spelling could never encode to the same bytes as a valid one.
    out.extend_from_slice(&crate::validate::seed_bytes(&spec.noise_seed_hex)?);
    out.push(platform_code(spec.platform));
    // screen
    out.extend_from_slice(&spec.screen.width.to_be_bytes());
    out.extend_from_slice(&spec.screen.height.to_be_bytes());
    out.push(spec.screen.color_depth);
    out.extend_from_slice(&spec.screen.dpr_milli.to_be_bytes());
    // hardware
    out.extend_from_slice(&spec.hardware.cpu_cores.to_be_bytes());
    out.extend_from_slice(&spec.hardware.memory_mib.to_be_bytes());
    out.push(spec.hardware.max_touch_points);
    // locale
    push_str(&mut out, &spec.locale.language)?;
    push_str(&mut out, &spec.locale.timezone)?;
    // slots, in BTreeMap order
    let count = u16::try_from(spec.slots.len())
        .map_err(|_| ProfileError::Canonical("too many slot entries"))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (dimension, id) in &spec.slots {
        push_str(&mut out, dimension)?;
        out.extend_from_slice(&id.to_be_bytes());
    }
    Ok(out)
}

fn push_str(out: &mut Vec<u8>, value: &str) -> Result<(), ProfileError> {
    // Not a `str` from arbitrary bytes, so UTF-8 validity is guaranteed; only
    // the length prefix can be exceeded.
    let len = u16::try_from(value.len())
        .map_err(|_| ProfileError::Canonical("string exceeds canonical length prefix"))?;
    if value.len() > MAX_CANONICAL_STR {
        return Err(ProfileError::Canonical("string exceeds canonical length"));
    }
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

/// SHA-256 over `CANONICAL_DOMAIN || body`.
pub(crate) fn digest_of(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CANONICAL_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}
