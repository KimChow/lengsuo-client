//! Authenticated release payloads, separate from Windows executable signing.
//!
//! Trust roots must come from application-controlled configuration, never the
//! downloaded envelope. The caller supplies a trusted time and persists the
//! release floor. Authentication does not validate kernel manifest semantics,
//! package bytes, operating-system compatibility, or authorize installation.
#![forbid(unsafe_code)]

use ring::signature;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SIGNING_DOMAIN: &[u8] = b"Lengsuo/KernelManifestEnvelope/v1\0";
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;
pub const MAX_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_MANIFEST_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    key_id: String,
    payload: String,
    signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    schema_version: u32,
    sequence: u64,
    issued_at_unix: u64,
    expires_at_unix: u64,
    manifest_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFloor {
    pub sequence: u64,
    pub envelope_digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Must be anchored to trusted time by the caller, not an untrusted clock.
    pub now_unix: u64,
    pub maximum_validity_seconds: u64,
    /// Previously installed release. Equal sequences require identical bytes.
    pub floor: Option<ReleaseFloor>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("release metadata exceeds a size limit")]
    TooLarge,
    #[error("malformed release envelope")]
    Envelope,
    #[error("unsupported release schema")]
    Schema,
    #[error("invalid signing key identifier")]
    KeyId,
    #[error("no trusted release keys configured")]
    EmptyRoots,
    #[error("duplicate release key identifier")]
    DuplicateRoot,
    #[error("release signing key is not trusted")]
    UnknownKey,
    #[error("invalid signature encoding")]
    SignatureEncoding,
    #[error("release signature rejected")]
    InvalidSignature,
    #[error("malformed authenticated release claims")]
    Claims,
    #[error("invalid verification policy")]
    Policy,
    #[error("invalid release validity window")]
    Window,
    #[error("release is not yet valid")]
    Future,
    #[error("release has expired")]
    Expired,
    #[error("release validity exceeds policy")]
    Validity,
    #[error("release rollback rejected")]
    Rollback,
    #[error("conflicting content for an installed release sequence")]
    Conflict,
}

#[derive(Debug)]
pub struct TrustStore {
    roots: BTreeMap<String, [u8; 32]>,
}

pub struct VerifiedPayload {
    manifest_json: String,
    sequence: u64,
    key_id: String,
    expires_at_unix: u64,
    verified_at_unix: u64,
    envelope_digest: [u8; 32],
}

impl std::fmt::Debug for VerifiedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedPayload")
            .field("sequence", &self.sequence)
            .field("manifest_json", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl VerifiedPayload {
    /// Recheck against trusted time immediately before an installation commit.
    /// The caller still owns authorization, key revocation and floor persistence.
    pub fn assert_current(&self, trusted_now_unix: u64) -> Result<(), Error> {
        if trusted_now_unix < self.verified_at_unix {
            return Err(Error::Policy);
        }
        if trusted_now_unix >= self.expires_at_unix {
            return Err(Error::Expired);
        }
        Ok(())
    }

    pub fn manifest_json(&self) -> &str {
        &self.manifest_json
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
    pub fn release_floor(&self) -> ReleaseFloor {
        ReleaseFloor {
            sequence: self.sequence,
            envelope_digest: self.envelope_digest,
        }
    }
}

impl TrustStore {
    pub fn new(roots: impl IntoIterator<Item = (String, [u8; 32])>) -> Result<Self, Error> {
        let mut accepted = BTreeMap::new();
        for (key_id, public_key) in roots {
            check_key_id(&key_id)?;
            if accepted.contains_key(&key_id) {
                return Err(Error::DuplicateRoot);
            }
            if accepted.len() >= 64 {
                return Err(Error::TooLarge);
            }
            accepted.insert(key_id, public_key);
        }
        if accepted.is_empty() {
            return Err(Error::EmptyRoots);
        }
        Ok(Self { roots: accepted })
    }

    pub fn verify_json(
        &self,
        envelope: &str,
        policy: &VerificationPolicy,
    ) -> Result<VerifiedPayload, Error> {
        if policy.maximum_validity_seconds == 0
            || policy
                .floor
                .as_ref()
                .is_some_and(|floor| floor.sequence == 0)
        {
            return Err(Error::Policy);
        }
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        let envelope: Envelope = serde_json::from_str(envelope).map_err(|_| Error::Envelope)?;
        if envelope.schema_version != 1 {
            return Err(Error::Schema);
        }
        check_key_id(&envelope.key_id)?;
        let public_key = self.roots.get(&envelope.key_id).ok_or(Error::UnknownKey)?;
        if envelope.signature_hex.len() != 128
            || !envelope
                .signature_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::SignatureEncoding);
        }
        let mut signature_bytes = [0; 64];
        hex::decode_to_slice(&envelope.signature_hex, &mut signature_bytes)
            .map_err(|_| Error::SignatureEncoding)?;
        let signed_bytes = signing_bytes(&envelope.key_id, &envelope.payload)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&signed_bytes, &signature_bytes)
            .map_err(|_| Error::InvalidSignature)?;
        // Parse policy-bearing claims only after authenticating their exact bytes.
        let claims: Claims = serde_json::from_str(&envelope.payload).map_err(|_| Error::Claims)?;
        if claims.schema_version != 1 {
            return Err(Error::Schema);
        }
        if claims.manifest_json.len() > MAX_MANIFEST_BYTES {
            return Err(Error::TooLarge);
        }
        if claims.sequence == 0 || claims.manifest_json.trim().is_empty() {
            return Err(Error::Claims);
        }
        let manifest: serde_json::Value =
            serde_json::from_str(&claims.manifest_json).map_err(|_| Error::Claims)?;
        if !manifest.is_object() {
            return Err(Error::Claims);
        }
        let validity = claims
            .expires_at_unix
            .checked_sub(claims.issued_at_unix)
            .filter(|seconds| *seconds > 0)
            .ok_or(Error::Window)?;
        if validity > policy.maximum_validity_seconds {
            return Err(Error::Validity);
        }
        if claims.issued_at_unix > policy.now_unix {
            return Err(Error::Future);
        }
        if claims.expires_at_unix <= policy.now_unix {
            return Err(Error::Expired);
        }
        let envelope_digest: [u8; 32] = Sha256::digest(&signed_bytes).into();
        if let Some(floor) = &policy.floor {
            if claims.sequence < floor.sequence {
                return Err(Error::Rollback);
            }
            if claims.sequence == floor.sequence && envelope_digest != floor.envelope_digest {
                return Err(Error::Conflict);
            }
        }
        Ok(VerifiedPayload {
            manifest_json: claims.manifest_json,
            sequence: claims.sequence,
            key_id: envelope.key_id,
            expires_at_unix: claims.expires_at_unix,
            verified_at_unix: policy.now_unix,
            envelope_digest,
        })
    }
}

fn check_key_id(key_id: &str) -> Result<(), Error> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id.as_bytes()[0].is_ascii_alphanumeric()
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::KeyId);
    }
    Ok(())
}

/// Exact signing wire format: domain || u16be(key bytes) || key ||
/// u32be(payload bytes) || raw UTF-8 payload. No JSON canonicalization.
pub fn signing_bytes(key_id: &str, payload: &str) -> Result<Vec<u8>, Error> {
    check_key_id(key_id)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::TooLarge);
    }
    let key_len = u16::try_from(key_id.len()).map_err(|_| Error::TooLarge)?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| Error::TooLarge)?;
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + 2 + key_id.len() + 4 + payload.len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.extend_from_slice(&key_len.to_be_bytes());
    bytes.extend_from_slice(key_id.as_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(payload.as_bytes());
    Ok(bytes)
}
