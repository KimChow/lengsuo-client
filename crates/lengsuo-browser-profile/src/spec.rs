//! Frozen profile types for schema version 1.
//!
//! These structs are the contract only: nothing here starts a browser, injects
//! a fingerprint, generates noise from the seed, or talks to a pool service.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ProfileError;
use crate::validate;

/// The only schema version this contract accepts.
pub const SCHEMA_VERSION: u32 = 1;

/// Maximum accepted length (in ASCII characters) for identifier-like fields.
pub const MAX_IDENTIFIER_LEN: usize = 64;

/// `noise_seed_hex` must be exactly this many lowercase hex characters, i.e. 8
/// seed bytes, so peer encodings exchange it losslessly.
pub const NOISE_SEED_HEX_LEN: usize = 16;

/// Operating-system family the profile claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
    Android,
    Ios,
}

impl Platform {
    /// Android and iOS: touch is mandatory and `max_touch_points` must be >= 1.
    pub fn is_mobile(self) -> bool {
        matches!(self, Platform::Android | Platform::Ios)
    }

    /// Stable lowercase label (used in diagnostics; the canonical encoding
    /// uses fixed numeric codes so labels can never drift a digest).
    pub fn canonical_label(self) -> &'static str {
        match self {
            Platform::Windows => "windows",
            Platform::Linux => "linux",
            Platform::Macos => "macos",
            Platform::Android => "android",
            Platform::Ios => "ios",
        }
    }
}

/// Viewport / display surface claims.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenSpec {
    pub width: u32,
    pub height: u32,
    pub color_depth: u8,
    /// Device pixel ratio times 1000, so DPR `2.0` is `2000`.
    pub dpr_milli: u32,
}

impl Default for ScreenSpec {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            color_depth: 24,
            dpr_milli: 1000,
        }
    }
}

/// Hardware concurrency / memory / touch claims.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareSpec {
    pub cpu_cores: u16,
    pub memory_mib: u32,
    pub max_touch_points: u8,
}

impl Default for HardwareSpec {
    fn default() -> Self {
        Self {
            cpu_cores: 8,
            memory_mib: 8192,
            max_touch_points: 0,
        }
    }
}

/// Language and timezone claims.
///
/// Only *syntax* is checked (shape of a BCP47-style tag, shape of an
/// IANA-style zone name). This crate embeds no IANA database, so a
/// syntactically valid but unregistered zone or subtag is not detected here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocaleSpec {
    pub language: String,
    pub timezone: String,
}

impl Default for LocaleSpec {
    fn default() -> Self {
        Self {
            language: "en-US".to_string(),
            timezone: "UTC".to_string(),
        }
    }
}

/// A complete environment profile, schema version 1.
///
/// Unknown JSON fields are rejected rather than ignored, so a profile written
/// against a newer schema cannot be silently accepted by this version.
///
/// Identity: [`identity_digest`](Self::identity_digest) covers **every** field
/// including `environment_id`. Two environments that should differ in identity
/// must not collide in digest. Duplicating an environment into a new identity is
/// an explicit call to [`clone_as_environment`](Self::clone_as_environment); the
/// contract never rewrites an `environment_id` behind a caller's back.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpecV1 {
    pub schema_version: u32,
    pub environment_id: String,
    pub pool_version: String,
    pub noise_version: u32,
    pub noise_seed_hex: String,
    pub platform: Platform,
    pub screen: ScreenSpec,
    pub hardware: HardwareSpec,
    pub locale: LocaleSpec,
    /// Dimension name -> tier (slot) id. The key set must be exactly
    /// [`DIMENSIONS`](crate::DIMENSIONS): no missing entry, no extra entry.
    #[serde(deserialize_with = "crate::json::unique_map")]
    pub slots: BTreeMap<String, u32>,
}

impl ProfileSpecV1 {
    /// Whether `dimension` is one of the supported slot dimensions.
    pub fn is_supported_dimension(dimension: &str) -> bool {
        crate::DIMENSIONS.contains(&dimension)
    }

    /// Full self-consistency check: schema and noise versions, safe
    /// identifiers, seed shape, screen and hardware bounds (including u64
    /// pixel-area overflow), locale syntax, exact slot dimensions, and
    /// platform / touch-point consistency.
    pub fn validate(&self) -> Result<(), ProfileError> {
        validate::validate_spec(self)
    }

    /// Parse profile JSON, then [`validate`](Self::validate).
    pub fn from_json_str(text: &str) -> Result<Self, ProfileError> {
        crate::json::check_size(text, crate::MAX_PROFILE_JSON_BYTES)?;
        let spec: Self = serde_json::from_str(text).map_err(deser_error)?;
        spec.validate()?;
        Ok(spec)
    }

    /// Serialize to JSON (field order follows this struct declaration).
    pub fn to_json_string(&self) -> Result<String, ProfileError> {
        serde_json::to_string(self).map_err(|e| ProfileError::Serialization(e.to_string()))
    }

    /// Validate, then encode to the deterministic canonical byte form.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        self.validate()?;
        crate::canonical::encode(self)
    }

    /// Domain-separated SHA-256 of [`canonical_bytes`](Self::canonical_bytes),
    /// as 64 lowercase hex characters.
    pub fn identity_digest(&self) -> Result<String, ProfileError> {
        let bytes = self.canonical_bytes()?;
        Ok(hex::encode(crate::canonical::digest_of(&bytes)))
    }

    /// Copy this profile under a new `environment_id`, validating the result.
    ///
    /// This is the only sanctioned way to duplicate an environment definition:
    /// fingerprint settings carry over, identity does not, and because the
    /// digest includes `environment_id` the copy gets a distinct digest.
    pub fn clone_as_environment(
        &self,
        environment_id: impl Into<String>,
    ) -> Result<Self, ProfileError> {
        let mut copy = self.clone();
        copy.environment_id = environment_id.into();
        copy.validate()?;
        Ok(copy)
    }
}

pub(crate) fn deser_error(e: serde_json::Error) -> ProfileError {
    // serde's field path is kept in the message: operators need to know which
    // field was rejected, and profile JSON carries no secret material.
    ProfileError::Deserialization(e.to_string())
}
