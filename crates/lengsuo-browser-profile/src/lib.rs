//! Versioned browser environment profile contract (`lengsuo-browser-profile`).
//!
//! This crate owns the *data contract* for a fingerprint browser environment
//! profile: the frozen [`ProfileSpec`] structure, its validation rules, the
//! deterministic canonical encoding plus SHA-256 identity digest, and the
//! [`PoolCatalogV1`] slot-pool manifest used to reject unknown tier ids.
//!
//! Explicit non-goals (do not describe this crate as doing these):
//! - no production pool or device-population distributions are generated here;
//! - no fingerprint injection into a browser, and no Chromium or runtime code;
//! - no noise generation beyond carrying the versioned seed field;
//! - no server-side authority, signing, quota or entitlement logic.
//!
//! Failure policy is fail-closed: an unsupported schema, a missing or unknown
//! dimension, an unsafe identifier, an inconsistent platform/touch pairing, or
//! any slot id absent from the catalog pool is a hard error. There is never a
//! modulo, random or "closest match" fallback.

#![forbid(unsafe_code)]

mod canonical;
mod catalog;
mod error;
mod json;
mod spec;
mod validate;

pub use canonical::{CANONICAL_DOMAIN, CANONICAL_HEADER};
pub use catalog::{DimensionPools, PoolCatalogV1, Reject};
pub use error::ProfileError;
pub use json::{MAX_CATALOG_JSON_BYTES, MAX_PROFILE_JSON_BYTES};
pub use spec::{
    HardwareSpec, LocaleSpec, Platform, ProfileSpec, ScreenSpec, WebRtcIpHandlingPolicy,
    MAX_IDENTIFIER_LEN, MAX_WEBRTC_POLICY_CODE, NOISE_SEED_HEX_LEN, SCHEMA_VERSION_V1,
    SCHEMA_VERSION_V2,
};
pub use validate::{
    DIMENSIONS, MAX_CPU_CORES, MAX_DPR_MILLI, MAX_LANGUAGE_LEN, MAX_MEMORY_MIB, MAX_SCREEN_AREA,
    MAX_SCREEN_DIMENSION, MAX_SLOT_ID, MAX_TIMEZONE_LEN, MAX_TOUCH_POINTS, MIN_MEMORY_MIB,
    MIN_SCREEN_DIMENSION, MIN_SLOT_CPU_CORES, MIN_SLOT_ID, SUPPORTED_COLOR_DEPTHS,
    SUPPORTED_DIMENSIONS,
};
