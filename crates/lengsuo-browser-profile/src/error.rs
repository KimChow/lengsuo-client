//! Errors for the browser environment profile contract.
//!
//! Every validation failure is explicit and fail-closed. The contract never
//! repairs a profile, never falls back to a random slot, and never substitutes
//! a missing pool entry with a modulo lookup.

/// A profile, catalog, or encoding operation failed the contract.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ProfileError {
    #[error("JSON envelope has {bytes} bytes, above limit {limit}")]
    JsonTooLarge { bytes: usize, limit: usize },

    #[error("schema_version {0} is not supported (expected 1)")]
    SchemaVersion(u32),

    #[error("noise_version {0} is not supported (expected 1)")]
    NoiseVersion(u32),

    #[error("noise_seed_hex must be exactly 16 lowercase hex characters")]
    NoiseSeedShape,

    #[error("{field} must not be empty")]
    EmptyIdentifier { field: &'static str },

    #[error("{field} is {len} characters, above the contract limit of {limit}")]
    IdentifierTooLong {
        field: &'static str,
        len: usize,
        limit: usize,
    },

    #[error(
        "{field} must use only ASCII letters, digits, '-' and '_'; \
         '.' and path separators are refused"
    )]
    IdentifierUnsafe { field: &'static str },

    #[error("{field} contains a path traversal or separator sequence")]
    IdentifierPathTraversal { field: &'static str },

    #[error("locale.language is not a well-formed BCP47-style tag")]
    LanguageSyntax,

    #[error("locale.timezone is not a well-formed IANA-style zone string")]
    TimezoneSyntax,

    #[error("\"{0}\" is not a supported slot dimension")]
    UnknownDimension(String),

    #[error("slot dimension \"{0}\" is missing")]
    MissingDimension(String),

    #[error("screen {field} must be between {min} and {max} (got {value})")]
    ScreenOutOfRange {
        field: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },

    #[error("hardware {field} must be between {min} and {max} (got {value})")]
    HardwareOutOfRange {
        field: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },

    #[error("unsupported color depth {0}")]
    ColorDepth(u64),

    #[error("slot {dimension} id {value} must be within 1..={max}")]
    SlotIdOutOfRange {
        dimension: String,
        value: u32,
        max: u32,
    },

    #[error("screen pixel area {value} exceeds the contract limit {max}")]
    ScreenAreaTooLarge { value: u64, max: u64 },

    #[error("mobile platforms require max_touch_points in 1..=10 (got {0})")]
    MobileTouchPoints(u64),

    #[error("non-mobile platforms require max_touch_points 0 (got {0})")]
    DesktopTouchPoints(u64),

    #[error("catalog pool for dimension \"{0}\" is empty")]
    EmptyPool(String),

    #[error("profile pool_version \"{profile}\" != catalog pool_version \"{catalog}\"")]
    PoolVersionMismatch { profile: String, catalog: String },

    #[error("slot id {id} is not in the {dimension} pool of the fixed catalog")]
    SlotIdNotInPool { dimension: String, id: u32 },

    #[error("catalog {0} must satisfy the same rules as a profile slot set")]
    CatalogShape(&'static str),

    #[error("canonical encoding refused: {0}")]
    Canonical(&'static str),

    #[error("JSON deserialization failed: {0}")]
    Deserialization(String),

    #[error("JSON serialization failed: {0}")]
    Serialization(String),
}
