//! Error types for manifest parsing, validation, compatibility and artifact
//! verification.
//!
//! Every variant is a *rejection*: nothing in this crate degrades a failed
//! check into a warning, a default value or a silently corrected field.
//!
//! # Untrusted text in messages
//!
//! Manifest content is attacker-chosen. Every variant that names a key, an id
//! or a digest reports it only after [`crate::grammar::sanitize`], which keeps
//! printable ASCII, escapes anything else and caps the length. That stops two
//! things at once: a key literally named `"\n[INFO] install approved"` forging
//! a log line, and a one-megabyte "field name" ending up in a log aggregator.
//! Computed digests are hex we produced ourselves and need no such treatment.

use std::io;

/// Failure while parsing or validating a [`KernelManifestV1`](crate::KernelManifestV1).
#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    /// The input is not syntactically valid JSON, is not a single JSON object,
    /// or has trailing content.
    ///
    /// Fixed message with position only: `serde_json`'s own `Display` quotes
    /// document content (`invalid type: string "…"`), which would hand a
    /// hostile manifest a way to write arbitrary text into client logs.
    #[error("manifest is not a valid JSON object: {reason} (line {line}, column {column})")]
    JsonSyntax {
        /// Coarse classification, one of a fixed set of phrases.
        reason: &'static str,
        /// 1-based line of the failure.
        line: usize,
        /// 1-based column of the failure.
        column: usize,
    },

    /// A JSON object repeats one key. Textbook JSON lets the last occurrence
    /// win, so a manifest could carry an innocuous-looking `sha256` plus a
    /// second one; strict parsing rejects the document instead.
    #[error("manifest repeats object key `{key}`")]
    DuplicateKey {
        /// Repeated key name, sanitized.
        key: String,
    },

    /// The document has a key that is not part of `KernelManifestV1`. The
    /// schema is closed: an extra key means the caller is looking at a newer,
    /// different or misspelled contract, and guessing is not an option.
    #[error("manifest has unknown field `{field}`")]
    UnknownField {
        /// Offending key, sanitized.
        field: String,
    },

    /// The document lacks a key that `KernelManifestV1` requires. There are no
    /// defaults: a missing field is a rejected manifest, not an optional one.
    #[error("manifest is missing required field `{field}`")]
    MissingField {
        /// Absent key, one of the known schema names.
        field: &'static str,
    },

    /// `schema_version` is not the one schema this build understands.
    #[error("unsupported manifest schema_version {found} (this build implements {wanted})")]
    SchemaVersion {
        /// Version found in the document.
        found: u32,
        /// Version this build implements.
        wanted: u32,
    },

    /// A required field is present but violates its documented grammar.
    #[error("manifest field `{field}` is invalid: {reason}")]
    InvalidField {
        /// Field name as it appears in the manifest.
        field: &'static str,
        /// What is wrong, in fixed words.
        reason: &'static str,
    },

    /// A field is present but has the wrong JSON type for the schema.
    #[error("manifest field `{field}` has the wrong JSON type: expected {expected}")]
    FieldType {
        /// Field name.
        field: &'static str,
        /// Shape the schema demands, in fixed words.
        expected: &'static str,
    },

    /// A set-valued field is empty.
    #[error("manifest field `{field}` must contain at least one entry")]
    EmptyCollection {
        /// Field name.
        field: &'static str,
    },

    /// A set-valued field has more entries than the accepted bound, which
    /// limits how much memory a hostile manifest can force a client to spend.
    #[error("manifest field `{field}` has {count} entries, more than the bound of {bound}")]
    CollectionTooLarge {
        /// Field name.
        field: &'static str,
        /// Entries present.
        count: usize,
        /// Accepted maximum.
        bound: usize,
    },

    /// The host this must run on is not the platform the kernel was built for.
    #[error("manifest kernel is built for platform {manifest} but the host is {host}")]
    PlatformMismatch {
        /// Platform declared by the manifest.
        manifest: crate::Platform,
        /// Host platform supplied by the caller.
        host: crate::Platform,
    },

    /// The host CPU is not the architecture the kernel was built for.
    #[error("manifest kernel is built for arch {manifest} but the host is {host}")]
    ArchMismatch {
        /// Architecture declared by the manifest.
        manifest: crate::Arch,
        /// Host architecture supplied by the caller.
        host: crate::Arch,
    },

    /// The caller's profile schema is outside the range this kernel supports.
    #[error("manifest kernel does not support profile schema version {wanted}")]
    ProfileSchemaUnsupported {
        /// Schema version the caller needs.
        wanted: u32,
    },

    /// The caller's value pool version is not listed by this kernel.
    #[error("manifest kernel does not support pool version `{pool}`")]
    PoolVersionUnsupported {
        /// Pool version the caller needs, sanitized.
        pool: String,
    },

    /// The host cannot provide capabilities the kernel requires.
    #[error("host is missing {count} capability requirement(s) of this kernel: {missing}")]
    MissingCapabilities {
        /// How many requirements are unmet.
        count: usize,
        /// Sanitized, sorted, comma-separated list.
        missing: String,
    },
}

/// Failure while verifying artifact bytes against a validated manifest.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The manifest was not valid, so there is nothing trustworthy to verify
    /// against. Verification refuses to start.
    #[error("refusing to verify against an invalid manifest: {0}")]
    Manifest(#[from] PackageError),

    /// The reader failed. Reported as-is; never converted into "truncated".
    #[error("artifact read failed at byte {read}: {source}")]
    Io {
        /// Bytes successfully read before the failure.
        read: u64,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// The stream ended before the declared number of bytes.
    #[error("artifact is truncated: got {got} bytes, manifest declares {expected}")]
    Truncated {
        /// Declared size.
        expected: u64,
        /// Bytes read before end of stream.
        got: u64,
    },

    /// The stream carried more bytes than declared. Caught at the first extra
    /// byte, so a hostile server cannot make the client stream an endless body.
    #[error(
        "artifact is larger than declared: got at least {got} bytes, manifest declares {expected}"
    )]
    Oversize {
        /// Declared size.
        expected: u64,
        /// Bytes read when the overrun was detected.
        got: u64,
    },

    /// The bytes are complete and of the right length but not the recorded
    /// digest: corruption or substitution.
    #[error("artifact digest mismatch: manifest declares {expected}, bytes hash to {actual}")]
    DigestMismatch {
        /// Digest recorded in the manifest.
        expected: String,
        /// Digest computed over the received bytes.
        actual: String,
    },
}
