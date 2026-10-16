//! Strict, versioned browser kernel package metadata and artifact integrity
//! verification.
//!
//! This crate answers exactly two questions and nothing else:
//!
//! 1. *Is this kernel release manifest a well-formed, self-consistent
//!    [`KernelManifestV1`] that can run on this host?* ([`KernelManifestV1::validate`],
//!    [`KernelManifestV1::assert_compatible`]).
//! 2. *Do these downloaded artifact bytes match the size and SHA-256 the
//!    manifest declares, byte for byte?* ([`KernelManifestV1::verify_reader`]).
//!
//! It never fetches, never extracts, never installs and never launches a
//! kernel. Those belong to the installer/runner.
//!
//! # Trust boundary — read this before shipping an installer
//!
//! SHA-256 proves **integrity only**: that the bytes you verified are the
//! bytes whose digest the manifest recorded. It does **not** prove that a
//! publisher produced those bytes, and it does **not** prove that the manifest
//! itself came from the release pipeline. An attacker who can replace both the
//! artifact and the manifest can simply recompute a matching digest, and this
//! crate will happily report success.
//!
//! Raw parsed manifests remain unauthenticated input. [`AuthenticatedManifest`]
//! consumes a real `VerifiedPayload` from `lengsuo-browser-signature`, parses
//! precisely its authenticated manifest bytes and fully validates the schema.
//! It retains that payload for preinstallation expiry checks and release-floor
//! persistence; it never exposes mutable proof-bound metadata. Platform code
//! still owns installation authorization, trusted time, approved keys, key
//! revocation, safe extraction and persisting the floor after successful commit.
//!
//! # Capability semantics
//!
//! [`required_capabilities`](KernelManifestV1::required_capabilities) is what
//! the **kernel package demands of the host** at run time (for example a
//! compositing or WebAuthn-proxy host feature). The caller supplies the set of
//! capabilities the host actually offers as `available_capabilities`, and a
//! manifest whose required set is not covered is rejected.
//! The opposite framing — a kernel advertising the features it *provides*,
//! with the consumer declaring what it needs — is a different contract
//! (`provided_capabilities`) that this crate deliberately does not claim; see
//! the module docs of [`manifest`] for why, and what would have to be added
//! for it.
//!
//! Whatever the direction, capability names are an unauthenticated convenience
//! list, not an access-control mechanism: a hostile manifest can claim any
//! capability, so nothing may grant privileges based on them.

#![forbid(unsafe_code)]

mod artifact;
mod error;
mod grammar;
mod manifest;
mod parsing;
mod trust;
mod validation;

pub use artifact::verify_reader;
pub use artifact::VerifyReport;
pub use artifact::MIN_ARTIFACT_BYTES;
pub use artifact::READ_CHUNK_BYTES;

pub use error::PackageError;
pub use error::VerifyError;

pub use manifest::Arch;
pub use manifest::KernelManifestV1;
pub use manifest::Platform;
pub use manifest::MANIFEST_SCHEMA_VERSION;
pub use manifest::SUPPORTED_PROFILE_SCHEMA;

pub use trust::AuthenticatedManifest;
