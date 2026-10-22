//! The kernel release manifest: fields, grammar and host compatibility.
//!
//! See [`KernelManifestV1`] and the crate docs for the trust boundary.
//!
//! # Why `required_capabilities` and not `provided_capabilities`
//!
//! The manifest's capability set models what the **kernel needs from the host**:
//! a package built to lean on a host-provided WebAuthn proxy or a VA-API
//! backend cannot run where that is absent, so refusing to start it is the
//! fail-closed behaviour we want, and the caller's own state
//! (`available_capabilities`) is the authoritative input for that decision.
//!
//! A kernel *advertising* the features it provides is the opposite direction:
//! then the consumer would declare its requirements and the manifest would
//! declare what it offers, and the manifest's list becomes untrusted marketing
//! copy that nothing may depend on for safety. Both designs exist in the wild;
//! this contract implements the first, because the installer's real question is
//! "can this build run here". If the product later needs the second as well, it
//! should arrive as a separate, differently-named field (`provided_capabilities`)
//! with its own check and its own tests — never by reinterpreting this one, so
//! that an existing manifest can never silently flip its meaning.

use std::collections::BTreeSet;
use std::io::Read;

use crate::error::PackageError;
use crate::error::VerifyError;
use crate::VerifyReport;

/// The only manifest schema version this build accepts.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The profile schema version every kernel manifest must declare support for.
///
/// One schema is supported today; the field is still a set because the format
/// exists to allow a kernel to span more than one, and pinning a single value
/// would make that impossible without another schema change.
pub const SUPPORTED_PROFILE_SCHEMA: u32 = 1;

/// Target operating system of a kernel build.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Platform {
    /// Windows. Serialized as `"Windows"`.
    #[serde(rename = "Windows")]
    Windows,
    /// Linux. Serialized as `"Linux"`.
    #[serde(rename = "Linux")]
    Linux,
    /// macOS. Serialized as `"Macos"`.
    #[serde(rename = "Macos")]
    Macos,
}

/// Target CPU architecture of a kernel build.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Arch {
    /// x86-64. Serialized as `"X86_64"`.
    #[serde(rename = "X86_64")]
    X86_64,
    /// Arm 64-bit. Serialized as `"Aarch64"`.
    #[serde(rename = "Aarch64")]
    Aarch64,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Platform::Windows => "Windows",
            Platform::Linux => "Linux",
            Platform::Macos => "Macos",
        })
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Arch::X86_64 => "X86_64",
            Arch::Aarch64 => "Aarch64",
        })
    }
}

/// A kernel release manifest, schema version 1.
///
/// Construct it only through [`KernelManifestV1::from_json_str`], which is the
/// strict parser: it rejects unknown fields, missing fields, duplicate keys, a
/// wrong `schema_version` and trailing content. Field grammars require a separate
/// `validate()` call. The struct fields are public so
/// callers can read a validated manifest, but a value built by direct
/// construction has *not* been validated — call
/// [`validate`](Self::validate) first, and remember that validation checks the
/// manifest against its own grammar only, never against a publisher.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelManifestV1 {
    /// Manifest schema version; must be [`MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Release version, four dot-separated numeric components.
    pub version: String,
    /// Full Chromium source revision: exactly 40 lowercase hex characters.
    pub chromium_revision: String,
    /// SHA-256 of the ordered patch set applied to that revision, 64 lowercase
    /// hex characters. Not a digest of the artifact.
    pub patchset_sha256: String,
    /// Operating system the artifact was built for.
    pub platform: Platform,
    /// CPU architecture the artifact was built for.
    pub arch: Arch,
    /// Safe basename only. This crate does not build download URLs, and this
    /// field is a basename rather than a path: it is checked against a
    /// lexical grammar and never resolved against the filesystem.
    pub artifact_name: String,
    /// Exact artifact length in bytes: at least 1, at most the internal
    /// `MAX_SIZE_BYTES` bound (16 GiB).
    pub size_bytes: u64,
    /// SHA-256 of the artifact bytes, 64 lowercase hex characters. Integrity
    /// only — see the crate-level trust boundary.
    pub sha256: String,
    /// Profile schema versions this kernel can consume. Non-empty, bounded, and
    /// must include [`SUPPORTED_PROFILE_SCHEMA`].
    pub profile_schema_versions: BTreeSet<u32>,
    /// Fingerprint value-pool versions this kernel was tested against.
    /// Non-empty, bounded, conservative token ids.
    pub pool_versions: BTreeSet<String>,
    /// Host capabilities this kernel requires at run time. May be empty when the
    /// kernel needs nothing beyond a plain host. See the module docs for why
    /// this is "required by the kernel from the host" rather than "provided by
    /// the kernel".
    pub required_capabilities: BTreeSet<String>,
    /// Name of the extension directory shipped alongside the kernel, e.g.
    /// `lengsuo-credential`. A single path component, not a path.
    ///
    /// Optional, but paired with [`extension_sha256`](Self::extension_sha256):
    /// either both are present or neither is. A manifest that names an
    /// extension without a digest for it claims a payload the client cannot
    /// verify, so it is rejected rather than half-accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_dir_name: Option<String>,
    /// Deterministic digest of the extension directory named by
    /// [`extension_dir_name`](Self::extension_dir_name): 64 lowercase hex
    /// characters. See [`crate::digest_directory`] for the algorithm.
    ///
    /// Optional, and paired with
    /// [`extension_dir_name`](Self::extension_dir_name) as described there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_sha256: Option<String>,
}

impl KernelManifestV1 {
    /// Maximum accepted artifact size (16 GiB).
    pub const MAX_ACCEPTED_SIZE_BYTES: u64 = crate::grammar::MAX_SIZE_BYTES;

    /// Parse exact field names, JSON types and schema version. Call `validate`
    /// to check field grammars before using a parsed value.
    pub fn from_json_str(text: &str) -> Result<Self, PackageError> {
        crate::parsing::parse(text)
    }

    /// Check every field against its grammar and bounds.
    pub fn validate(&self) -> Result<(), PackageError> {
        crate::validation::validate(self)
    }

    /// Validate, then check platform, CPU, schemas, pool and host requirements.
    pub fn assert_compatible(
        &self,
        host_platform: Platform,
        host_arch: Arch,
        profile_schema: u32,
        pool_version: &str,
        available_capabilities: &BTreeSet<String>,
    ) -> Result<(), PackageError> {
        self.validate()?;
        if self.platform != host_platform {
            return Err(PackageError::PlatformMismatch {
                manifest: self.platform,
                host: host_platform,
            });
        }
        if self.arch != host_arch {
            return Err(PackageError::ArchMismatch {
                manifest: self.arch,
                host: host_arch,
            });
        }
        if !self.profile_schema_versions.contains(&profile_schema) {
            return Err(PackageError::ProfileSchemaUnsupported {
                wanted: profile_schema,
            });
        }
        if !self.pool_versions.contains(pool_version) {
            return Err(PackageError::PoolVersionUnsupported {
                pool: crate::grammar::sanitize(pool_version),
            });
        }
        let missing: Vec<_> = self
            .required_capabilities
            .difference(available_capabilities)
            .collect();
        if !missing.is_empty() {
            return Err(PackageError::MissingCapabilities {
                count: missing.len(),
                missing: missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        Ok(())
    }

    /// Stream exact length and SHA256. This is an integrity check only.
    pub fn verify_reader<R: Read>(&self, reader: R) -> Result<VerifyReport, VerifyError> {
        crate::artifact::verify_reader(self, reader)
    }
}
