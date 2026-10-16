//! Immutable binding between authenticated release bytes and validated metadata.
use crate::{KernelManifestV1, PackageError, VerifyError, VerifyReport};
use lengsuo_browser_signature::{Error, ReleaseFloor, VerifiedPayload};

/// Metadata parsed and validated from exactly one verified release payload.
///
/// The only constructor consumes a proof from the signature component. Neither
/// the proof nor metadata can be replaced independently, and mutable metadata is
/// never exposed. This does not grant installation authorization: callers must
/// check compatibility, verify artifact bytes, recheck trusted time immediately
/// before committing installation, and persist the resulting release floor.
///
/// Raw metadata cannot construct this type:
/// ```compile_fail
/// use lengsuo_browser_package::{AuthenticatedManifest, KernelManifestV1};
/// fn forge(manifest: KernelManifestV1) -> AuthenticatedManifest {
///     AuthenticatedManifest { manifest, payload: () }
/// }
/// ```
/// Authenticated metadata cannot be modified in place:
/// ```compile_fail
/// use lengsuo_browser_package::AuthenticatedManifest;
/// fn replace(authenticated: &mut AuthenticatedManifest) {
///     authenticated.manifest().sha256 = "0".repeat(64);
/// }
/// ```
#[derive(Debug)]
pub struct AuthenticatedManifest {
    manifest: KernelManifestV1,
    payload: VerifiedPayload,
}

impl AuthenticatedManifest {
    /// Parse only the exact authenticated manifest bytes, then fully validate.
    /// A valid publisher signature never bypasses schema or grammar checks.
    pub fn from_verified_payload(payload: VerifiedPayload) -> Result<Self, PackageError> {
        let manifest = KernelManifestV1::from_json_str(payload.manifest_json())?;
        manifest.validate()?;
        Ok(Self { manifest, payload })
    }

    /// Immutable metadata; copying it does not copy publisher authentication.
    pub fn manifest(&self) -> &KernelManifestV1 {
        &self.manifest
    }

    /// Recheck trusted time immediately before installation commit. Fails on
    /// expiry or a time earlier than the original verification instant.
    pub fn assert_current(&self, trusted_now_unix: u64) -> Result<(), Error> {
        self.payload.assert_current(trusted_now_unix)
    }

    /// Floor to persist only after a successful, authorized installation commit.
    pub fn release_floor(&self) -> ReleaseFloor {
        self.payload.release_floor()
    }

    /// Verify bytes against this exact proof-bound metadata, in bounded memory.
    /// Call `assert_current` again after downloading and before installation.
    pub fn verify_reader<R: std::io::Read>(&self, reader: R) -> Result<VerifyReport, VerifyError> {
        self.manifest.verify_reader(reader)
    }
}
