//! Schema field grammars. No signature or publisher trust is inferred here.
use crate::grammar::*;
use crate::{KernelManifestV1, PackageError, MANIFEST_SCHEMA_VERSION, SUPPORTED_PROFILE_SCHEMA};

pub(crate) fn validate(m: &KernelManifestV1) -> Result<(), PackageError> {
    if m.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(PackageError::SchemaVersion {
            found: m.schema_version,
            wanted: MANIFEST_SCHEMA_VERSION,
        });
    }
    for (field, valid) in [
        ("version", version_shape_ok(&m.version)),
        (
            "chromium_revision",
            hex_lowercase_of_len(&m.chromium_revision, 40),
        ),
        (
            "patchset_sha256",
            hex_lowercase_of_len(&m.patchset_sha256, 64),
        ),
        ("sha256", hex_lowercase_of_len(&m.sha256, 64)),
        ("artifact_name", artifact_name_ok(&m.artifact_name)),
        ("size_bytes", (1..=MAX_SIZE_BYTES).contains(&m.size_bytes)),
        (
            "pool_versions",
            m.pool_versions.iter().all(|s| pool_version_ok(s)),
        ),
        (
            "required_capabilities",
            m.required_capabilities.iter().all(|s| capability_ok(s)),
        ),
    ] {
        if !valid {
            return Err(PackageError::InvalidField {
                field,
                reason: "invalid field grammar or bound",
            });
        }
    }
    for (field, count, required) in [
        (
            "profile_schema_versions",
            m.profile_schema_versions.len(),
            true,
        ),
        ("pool_versions", m.pool_versions.len(), true),
        (
            "required_capabilities",
            m.required_capabilities.len(),
            false,
        ),
    ] {
        if required && count == 0 {
            return Err(PackageError::EmptyCollection { field });
        }
        if count > MAX_COLLECTION_ENTRIES {
            return Err(PackageError::CollectionTooLarge {
                field,
                count,
                bound: MAX_COLLECTION_ENTRIES,
            });
        }
    }
    if !m
        .profile_schema_versions
        .contains(&SUPPORTED_PROFILE_SCHEMA)
    {
        return Err(PackageError::InvalidField {
            field: "profile_schema_versions",
            reason: "missing supported profile schema",
        });
    }
    Ok(())
}
