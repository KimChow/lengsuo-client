//! Exact JSON field and type parsing, separate from field grammar validation.
use crate::grammar::{check_field_names, strict_json_object};
use crate::{KernelManifestV1, PackageError, MANIFEST_SCHEMA_VERSION};
use serde_json::Value;

pub(crate) fn parse(text: &str) -> Result<KernelManifestV1, PackageError> {
    if text.len() > 1024 * 1024 {
        return Err(PackageError::InvalidField {
            field: "$",
            reason: "manifest exceeds 1 MiB",
        });
    }
    let pairs = strict_json_object(text)?;
    const FIELDS: &[&str] = &[
        "schema_version",
        "version",
        "chromium_revision",
        "patchset_sha256",
        "platform",
        "arch",
        "artifact_name",
        "size_bytes",
        "sha256",
        "profile_schema_versions",
        "pool_versions",
        "required_capabilities",
    ];
    check_field_names(&pairs, FIELDS)?;
    for (key, value) in &pairs {
        let field = *FIELDS.iter().find(|f| **f == key).expect("checked field");
        let valid = match field {
            "schema_version" => value.as_u64().is_some_and(|n| u32::try_from(n).is_ok()),
            "size_bytes" => value.as_u64().is_some(),
            "profile_schema_versions" => value.as_array().is_some_and(|a| {
                a.iter()
                    .all(|v| v.as_u64().is_some_and(|n| u32::try_from(n).is_ok()))
            }),
            "pool_versions" | "required_capabilities" => value
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string)),
            "platform" => value
                .as_str()
                .is_some_and(|s| ["Windows", "Linux", "Macos"].contains(&s)),
            "arch" => value
                .as_str()
                .is_some_and(|s| ["X86_64", "Aarch64"].contains(&s)),
            _ => value.is_string(),
        };
        if !valid {
            return Err(PackageError::FieldType {
                field,
                expected: "schema-defined exact JSON type",
            });
        }
    }
    // PairList already rejected duplicate keys; conversion cannot lose one.
    let value = Value::Object(pairs.into_iter().collect());
    let manifest: KernelManifestV1 =
        serde_json::from_value(value).map_err(crate::grammar::json_error)?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(PackageError::SchemaVersion {
            found: manifest.schema_version,
            wanted: MANIFEST_SCHEMA_VERSION,
        });
    }
    Ok(manifest)
}
