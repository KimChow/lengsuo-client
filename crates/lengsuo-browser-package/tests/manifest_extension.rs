//! The two optional extension fields: presence rules, grammars, and the
//! byte-stability of the serialized manifest.

mod fixture;

use fixture::*;
use lengsuo_browser_package::KernelManifestV1;
use lengsuo_browser_package::PackageError;

/// A well-formed extension directory name.
const DIR_NAME: &str = "lengsuo-credential";
/// A well-formed extension digest (64 lowercase hex).
const DIGEST: &str = "cad5376ed54dc3a7128a5df681c1beb1d2a07007c5f90cb128a5fd8e4b59c820";

/// The manifest with both extension fields present.
fn with_extension() -> String {
    let text = extra(64, "extension_dir_name", &json_str(DIR_NAME));
    extra_text(&text, "extension_sha256", &json_str(DIGEST))
}

/// Append one field to an already rendered object.
fn extra_text(json: &str, key: &str, raw: &str) -> String {
    let trimmed = json.trim_end();
    format!(
        "{},\n  {}: {}\n}}",
        &trimmed[..trimmed.len() - 1],
        json_str(key),
        raw
    )
}

#[test]
fn a_manifest_without_the_extension_fields_still_parses_and_validates() {
    // The two fields are optional: an existing kernel manifest that says
    // nothing about an extension must keep working.
    let manifest = KernelManifestV1::from_json_str(&json_for(64)).expect("parse");
    manifest.validate().expect("validate");
    assert_eq!(manifest.extension_dir_name, None);
    assert_eq!(manifest.extension_sha256, None);
}

#[test]
fn both_extension_fields_together_are_accepted() {
    let manifest = KernelManifestV1::from_json_str(&with_extension()).expect("parse");
    manifest.validate().expect("validate");
    assert_eq!(manifest.extension_dir_name.as_deref(), Some(DIR_NAME));
    assert_eq!(manifest.extension_sha256.as_deref(), Some(DIGEST));
}

#[test]
fn only_one_extension_field_is_rejected() {
    // The manifest is untrusted input: one half of the declaration says the
    // client cannot check the extension it claims to ship.
    let only_name = extra(64, "extension_dir_name", &json_str(DIR_NAME));
    let err = KernelManifestV1::from_json_str(&only_name)
        .expect_err("a lone extension_dir_name must be rejected");
    assert!(
        matches!(
            err,
            PackageError::ExtensionFieldsUnpaired {
                present: "extension_dir_name"
            }
        ),
        "unexpected error: {err:?}"
    );

    let only_digest = extra(64, "extension_sha256", &json_str(DIGEST));
    let err = KernelManifestV1::from_json_str(&only_digest)
        .expect_err("a lone extension_sha256 must be rejected");
    assert!(
        matches!(
            err,
            PackageError::ExtensionFieldsUnpaired {
                present: "extension_sha256"
            }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn a_directly_built_manifest_with_one_field_is_rejected_by_validate() {
    // The pairing is not only a parse-time rule: a value assembled by hand
    // must fail validation too.
    let mut manifest = good_manifest();
    manifest.extension_dir_name = Some(DIR_NAME.to_string());
    let err = manifest
        .validate()
        .expect_err("a lone extension_dir_name must be rejected");
    assert!(
        matches!(
            err,
            PackageError::ExtensionFieldsUnpaired {
                present: "extension_dir_name"
            }
        ),
        "unexpected error: {err:?}"
    );

    let mut manifest = good_manifest();
    manifest.extension_sha256 = Some(DIGEST.to_string());
    let err = manifest
        .validate()
        .expect_err("a lone extension_sha256 must be rejected");
    assert!(
        matches!(
            err,
            PackageError::ExtensionFieldsUnpaired {
                present: "extension_sha256"
            }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn hostile_extension_directory_names_are_rejected() {
    for hostile in [
        "",
        ".",
        "..",
        "../evil",
        "a/b",
        "sub\\dir",
        "/absolute",
        "C:\\windows",
        ".hidden",
        "-flag",
        "trailing.",
        "trailing-",
        "with space",
        "with\ttab",
        "nul",
        "CON",
        "COM1",
        "LPT9",
        "aux.txt",
        "ünïcode",
        "emoji😀",
    ] {
        let text = with_extension();
        let text = text.replace(&json_str(DIR_NAME), &json_str(hostile));
        let parsed = KernelManifestV1::from_json_str(&text).expect("parse");
        let err = parsed
            .validate()
            .expect_err("a hostile extension_dir_name must be rejected");
        assert!(
            matches!(
                err,
                PackageError::InvalidField {
                    field: "extension_dir_name",
                    ..
                }
            ),
            "extension_dir_name {hostile:?} produced {err:?}"
        );
    }
}

#[test]
fn a_too_long_extension_directory_name_is_rejected() {
    let long = "a".repeat(256);
    let text = with_extension();
    let text = text.replace(&json_str(DIR_NAME), &json_str(&long));
    let parsed = KernelManifestV1::from_json_str(&text).expect("parse");
    let err = parsed.validate().expect_err("must be rejected");
    assert!(
        matches!(
            err,
            PackageError::InvalidField {
                field: "extension_dir_name",
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn a_255_byte_extension_directory_name_is_accepted() {
    let long = "a".repeat(255);
    let text = with_extension();
    let text = text.replace(&json_str(DIR_NAME), &json_str(&long));
    let parsed = KernelManifestV1::from_json_str(&text).expect("parse");
    parsed
        .validate()
        .expect("a 255-byte name is within the bound");
}

#[test]
fn hostile_extension_digests_are_rejected() {
    for hostile in [
        "".to_string(),
        "cad5376e".to_string(),
        DIGEST[..63].to_string(),
        format!("{DIGEST}0"),
        DIGEST.to_uppercase(),
        format!("{}g", &DIGEST[..63]),
        format!(" {}", &DIGEST[..63]),
    ] {
        let hostile = hostile.as_str();
        let text = with_extension();
        let text = text.replace(&json_str(DIGEST), &json_str(hostile));
        let parsed = KernelManifestV1::from_json_str(&text).expect("parse");
        let err = parsed
            .validate()
            .expect_err("a hostile extension_sha256 must be rejected");
        assert!(
            matches!(
                err,
                PackageError::InvalidField {
                    field: "extension_sha256",
                    ..
                }
            ),
            "extension_sha256 {hostile:?} produced {err:?}"
        );
    }
}

#[test]
fn the_extension_fields_must_be_json_strings() {
    for (key, value) in [
        ("extension_dir_name", "1"),
        ("extension_dir_name", "null"),
        ("extension_dir_name", "[\"a\"]"),
        ("extension_dir_name", "{}"),
        ("extension_sha256", "1"),
        ("extension_sha256", "null"),
        ("extension_sha256", "[\"a\"]"),
    ] {
        let text = replace_field(&with_extension(), key, value);
        let err = KernelManifestV1::from_json_str(&text)
            .expect_err("a non-string extension field must be rejected");
        assert!(
            matches!(err, PackageError::FieldType { .. }),
            "{key}={value} produced {err:?}"
        );
    }
}

#[test]
fn serialization_of_an_existing_manifest_is_unchanged_by_the_new_fields() {
    // The release pipeline signs these exact bytes, so a manifest without an
    // extension must serialize exactly as it did before the fields existed.
    let manifest = good_manifest();
    let encoded = serde_json::to_string(&manifest).expect("serialize");
    assert!(
        !encoded.contains("extension_dir_name"),
        "an absent optional field must not appear: {encoded}"
    );
    assert!(
        !encoded.contains("extension_sha256"),
        "an absent optional field must not appear: {encoded}"
    );
    assert_eq!(
        encoded,
        concat!(
            r#"{"schema_version":1,"version":"155.0.8059.85","#,
            r#""chromium_revision":"0e66b94549a8bd85f03fbdf189b752d6e7b63c32","#,
            r#""patchset_sha256":"5f896d6581df21565699ef4c44695cfb4466fa69a50de3260ff982b5574d872a","#,
            r#""platform":"Linux","arch":"X86_64","#,
            r#""artifact_name":"chrome-linux-x86_64-155.0.8059.85.tar.zst","#,
            r#""size_bytes":64,"#,
            r#""sha256":"734bcd3e0fb61460e6a628bc3c39966a663c6f5fd737f6fcc15dc9ebb667ce51","#,
            r#""profile_schema_versions":[1],"pool_versions":["pool-2026.10"],"#,
            r#""required_capabilities":["webauthn-proxy"]}"#
        ),
        "the wire format of an extension-free manifest must not move"
    );
}

#[test]
fn the_extension_fields_serialize_after_the_required_ones() {
    let manifest = KernelManifestV1::from_json_str(&with_extension()).expect("parse");
    let encoded = serde_json::to_string(&manifest).expect("serialize");
    assert!(
        encoded.ends_with(&format!(
            r#""extension_dir_name":"{DIR_NAME}","extension_sha256":"{DIGEST}"}}"#
        )),
        "unexpected field order: {encoded}"
    );
    let reparsed = KernelManifestV1::from_json_str(&encoded).expect("re-parse");
    assert_eq!(reparsed, manifest);
}

/// Replace one field's raw value in a rendered manifest.
fn replace_field(json: &str, key: &str, raw: &str) -> String {
    let needle = format!("\"{key}\": ");
    let start = json
        .find(&needle)
        .unwrap_or_else(|| panic!("no field {key} in {json}"))
        + needle.len();
    let rest = &json[start..];
    // The value is a JSON string or a bare token; find where it ends.
    let end = if rest.starts_with('"') {
        let mut idx = 1;
        let bytes = rest.as_bytes();
        while idx < bytes.len() {
            if bytes[idx] == b'\\' {
                idx += 2;
                continue;
            }
            if bytes[idx] == b'"' {
                break;
            }
            idx += 1;
        }
        idx + 1
    } else {
        rest.find([',', '\n']).unwrap_or(rest.len())
    };
    format!("{}{raw}{}", &json[..start], &rest[end..])
}
