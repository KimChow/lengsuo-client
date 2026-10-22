//! Strict JSON parsing of `KernelManifestV1`: closed schema, no defaults, no
//! last-wins duplicate keys, single document, exact types, no log injection.

mod fixture;

use fixture::*;
use lengsuo_browser_package::KernelManifestV1;
use lengsuo_browser_package::PackageError;
use lengsuo_browser_package::MANIFEST_SCHEMA_VERSION;

/// Every field the schema requires, in declaration order.
const REQUIRED_FIELDS: &[&str] = &[
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

/// Fields the schema allows to be absent. Their absence is legal; their
/// presence is still type-checked and grammared.
const OPTIONAL_FIELDS: &[&str] = &["extension_dir_name", "extension_sha256"];

/// Keys a hostile (or merely newer) publisher might add, none of which the
/// schema may tolerate.
const HOSTILE_EXTRA_KEYS: &[&str] = &[
    "signatures",
    "signature",
    "sig",
    "pgp",
    "minisign",
    "issuer",
    "trust_root",
    "schema",
    "schema_versions",
    "schema_version_minor",
    "manifest_version",
    "supported_schema_versions",
    "size",
    "bytes",
    "checksum",
    "md5",
    "sha512",
    "filename",
    "path",
    "artifact_path",
    "download_url",
    "url",
    "urls",
    "mirror",
    "platforms",
    "arches",
    "capabilities",
    "provided_capabilities",
    "profile_schema",
    "pool_version",
    "chromium",
    "revision",
    "notes",
    "comment",
];

fn must_reject(text: &str, ctx: &str) -> PackageError {
    match KernelManifestV1::from_json_str(text) {
        Ok(manifest) => panic!("expected rejection for {ctx}, parsed: {manifest:?}"),
        Err(err) => err,
    }
}

/// Does the rejection speak in one of the schema's own error channels?
fn is_schema_rejection(err: &PackageError) -> bool {
    matches!(
        err,
        PackageError::JsonSyntax { .. }
            | PackageError::DuplicateKey { .. }
            | PackageError::UnknownField { .. }
            | PackageError::MissingField { .. }
            | PackageError::SchemaVersion { .. }
            | PackageError::InvalidField { .. }
            | PackageError::FieldType { .. }
            | PackageError::EmptyCollection { .. }
            | PackageError::CollectionTooLarge { .. }
            | PackageError::ExtensionFieldsUnpaired { .. }
    )
}

#[test]
fn golden_manifest_parses_and_validates() {
    let manifest = KernelManifestV1::from_json_str(&json_for(64))
        .unwrap_or_else(|e| panic!("canonical manifest must parse, got {e}"));
    manifest
        .validate()
        .expect("canonical manifest must validate");
    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.version, "155.0.8059.85");
    assert_eq!(manifest.chromium_revision, CHROMIUM_REVISION);
    assert_eq!(manifest.patchset_sha256, PATCHSET_SHA256);
    assert_eq!(manifest.size_bytes, 64);
    assert_eq!(manifest.sha256, known_sha256(64));
    assert_eq!(manifest.profile_schema_versions.len(), 1);
    assert_eq!(
        manifest.artifact_name,
        "chrome-linux-x86_64-155.0.8059.85.tar.zst"
    );
}

#[test]
fn serialization_is_byte_exact_and_field_ordered() {
    // Pin the wire format: key set, key order (struct declaration order) and
    // enum spellings. A regression here silently changes what every client
    // accepts, so compare exact bytes rather than parsed equality.
    let manifest = good_manifest();
    let encoded = serde_json::to_string(&manifest).expect("serialize");
    let expected = concat!(
        r#"{"schema_version":1,"version":"155.0.8059.85","#,
        r#""chromium_revision":"0e66b94549a8bd85f03fbdf189b752d6e7b63c32","#,
        r#""patchset_sha256":"5f896d6581df21565699ef4c44695cfb4466fa69a50de3260ff982b5574d872a","#,
        r#""platform":"Linux","arch":"X86_64","#,
        r#""artifact_name":"chrome-linux-x86_64-155.0.8059.85.tar.zst","#,
        r#""size_bytes":64,"#,
        r#""sha256":"734bcd3e0fb61460e6a628bc3c39966a663c6f5fd737f6fcc15dc9ebb667ce51","#,
        r#""profile_schema_versions":[1],"pool_versions":["pool-2026.10"],"#,
        r#""required_capabilities":["webauthn-proxy"]}"#
    );
    assert_eq!(encoded, expected);
    // Re-parsing our own output must succeed: the format is self-consistent.
    let reparsed = KernelManifestV1::from_json_str(&encoded).expect("re-parse");
    assert_eq!(reparsed, manifest);
}

#[test]
fn each_declared_field_name_and_enum_spelling_is_pinned() {
    // Enum spellings are part of the contract; a case change breaks every
    // existing manifest file.
    let text = json_for(64);
    for needle in [
        "\"schema_version\": 1",
        "\"platform\": \"Linux\"",
        "\"arch\": \"X86_64\"",
    ] {
        assert!(text.contains(needle), "{needle} missing from fixture");
    }
    for platform in ["Windows", "Linux", "Macos"] {
        let m =
            KernelManifestV1::from_json_str(&replaced(64, "platform", &format!(r#""{platform}""#)))
                .unwrap_or_else(|e| panic!("platform {platform} must parse: {e}"));
        m.validate().expect("platform validated");
    }
    for arch in ["X86_64", "Aarch64"] {
        let m = KernelManifestV1::from_json_str(&replaced(64, "arch", &format!(r#""{arch}""#)))
            .unwrap_or_else(|e| panic!("arch {arch} must parse: {e}"));
        m.validate().expect("arch validated");
    }
}

#[test]
fn every_extra_key_is_rejected() {
    for key in HOSTILE_EXTRA_KEYS {
        let text = extra(64, key, r#""x""#);
        let err = must_reject(&text, &format!("unknown field `{key}`"));
        assert!(
            matches!(err, PackageError::UnknownField { .. }),
            "`{key}` produced {err:?}"
        );
    }
}

#[test]
fn extra_field_with_object_value_is_rejected() {
    // The shape a real signed-manifest format would use; must not be absorbed
    // or mistaken for a signature the verifier will honour later.
    let text = extra(64, "signatures", r#"{"ed25519":"AAAA","publisher":"acme"}"#);
    let err = must_reject(&text, "signatures object");
    assert!(matches!(err, PackageError::UnknownField { .. }), "{err:?}");
}

#[test]
fn each_missing_required_field_is_rejected() {
    for field in REQUIRED_FIELDS {
        let text = without(64, field);
        let err = must_reject(&text, &format!("missing `{field}`"));
        assert!(
            matches!(err, PackageError::MissingField { .. }),
            "dropping `{field}` produced {err:?}"
        );
    }
}

#[test]
fn each_optional_field_may_be_absent() {
    // The opposite rule: an absent optional field is not a missing field.
    // A kernel package that ships no extension says nothing about one, and
    // the fixture declares neither field.
    for field in OPTIONAL_FIELDS {
        assert!(
            !fixture_fields(64).iter().any(|(k, _)| k == field),
            "the fixture must not carry the optional field `{field}`"
        );
    }
    let manifest = KernelManifestV1::from_json_str(&json_for(64)).expect("parse");
    manifest.validate().expect("validate");
    assert_eq!(manifest.extension_dir_name, None);
    assert_eq!(manifest.extension_sha256, None);
}

#[test]
fn duplicate_top_level_keys_are_rejected_even_when_benign() {
    // serde_json/BTreeMap let the last occurrence win, so a document pairing a
    // real digest with a second one would silently select the second. A
    // duplicate of a *known* key must be rejected before any typed parsing.
    let dup_targets: &[(&str, &str)] = &[
        ("sha256", SYC_SHA256),
        ("size_bytes", "1"),
        ("artifact_name", "evil.zip"),
        ("schema_version", "1"),
        ("platform", "Linux"),
        ("version", "155.0.8059.85"),
        ("chromium_revision", CHROMIUM_REVISION),
        ("profile_schema_versions", "[1]"),
        ("pool_versions", "[\"pool-2026.10\"]"),
        ("required_capabilities", "[\"webauthn-proxy\"]"),
        ("patchset_sha256", PATCHSET_SHA256),
    ];
    for (key, inner) in dup_targets {
        let text = extra(64, key, &json_str(inner));
        let err = must_reject(&text, &format!("duplicate `{key}`"));
        assert!(
            matches!(err, PackageError::DuplicateKey { .. }),
            "duplicate `{key}` produced {err:?}"
        );
    }
    // Numeric duplicate too (rendered as a bare number, not a string).
    let err = must_reject(&extra(64, "size_bytes", "1"), "duplicate size_bytes");
    assert!(matches!(err, PackageError::DuplicateKey { .. }), "{err:?}");
}

#[test]
fn duplicate_unknown_key_is_rejected_before_the_unknown_key_report() {
    let text = extra(64, "signatures", r#""a""#);
    let text = extra_pair(&text, "signatures", r#""b""#);
    let err = must_reject(&text, "duplicate unknown key");
    assert!(matches!(err, PackageError::DuplicateKey { .. }), "{err:?}");
}

#[test]
fn trailing_content_and_second_document_are_rejected() {
    let base = json_for(64);
    let legal_tails = ["", " ", "\n", "\t", "\r\n  "];
    for suffix in [
        "}",
        "{}",
        " null",
        ",{}",
        "\u{0}",
        "trailing junk",
        base.as_str(),
        &base[1..],
    ] {
        let text = format!("{base}{suffix}");
        let result = KernelManifestV1::from_json_str(&text);
        assert!(
            result.is_err(),
            "trailing {suffix:?} must be rejected, got {result:?}"
        );
    }
    for suffix in legal_tails {
        let text = format!("{base}{suffix}");
        KernelManifestV1::from_json_str(&text)
            .unwrap_or_else(|e| panic!("JSON whitespace tail {suffix:?} must be accepted: {e}"));
    }
}

#[test]
fn leading_content_is_rejected_except_plain_whitespace() {
    let base = json_for(64);
    for prefix in ["{", "[", "null", "<!--", "\u{feff}", "//x\n", "\u{0}", "#"] {
        let text = format!("{prefix}{base}");
        let result = KernelManifestV1::from_json_str(&text);
        assert!(
            result.is_err(),
            "leading {prefix:?} must be rejected, got {result:?}"
        );
    }
    for prefix in [" ", "\n", "\t", "\r\n "] {
        let text = format!("{prefix}{base}");
        KernelManifestV1::from_json_str(&text)
            .unwrap_or_else(|e| panic!("leading whitespace {prefix:?} must be accepted: {e}"));
    }
}

#[test]
fn top_level_must_be_an_object() {
    for text in [
        "[]",
        "null",
        "true",
        "false",
        "1",
        "1.5",
        r#""a string""#,
        "",
        "   ",
        "\n",
        r#"[{"schema_version":1}]"#,
    ] {
        let err = must_reject(text, &format!("top-level {text:?}"));
        assert!(
            matches!(err, PackageError::JsonSyntax { .. }),
            "{text:?} produced {err:?}"
        );
    }
}

#[test]
fn wrong_json_types_are_rejected_not_coerced() {
    let wrong: Vec<(&str, &str)> = vec![
        ("schema_version", r#""1""#),
        ("schema_version", "1.0"),
        ("schema_version", "true"),
        ("schema_version", "null"),
        ("schema_version", "[1]"),
        ("schema_version", "99999999999999"),
        ("version", "155"),
        ("version", "null"),
        ("version", "true"),
        ("chromium_revision", "null"),
        ("chromium_revision", "[1]"),
        ("patchset_sha256", "0"),
        ("platform", "1"),
        ("platform", "null"),
        ("platform", r#"{"name":"Linux"}"#),
        ("arch", "null"),
        ("arch", "[\"X86_64\"]"),
        ("artifact_name", "null"),
        ("artifact_name", r#"["a","b"]"#),
        ("size_bytes", r#""64""#),
        ("size_bytes", "64.0"),
        ("size_bytes", "64.5"),
        ("size_bytes", "-1"),
        ("size_bytes", "true"),
        ("size_bytes", "null"),
        ("size_bytes", "18446744073709551616"),
        ("sha256", "null"),
        ("sha256", "[\"x\"]"),
        ("profile_schema_versions", "1"),
        ("profile_schema_versions", r#""1""#),
        ("profile_schema_versions", r#"{"1":1}"#),
        ("profile_schema_versions", "[\"1\"]"),
        ("profile_schema_versions", "[null]"),
        ("profile_schema_versions", "[[1]]"),
        ("pool_versions", "null"),
        ("pool_versions", "[null]"),
        ("pool_versions", "[[\"a\"]]"),
        ("pool_versions", r#"{"a":1}"#),
        ("required_capabilities", r#""webauthn-proxy""#),
        ("required_capabilities", "null"),
        ("required_capabilities", "[{}]"),
    ];
    for (field, value) in wrong {
        let text = replaced(64, field, value);
        let err = must_reject(&text, &format!("{field}={value}"));
        assert!(
            is_schema_rejection(&err),
            "{field}={value} produced {err:?}"
        );
    }
}

#[test]
fn four_gib_is_a_legal_u64_size_below_the_documented_bound() {
    let manifest =
        KernelManifestV1::from_json_str(&replaced(64, "size_bytes", "4294967296")).unwrap();
    manifest.validate().unwrap();
    assert_eq!(manifest.size_bytes, 4294967296);
}
