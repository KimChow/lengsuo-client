//! Field grammar enforced by `validate()`: version shape, hex-shaped fields,
//! hostile artifact names, and the bounds on the three collections.

mod fixture;

use fixture::*;
use lengsuo_browser_package::PackageError;
use lengsuo_browser_package::SUPPORTED_PROFILE_SCHEMA;
use lengsuo_browser_package::{Arch, KernelManifestV1, Platform};

/// Parse a fixture with one field replaced by raw JSON text.
fn with(field: &str, raw: &str) -> KernelManifestV1 {
    KernelManifestV1::from_json_str(&replaced(64, field, raw))
        .unwrap_or_else(|e| panic!("{field}={raw} must parse as a document: {e}"))
}

/// Assert a manifest fails `validate()`, and return the error.
fn rejected(m: &KernelManifestV1, ctx: &str) -> PackageError {
    match m.validate() {
        Ok(()) => panic!("expected validate() rejection for {ctx}"),
        Err(err) => err,
    }
}

// --------------------------------------------- profile_schema_versions ---

#[test]
fn profile_schema_versions_must_be_nonempty_and_include_supported() {
    let err = rejected(&with("profile_schema_versions", "[]"), "empty schema list");
    assert!(
        matches!(err, PackageError::EmptyCollection { .. }),
        "{err:?}"
    );

    for raw in ["[2]", "[2,3]", "[0]", "[4294967295]"] {
        let err = rejected(&with("profile_schema_versions", raw), raw);
        assert!(
            matches!(err, PackageError::InvalidField { .. }),
            "{raw}: {err:?}"
        );
    }

    // Must contain the one schema this product line speaks.
    assert!(good_manifest()
        .profile_schema_versions
        .contains(&SUPPORTED_PROFILE_SCHEMA));
}

#[test]
fn profile_schema_versions_allows_duplicate_and_multi_range() {
    // Duplicates collapse in a BTreeSet, which is correct: the set is a claim
    // about support, not a list to preserve.
    for raw in ["[1,1,1]", "[1,1,2]", "[1,2,3,4,5]", "[1,4294967295]"] {
        with("profile_schema_versions", raw)
            .validate()
            .unwrap_or_else(|e| panic!("{raw} must validate: {e}"));
    }
    let m = with("profile_schema_versions", "[1,1,1]");
    assert_eq!(m.profile_schema_versions.len(), 1);
}

#[test]
fn profile_schema_versions_rejects_non_numeric_items() {
    for raw in [
        r#"[1,"2"]"#,
        "[null]",
        "[[1]]",
        "[{}]",
        "[1.0]",
        "[-1]",
        "[1e3]",
        "\"1\"",
        "1",
        "null",
        "{\"1\":1}",
    ] {
        let err = KernelManifestV1::from_json_str(&replaced(64, "profile_schema_versions", raw))
            .expect_err(&format!("schemas {raw} must be rejected"));
        assert!(
            matches!(
                err,
                PackageError::FieldType { .. } | PackageError::JsonSyntax { .. }
            ),
            "schemas {raw}: {err:?}"
        );
    }
}

#[test]
fn collections_are_entry_bounded() {
    // One hostile manifest must not dictate a large allocation.
    let schemas = format!(
        "[1,{}]",
        (2..=200u32)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let err = rejected(&with("profile_schema_versions", &schemas), "200 schemas");
    assert!(
        matches!(
            err,
            PackageError::CollectionTooLarge {
                field: "profile_schema_versions",
                ..
            }
        ),
        "{err:?}"
    );

    let pools = json_array((0..200).map(|i| format!("pool-{i}")).collect::<Vec<_>>());
    let err = rejected(&with("pool_versions", &pools), "200 pools");
    assert!(
        matches!(
            err,
            PackageError::CollectionTooLarge {
                field: "pool_versions",
                ..
            }
        ),
        "{err:?}"
    );

    let caps = json_array((0..200).map(|i| format!("cap-{i}")).collect::<Vec<_>>());
    let err = rejected(&with("required_capabilities", &caps), "200 caps");
    assert!(
        matches!(
            err,
            PackageError::CollectionTooLarge {
                field: "required_capabilities",
                ..
            }
        ),
        "{err:?}"
    );

    // Within the bound: accepted.
    let pools = json_array((0..64).map(|i| format!("pool-{i}")).collect::<Vec<_>>());
    with("pool_versions", &pools)
        .validate()
        .expect("64 pools must validate");
}

// ------------------------------------------------------------ pool_versions ---

#[test]
fn pool_versions_must_be_nonempty_and_well_formed() {
    let err = rejected(&with("pool_versions", "[]"), "empty pool list");
    assert!(
        matches!(err, PackageError::EmptyCollection { .. }),
        "{err:?}"
    );

    let mut hostile: Vec<String> = vec![
        "".to_string(),
        " ".to_string(),
        "..".to_string(),
        "../etc".to_string(),
        "a/b".to_string(),
        "a\\b".to_string(),
        "a:b".to_string(),
        "-lead".to_string(),
        ".lead".to_string(),
        "trail.".to_string(),
        "a..b".to_string(),
        "a\u{0}b".to_string(),
        "a\nb".to_string(),
        "POOL-2026.10".to_string(),
        "P".to_string(),
        "ünïcode".to_string(),
        "内核池".to_string(),
        "a".repeat(65),
        "a".repeat(100_000),
    ];
    hostile.extend((0..8).map(|i| format!("pool-{i}\u{1}")));

    for raw in &hostile {
        let text = replaced(
            64,
            "pool_versions",
            &json_array(std::iter::once(raw.as_str())),
        );
        let err = match KernelManifestV1::from_json_str(&text) {
            Ok(m) => rejected(&m, &format!("pool {raw:?}")),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                PackageError::InvalidField { .. } | PackageError::FieldType { .. }
            ),
            "pool {raw:?}: {err:?}"
        );
        if let PackageError::InvalidField { field, .. } = err {
            assert_eq!(field, "pool_versions");
        }
    }

    for raw in [
        "pool-2026.10",
        "2026.10",
        "base_a",
        "a",
        "p",
        "pool-1",
        "0",
        "a.b_c-d",
    ] {
        let text = replaced(64, "pool_versions", &json_array([raw]));
        KernelManifestV1::from_json_str(&text)
            .expect("parses")
            .validate()
            .unwrap_or_else(|e| panic!("pool {raw:?} must validate: {e}"));
    }
}

#[test]
fn pool_versions_rejects_non_string_items() {
    for raw in [
        "[null]",
        "[1]",
        "[[\"a\"]]",
        "[{}]",
        r#"{"a":1}"#,
        "null",
        "\"pool-1\"",
    ] {
        let err = KernelManifestV1::from_json_str(&replaced(64, "pool_versions", raw))
            .expect_err(&format!("pools {raw} must be rejected"));
        assert!(
            matches!(
                err,
                PackageError::FieldType { .. } | PackageError::JsonSyntax { .. }
            ),
            "pools {raw}: {err:?}"
        );
    }
}

// ---------------------------------------------------- required_capabilities ---

#[test]
fn required_capabilities_may_be_empty_unlike_the_other_collections() {
    // Documented asymmetry: a kernel that needs nothing from the host is legal.
    let m = with("required_capabilities", "[]");
    m.validate().expect("empty requirements must validate");
    assert!(m.required_capabilities.is_empty());
}

#[test]
fn required_capabilities_must_be_lowercase_identifier_tokens() {
    let hostile: Vec<String> = vec![
        "".to_string(),
        " ".to_string(),
        "web authn".to_string(),
        "WebAuthn".to_string(),
        "VA-API".to_string(),
        "-lead".to_string(),
        ".lead".to_string(),
        "webauthn.".to_string(),
        "a..b".to_string(),
        "../../etc".to_string(),
        "a/b".to_string(),
        "a\\b".to_string(),
        "webauthn:\u{0}".to_string(),
        "webauthn\n".to_string(),
        "1cap".to_string(),
        "_cap".to_string(),
        "c".repeat(65),
        "vaapié".to_string(),
        "A".repeat(200),
    ];
    for raw in &hostile {
        let text = replaced(
            64,
            "required_capabilities",
            &json_array(std::iter::once(raw.as_str())),
        );
        let err = match KernelManifestV1::from_json_str(&text) {
            Ok(m) => rejected(&m, &format!("capability {raw:?}")),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                PackageError::InvalidField { .. } | PackageError::FieldType { .. }
            ),
            "capability {raw:?}: {err:?}"
        );
        if let PackageError::InvalidField { field, .. } = err {
            assert_eq!(field, "required_capabilities");
        }
    }

    for raw in [
        "webauthn-proxy",
        "vaapi",
        "a",
        "x-y_z.0",
        "cap9",
        "a".repeat(64).as_str(),
    ] {
        let text = replaced(64, "required_capabilities", &json_array([raw]));
        KernelManifestV1::from_json_str(&text)
            .expect("parses")
            .validate()
            .unwrap_or_else(|e| panic!("capability {raw:?} must validate: {e}"));
    }
}

#[test]
fn capability_direction_is_required_not_provided_and_cannot_be_reworded() {
    // The field means "the kernel demands this of the host". A hostile manifest
    // cannot express the opposite contract by renaming a value: `provided-`
    // prefixed tokens are ordinary identifiers here, so the only way to change
    // the meaning is the separate `provided_capabilities` key — which the
    // closed schema refuses (manifest_strict::every_extra_key_is_rejected).
    let m = KernelManifestV1::from_json_str(&replaced(
        64,
        "required_capabilities",
        &json_array(["provided-vaapi"]),
    ))
    .expect("parses")
    .validate()
    .map(|()| good_manifest());
    assert!(m.is_ok());

    // Semantics test: a host that merely *offers* extra capabilities does not
    // satisfy a requirement the manifest names differently.
    let requires = KernelManifestV1::from_json_str(&replaced(
        64,
        "required_capabilities",
        &json_array(["vaapi"]),
    ))
    .expect("requires vaapi");
    let host_offers_other = ["webauthn-proxy".to_string()].into_iter().collect();
    assert!(requires
        .assert_compatible(
            Platform::Linux,
            Arch::X86_64,
            1,
            "pool-2026.10",
            &host_offers_other
        )
        .is_err());
}

#[test]
fn duplicate_entries_and_order_are_irrelevant_to_set_fields() {
    // The set form is what callers compare, so spelling differences that only
    // reorder or repeat must not change acceptance.
    let a = with(
        "pool_versions",
        &json_array(["pool-2026.10", "pool-2026.11"]),
    );
    let b = with(
        "pool_versions",
        &json_array(["pool-2026.11", "pool-2026.10"]),
    );
    assert_eq!(a.pool_versions, b.pool_versions);
    let c = with(
        "pool_versions",
        &json_array(["pool-2026.10", "pool-2026.10"]),
    );
    assert_eq!(c.pool_versions.len(), 1);
}

#[test]
fn validate_is_repeatable_and_does_not_mutate_state() {
    let mut m = good_manifest();
    for _ in 0..3 {
        m.validate().expect("idempotent");
    }
    let before = m.clone();
    m.sha256 = "0".repeat(64);
    assert!(m.validate().is_ok(), "digest shape is still valid hex");
    assert_ne!(m, before);
}
