//! Strict parser diagnostics and hostile input regression cases.
mod fixture;
use fixture::*;
use lengsuo_browser_package::{KernelManifestV1, PackageError};

fn must_reject(text: &str, ctx: &str) -> PackageError {
    KernelManifestV1::from_json_str(text).expect_err(ctx)
}
#[test]
fn schema_version_is_an_exact_match_not_a_range() {
    for (raw, expect_ok) in [
        ("1", true),
        ("0", false),
        ("2", false),
        ("4294967295", false),
    ] {
        let text = replaced(64, "schema_version", raw);
        let result = KernelManifestV1::from_json_str(&text);
        if expect_ok {
            assert!(result.is_ok(), "schema_version 1 rejected: {result:?}");
        } else {
            let err = result.err().unwrap_or_else(|| panic!("{raw} accepted"));
            assert!(
                matches!(err, PackageError::SchemaVersion { wanted: 1, .. }),
                "schema_version {raw} produced {err:?}"
            );
        }
    }
}

#[test]
fn derive_deny_unknown_fields_is_active_on_the_type() {
    // Independent of from_json_str: the serde derive itself must refuse extras,
    // so a caller that uses serde_json directly cannot get a looser parse.
    let value: serde_json::Value = serde_json::from_str(&json_for(64)).expect("fixture");
    let mut object = value.as_object().expect("object").clone();
    object.insert("unexpected".to_string(), serde_json::json!(1));
    let err = serde_json::from_value::<KernelManifestV1>(serde_json::Value::Object(object.clone()))
        .expect_err("deny_unknown_fields must refuse");
    let _ = err.to_string();

    // And the clean value still parses through the derive path.
    let ok = serde_json::from_value::<KernelManifestV1>(value).expect("derive parse");
    ok.validate().expect("valid");
}

#[test]
fn derive_does_not_invent_defaults_for_absent_fields() {
    // No `#[serde(default)]` anywhere: a document missing fields must not
    // become a manifest with zeroed values.
    let value: serde_json::Value =
        serde_json::json!({"schema_version": 1, "version": "155.0.8059.85"});
    let err = serde_json::from_value::<KernelManifestV1>(value)
        .expect_err("absent fields must not default");
    let _ = err.to_string();
}

#[test]
fn error_text_cannot_forge_log_structure_or_leak_huge_content() {
    // Manifest content is untrusted. A key containing a NUL and a newline must
    // not be able to write a *second* log line, and a megabyte key must not
    // become a megabyte message. Printable text from a key name is still
    // reported (it is the useful part of the diagnosis); what must be
    // impossible is structure injection and unbounded length.
    let hostile_key = "signatures\u{0}\n[INFO] install approved by publisher";
    let text = extra(64, hostile_key, r#""x""#);
    let err = must_reject(&text, "hostile key name");
    let message = err.to_string();
    assert!(
        !message.contains('\n') && !message.contains('\r') && !message.contains('\u{0}'),
        "error message carries injected structure: {message:?}"
    );
    assert!(
        message.contains("install approved by publisher"),
        "key name should still be readable for diagnosis: {message}"
    );

    let huge_key = "x".repeat(65_536);
    let text = extra(64, &huge_key, "1");
    let err = must_reject(&text, "oversized key name");
    assert!(
        err.to_string().len() < 400,
        "message length {} leaks the huge key",
        err.to_string().len()
    );
}

#[test]
fn no_panic_on_any_hostile_document() {
    // The parser runs inside an installer that must not crash on a hostile
    // download. Every case here must be a clean Ok or a clean Err — never a
    // panic, and never an unbounded allocation.
    let big_array = format!("[{}]", vec!["1"; 20_000].join(","));
    let corpus: Vec<String> = vec![
        String::new(),
        " ".to_string(),
        "{".to_string(),
        "}".to_string(),
        "[".to_string(),
        r#"{"#.to_string(),
        r#"{"schema_version":1}"#.to_string(),
        r#"{"schema_version":,}"#.to_string(),
        r#"{,}"#.to_string(),
        without(64, "sha256"),
        replaced(64, "sha256", r#""""#),
        replaced(64, "sha256", &format!("\"{}\"", "0".repeat(4096))),
        replaced(64, "size_bytes", "1e400"),
        replaced(64, "size_bytes", r#"-99999999999999999999"#),
        replaced(64, "profile_schema_versions", &big_array),
        replaced(64, "profile_schema_versions", "[4294967295,4294967296,-1]"),
        replaced(
            64,
            "pool_versions",
            &format!("[\"{}\"]", "p".repeat(200_000)),
        ),
        replaced(64, "version", &format!("\"{}\"", "1.1.1.1".repeat(4000))),
        replaced(64, "artifact_name", &format!("\"{}\"", "../".repeat(9000))),
        replaced(64, "platform", r#""\u0000""#),
        replaced(64, "required_capabilities", "[\"\",\" \",\"\\n\"]"),
        json_for(64) + &json_for(64),
        without(64, "schema_version"),
        "\u{1}".to_string(),
        r#"{"aaaaaaaa":"b"}"#.to_string(),
    ];
    for text in corpus {
        if let Ok(manifest) = KernelManifestV1::from_json_str(&text) {
            // Anything that parses must still be checked by validate(); the
            // corpus is hostile, so nothing here may quietly look installable.
            assert!(
                check_good(&manifest).is_err() || manifest == good_manifest(),
                "hostile corpus entry accepted as compatible: {text:?}"
            );
            let _ = manifest.validate();
        }
    }
}
