//! Field grammar enforced by `validate()`: version shape, hex-shaped fields,
//! hostile artifact names, and the bounds on the three collections.

mod fixture;

use fixture::*;
use lengsuo_browser_package::KernelManifestV1;
use lengsuo_browser_package::PackageError;

/// Parse a fixture with one field replaced by raw JSON text.
fn with(field: &str, raw: &str) -> KernelManifestV1 {
    KernelManifestV1::from_json_str(&replaced(64, field, raw))
        .unwrap_or_else(|e| panic!("{field}={raw} must parse as a document: {e}"))
}

/// Parse a fixture with one string field replaced by a Rust string, escaped
/// into a JSON literal so control bytes and non-ASCII survive.
fn with_str(field: &str, value: &str) -> Result<KernelManifestV1, PackageError> {
    KernelManifestV1::from_json_str(&replaced(64, field, &json_str(value)))
}

/// Assert a manifest fails `validate()`, and return the error.
fn rejected(m: &KernelManifestV1, ctx: &str) -> PackageError {
    match m.validate() {
        Ok(()) => panic!("expected validate() rejection for {ctx}"),
        Err(err) => err,
    }
}

fn is_field_error(err: &PackageError, field: &str) -> bool {
    match err {
        PackageError::InvalidField { field: f, .. } => *f == field,
        _ => false,
    }
}

#[test]
fn canonical_manifest_validates() {
    good_manifest().validate().expect("canonical manifest");
}

// ---------------------------------------------------------------- version ---

#[test]
fn version_accepts_the_documented_four_component_shape() {
    for raw in [
        "155.0.8059.85",
        "0.0.0.0",
        "1.2.3.4",
        "155.0.8059.123456789",
        "4294967295.0.0.0",
    ] {
        with_str("version", raw)
            .expect("parses as a string")
            .validate()
            .unwrap_or_else(|e| panic!("version {raw:?} must validate: {e}"));
    }
}

#[test]
fn version_rejects_every_nonconforming_spelling() {
    let hostile: &[&str] = &[
        "",
        "155.0.8059",
        "155.0.8059.85.1",
        "155.0.8059.",
        ".155.0.8059.85",
        "155..0.8059",
        "155.0..8059.85",
        "155.0.8059.085", // leading zero: two spellings, one release
        "155.0.8059.0085",
        "155.0.8059.85 ",
        " 155.0.8059.85",
        "155.0.8059.85\u{0}",
        "155.0.8059.85\n",
        "155.0.8059.85-dev",
        "v155.0.8059.85",
        "155,0,8059,85",
        "155.0.8059.85444444444444444444444444444444444444444444444444444444",
        "4294967296.0.0.0", // component exceeds u32
        "155.-1.8059.85",
        "155.0.8059.+85",
        "155.0.8059.85.",
        "155.0.8059.8\u{a0}5",
        "１５５.0.8059.85", // fullwidth digits are not ASCII digits
        "0x1.0.0.0",
        "1e2.0.0.0",
    ];
    for raw in hostile {
        let err = rejected(
            &with_str("version", raw).expect("parses"),
            &format!("{raw:?}"),
        );
        assert!(is_field_error(&err, "version"), "version {raw:?}: {err:?}");
    }
}

#[test]
fn version_rejects_wrong_json_types() {
    for raw in ["155", "1.0", "true", "null", "[1]", "{}"] {
        let err = KernelManifestV1::from_json_str(&replaced(64, "version", raw))
            .expect_err(&format!("version {raw} must be rejected"));
        assert!(
            matches!(
                err,
                PackageError::FieldType { .. } | PackageError::JsonSyntax { .. }
            ),
            "{err:?}"
        );
    }
}

// ------------------------------------------------------- hex-shaped fields ---

#[test]
fn hex_fields_require_exact_length_and_lowercase() {
    let ok40 = CHROMIUM_REVISION.to_string();
    let ok64 = known_sha256(64);
    assert_eq!(ok40.len(), 40);
    assert_eq!(ok64.len(), 64);

    for (field, good) in [
        ("chromium_revision", &ok40),
        ("patchset_sha256", &PATCHSET_SHA256.to_string()),
        ("sha256", &ok64),
    ] {
        let len = good.len();
        with_str(field, good)
            .expect("parses")
            .validate()
            .unwrap_or_else(|e| panic!("{field} baseline must validate: {e}"));

        let bad: Vec<String> = vec![
            good[..len - 1].to_string(),
            format!("{good}0"),
            good.to_uppercase(),
            format!("{}f", good[..len - 1].to_uppercase()),
            format!("{} ", &good[..len - 1]),
            format!(" {good}"),
            format!("{}g", &good[..len - 1]),
            format!("{}-", &good[..len - 1]),
            format!("{}\u{0}", &good[..len - 1]),
            format!("{}\n", &good[..len - 1]),
            String::new(),
            "z".repeat(len),
            format!("{}é", &good[..len - 2]), // multi-byte, right byte length
        ];
        for raw in bad {
            let err = rejected(
                &with_str(field, &raw).expect("parses as a string"),
                &format!("{field}={raw:?}"),
            );
            assert!(is_field_error(&err, field), "{field}={raw:?}: {err:?}");
        }
    }
}

#[test]
fn hex_fields_reject_wrong_json_types() {
    for field in ["chromium_revision", "patchset_sha256", "sha256"] {
        for raw in ["0", "null", "true", "[\"x\"]", "{}"] {
            let err = KernelManifestV1::from_json_str(&replaced(64, field, raw))
                .expect_err(&format!("{field}={raw}"));
            assert!(
                matches!(
                    err,
                    PackageError::FieldType { .. } | PackageError::JsonSyntax { .. }
                ),
                "{field}={raw}: {err:?}"
            );
        }
    }
}

#[test]
fn equal_digest_fields_are_valid_but_do_not_prove_artifact_bytes() {
    // Different objects are allowed to contain identical bytes. Schema validity
    // cannot infer their digest must differ; verify_reader checks actual bytes.
    let m = with("sha256", &json_str(PATCHSET_SHA256));
    m.validate().unwrap();
    assert!(matches!(
        m.verify_reader(&lcg_payload(64)[..]),
        Err(lengsuo_browser_package::VerifyError::DigestMismatch { .. })
    ));
}

// --------------------------------------------------------- artifact names ---

#[test]
fn artifact_name_accepts_safe_basenames() {
    for raw in [
        "chrome-linux-x86_64-155.0.8059.85.tar.zst",
        "chrome-win-x86_64.zip",
        "chrome.app",
        "a",
        "A1",
        "fingerprint_kernel+2026.10.pkg",
        "chrome_64bit.tar",
        "l0.zip",
        "0.zip",
        "com1x.zip",
        "console.zip",
        "null.zip",
        "auxdata.zip",
        "lpt10.zip",
        "clockx",
        "a".repeat(255).as_str(),
    ] {
        with_str("artifact_name", raw)
            .expect("parses")
            .validate()
            .unwrap_or_else(|e| panic!("name {raw:?} must validate: {e}"));
    }
}

#[test]
fn artifact_name_rejects_traversal_separators_and_absolute_forms() {
    let hostile: &[&str] = &[
        "",
        ".",
        "..",
        "...",
        "../evil",
        "../../etc/passwd",
        "chrome/../../evil",
        "a/../b",
        "/etc/passwd",
        "/chrome.zip",
        "//server/share/chrome.zip",
        "C:\\windows\\chrome.dll",
        "\\\\nas\\share\\chrome.zip",
        "sub/dir.zip",
        "chrome\\x64.zip",
        "dir/",
        "C:chrome.zip",
        "file:///etc/passwd",
        "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "./chrome.zip",
        "../",
        "..%2f..%2f",
        "chrome.zip/../evil",
        "chrome%00.zip",
        "chrome:zone.identifier", // NTFS alternate data stream
        "chrome.zip\u{0}.exe",
    ];
    for raw in hostile {
        let err = rejected(
            &with_str("artifact_name", raw).expect("parses"),
            &format!("{raw:?}"),
        );
        assert!(
            is_field_error(&err, "artifact_name"),
            "name {raw:?}: {err:?}"
        );
    }
}

#[test]
fn artifact_name_rejects_control_characters_non_ascii_and_spaces() {
    let hostile: &[&str] = &[
        "chrome\r\nHost: evil\r\n\r\n",
        "chrome\u{0}.dll",
        "chrome\u{7}.dll",
        "chrome\u{1b}[31m.dll",
        "chrome dll",
        "chrome\u{a0}dll",
        "chrome\u{202e}dll",
        "chröme.zip",
        "内核.zip",
        "chrome\u{feff}.zip",
        "-x",
        "--",
        ".hidden",
        "chrome.",
        "chrome-",
        "chrome ",
        " chrome",
        "x..y",
    ];
    for raw in hostile {
        let err = rejected(
            &with_str("artifact_name", raw).expect("parses"),
            &format!("{raw:?}"),
        );
        assert!(
            is_field_error(&err, "artifact_name"),
            "name {raw:?}: {err:?}"
        );
    }
}

#[test]
fn artifact_name_rejects_win32_reserved_device_names() {
    // Basenames that are "safe" by character class yet still hijack a write on
    // Windows, including the case- and trailing-dot-folded spellings.
    for raw in [
        "nul", "NUL", "con", "CON", "prn", "aux", "AUX", "com1", "COM9", "lpt1", "LPT3", "COM1.",
        "nul.", "NUL.txt", "clock$",
    ] {
        let err = rejected(
            &with_str("artifact_name", raw).expect("parses"),
            &format!("reserved {raw:?}"),
        );
        assert!(
            is_field_error(&err, "artifact_name"),
            "reserved name {raw:?}: {err:?}"
        );
    }
}

#[test]
fn artifact_name_is_length_bounded() {
    // 255 characters is the bound; anything longer is refused so a hostile
    // manifest cannot dictate a path component the OS will truncate.
    with_str("artifact_name", &"a".repeat(254))
        .expect("parses")
        .validate()
        .expect("254 chars must validate");

    for len in [256, 257, 1000, 100_000] {
        let err = rejected(
            &with_str("artifact_name", &"a".repeat(len)).expect("parses"),
            &format!("{len} chars"),
        );
        assert!(is_field_error(&err, "artifact_name"), "{len}: {err:?}");
    }
}

// ------------------------------------------------------------- size_bytes ---

#[test]
fn size_bytes_must_be_positive() {
    let err = rejected(&with("size_bytes", "0"), "size 0");
    assert!(is_field_error(&err, "size_bytes"), "{err:?}");
    with("size_bytes", "1")
        .validate()
        .expect("size 1 validates (digest mismatch is verify_reader's job)");
}

#[test]
fn size_bytes_is_upper_bounded() {
    // The bound is a documented constant; probe around it.
    let limit = KernelManifestV1::MAX_ACCEPTED_SIZE_BYTES;
    with("size_bytes", &limit.to_string())
        .validate()
        .unwrap_or_else(|e| panic!("{limit} must validate: {e}"));
    for raw in [
        (limit + 1).to_string(),
        (limit * 2).to_string(),
        "17179869185".to_string(),
        u64::MAX.to_string(),
    ] {
        let err = rejected(&with("size_bytes", &raw), &raw);
        assert!(is_field_error(&err, "size_bytes"), "{raw}: {err:?}");
    }
}

#[test]
fn size_bytes_rejects_every_non_integer_json_form() {
    for raw in [
        r#""64""#,
        "64.0",
        "64.5",
        "-1",
        "-99999999999999999999",
        "true",
        "false",
        "null",
        "[]",
        "{}",
        "1e400",
        "18446744073709551616", // one past u64
        "0x40",
        r#""0""#,
    ] {
        let err = KernelManifestV1::from_json_str(&replaced(64, "size_bytes", raw))
            .expect_err(&format!("size_bytes {raw} must be rejected"));
        assert!(
            matches!(
                err,
                PackageError::FieldType { .. } | PackageError::JsonSyntax { .. }
            ),
            "size_bytes {raw}: {err:?}"
        );
    }
}
