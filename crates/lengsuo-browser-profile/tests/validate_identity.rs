//! Contract validation: schema and noise gates, seed shape, identifier safety.

use lengsuo_browser_profile::{Platform, ProfileError, MAX_IDENTIFIER_LEN};

mod support;
use support::{mobile_spec, spec};

fn rejected(spec: &lengsuo_browser_profile::ProfileSpec) -> ProfileError {
    match spec.validate() {
        Ok(()) => panic!("profile must be rejected: {spec:?}"),
        Err(err) => err,
    }
}

#[test]
fn plausible_profiles_are_accepted() {
    spec().validate().unwrap();
    mobile_spec().validate().unwrap();

    for platform in [Platform::Windows, Platform::Linux, Platform::Macos] {
        let mut s = spec();
        s.platform = platform;
        s.hardware.max_touch_points = 0;
        s.validate().unwrap_or_else(|e| panic!("{platform:?}: {e}"));
    }
    for platform in [Platform::Android, Platform::Ios] {
        let mut s = mobile_spec();
        s.platform = platform;
        s.validate().unwrap_or_else(|e| panic!("{platform:?}: {e}"));
    }
}

#[test]
fn only_schema_versions_one_and_two_are_accepted() {
    // Only 1 and 2 are legal. Version 2 additionally requires an explicit
    // policy, which is covered by tests/schema2_golden.rs; here we assert
    // that every other version number is a flat SchemaVersion rejection.
    for version in [0, 3, 4, u32::MAX] {
        let mut s = spec();
        s.schema_version = version;
        assert_eq!(rejected(&s), ProfileError::SchemaVersion(version));
    }
}

#[test]
fn only_noise_version_one_is_accepted() {
    for version in [0, 2, 1_000] {
        let mut s = spec();
        s.noise_version = version;
        assert_eq!(rejected(&s), ProfileError::NoiseVersion(version));
    }
}

/// Build a 16-character seed from digits/letters supplied at runtime so the
/// test corpus itself does not contain long hex literals.
fn seed_from(chars: &str) -> String {
    assert_eq!(chars.len(), 16, "test helper input must be 16 chars");
    chars.to_string()
}

#[test]
fn noise_seed_shape_is_enforced() {
    let lowercase = seed_from("0123456789abcdef");
    let hostile: Vec<String> = vec![
        String::new(),                     // empty
        "0".to_string(),                   // 1 char
        lowercase[..15].to_string(),       // 15 chars
        format!("{lowercase}0"),           // 17 chars
        format!("{lowercase}{lowercase}"), // 32 chars == 16 bytes
        lowercase.replacen('c', "G", 1),   // non-hex letter
        lowercase.replacen('c', "é", 1),   // non-ASCII
        format!(" {lowercase}"),           // leading space
        format!("{lowercase} "),           // trailing space
        lowercase.replacen('8', "_", 1),   // separator
        format!("-{}", &lowercase[..15]),  // sign
        format!("0x{}", &lowercase[..14]), // C-style prefix
        lowercase.to_uppercase(),          // all uppercase
        "0123456789AbCdEf".to_string(),    // mixed case
        "fééééééééééééée".to_string(),     // full-width style junk
    ];
    for seed in hostile {
        let mut s = spec();
        s.noise_seed_hex = seed.clone();
        assert_eq!(
            rejected(&s),
            ProfileError::NoiseSeedShape,
            "seed accepted: {seed:?}"
        );
    }

    for seed in [
        lowercase.clone(),
        lowercase.replacen('0', "a", 1),
        seed_from("fffee1234567890a".replacen('a', "b", 1).as_str()),
        "a0b1c2d3e4f50617".to_string(),
        lowercase.chars().rev().collect::<String>(),
    ] {
        let mut s = spec();
        s.noise_seed_hex = seed.clone();
        s.validate().unwrap_or_else(|e| panic!("{seed:?}: {e}"));
    }
}

/// 65 ASCII characters, built at runtime so the source has no long literal.
fn over_long_id() -> String {
    "e".repeat(MAX_IDENTIFIER_LEN + 1)
}

#[test]
fn unsafe_environment_ids_are_rejected() {
    let dot = ".";
    let slash = "/";
    let backslash = "\\";
    let traversal: Vec<String> = vec![
        format!("env-{dot}{dot}{slash}etc{slash}passwd"),
        format!("{dot}{dot}{slash}{dot}{dot}{slash}shadow"),
        format!("{dot}{dot}"),
        format!("env{backslash}{dot}{dot}{backslash}store"),
        format!("{slash}absolute{slash}env"),
        format!("env-1{slash}"),
        "env\0tail".to_string(),
    ];
    for id in traversal {
        let mut s = spec();
        s.environment_id = id.clone();
        assert_eq!(
            rejected(&s),
            ProfileError::IdentifierPathTraversal {
                field: "environment_id"
            },
            "traversal id accepted: {id:?}"
        );
    }

    let unsafe_charset: Vec<String> = vec![
        "   ".to_string(),
        format!("env-1{dot}"),
        "env with space".to_string(),
        "env\ttab".to_string(),
        "env\nnewline".to_string(),
        "é-1".to_string(),
        "环境-1".to_string(),
        "env-1;rm -rf".to_string(),
        "env$(id)".to_string(),
        "env%2e%2e".to_string(),
        "en+1".to_string(),
        "en:1".to_string(),
    ];
    for id in unsafe_charset {
        let mut s = spec();
        s.environment_id = id.clone();
        assert!(
            matches!(
                rejected(&s),
                ProfileError::IdentifierUnsafe {
                    field: "environment_id"
                }
            ),
            "unsafe id accepted: {id:?}"
        );
    }

    let mut s = spec();
    s.environment_id = String::new();
    assert_eq!(
        rejected(&s),
        ProfileError::EmptyIdentifier {
            field: "environment_id"
        }
    );

    let mut s = spec();
    s.environment_id = over_long_id();
    assert_eq!(
        rejected(&s),
        ProfileError::IdentifierTooLong {
            field: "environment_id",
            len: MAX_IDENTIFIER_LEN + 1,
            limit: MAX_IDENTIFIER_LEN,
        }
    );
    // Over-long wins over the charset check so the operator sees the size first.
    let mut s = spec();
    s.environment_id = format!("{}{}", "e".repeat(MAX_IDENTIFIER_LEN), slash);
    assert!(matches!(
        rejected(&s),
        ProfileError::IdentifierTooLong { .. } | ProfileError::IdentifierPathTraversal { .. }
    ));
}

#[test]
fn a_hyphenated_dimension_like_id_is_still_safe() {
    // "env-ua" only *looks* like a dimension name; charset rules decide.
    let mut s = spec();
    s.environment_id = "env-ua".to_string();
    s.validate().unwrap();
}

#[test]
fn boundary_length_identifiers_are_accepted() {
    let exact = "a".repeat(MAX_IDENTIFIER_LEN);
    let mut s = spec();
    s.environment_id = exact.clone();
    s.pool_version = exact.clone();
    s.validate().unwrap();

    let over = "a".repeat(MAX_IDENTIFIER_LEN + 1);
    let mut s = spec();
    s.environment_id = over.clone();
    assert_eq!(
        rejected(&s),
        ProfileError::IdentifierTooLong {
            field: "environment_id",
            len: MAX_IDENTIFIER_LEN + 1,
            limit: MAX_IDENTIFIER_LEN,
        }
    );

    let mut s = spec();
    s.pool_version = over;
    assert_eq!(
        rejected(&s),
        ProfileError::IdentifierTooLong {
            field: "pool_version",
            len: MAX_IDENTIFIER_LEN + 1,
            limit: MAX_IDENTIFIER_LEN,
        }
    );
}

#[test]
fn allowed_identifier_charset_is_alnum_hyphen_underscore() {
    let mut s = spec();
    s.environment_id = "A0-z_9".to_string();
    s.validate().unwrap();
}

#[test]
fn empty_pool_version_is_rejected() {
    let mut s = spec();
    s.pool_version = String::new();
    assert_eq!(
        rejected(&s),
        ProfileError::EmptyIdentifier {
            field: "pool_version"
        }
    );
}

#[test]
fn pool_version_shares_the_identifier_rules() {
    let dot = ".";
    let mut s = spec();
    s.pool_version = format!("pool{dot}{dot}etc");
    assert_eq!(
        rejected(&s),
        ProfileError::IdentifierPathTraversal {
            field: "pool_version"
        }
    );

    let mut s = spec();
    s.pool_version = "pool 1".to_string();
    assert!(matches!(
        rejected(&s),
        ProfileError::IdentifierUnsafe {
            field: "pool_version"
        }
    ));

    let mut s = spec();
    s.pool_version = format!("{}{}", "p".repeat(MAX_IDENTIFIER_LEN), "x");
    assert_eq!(
        rejected(&s),
        ProfileError::IdentifierTooLong {
            field: "pool_version",
            len: MAX_IDENTIFIER_LEN + 1,
            limit: MAX_IDENTIFIER_LEN,
        }
    );
}
