//! Shared builders for the profile contract tests.
//!
//! Everything here is a *test fixture*: JSON is written by hand as text so the
//! tests exercise the public deserialization surface (unknown fields, wrong
//! types, hostile strings) instead of reusing the crate's own constructors.

use std::collections::{BTreeMap, BTreeSet};

use lengsuo_browser_profile::{DimensionPools, Platform, PoolCatalogV1, ProfileSpec};

/// A schema-1 profile that satisfies the contract, serialized as JSON text
/// with every field present and correctly typed.
pub const VALID_JSON: &str = r#"{
  "schema_version": 1,
  "environment_id": "env-alpha_1",
  "pool_version": "pool-2026-10",
  "noise_version": 1,
  "noise_seed_hex": "00ff1a2b3c4d5e6f",
  "platform": "windows",
  "screen": { "width": 1920, "height": 1080, "color_depth": 24, "dpr_milli": 1000 },
  "hardware": { "cpu_cores": 8, "memory_mib": 8192, "max_touch_points": 0 },
  "locale": { "language": "en-US", "timezone": "America/New_York" },
  "slots": {
    "canvas": 3,
    "webgl": 7,
    "audio": 2,
    "fonts": 11,
    "client_rects": 5,
    "gpu": 9,
    "ua": 1
  }
}"#;

/// The pool catalog that `VALID_JSON` is meant to be validated against.
pub fn valid_catalog() -> PoolCatalogV1 {
    PoolCatalogV1::new("pool-2026-10", full_pools()).expect("catalog fixture must be valid")
}

/// Every supported dimension with a pool wide enough to contain the fixture
/// slot ids used by `VALID_JSON` plus neighbours.
pub fn full_pools() -> DimensionPools {
    let mut pools: DimensionPools = BTreeMap::new();
    for (dimension, base) in [
        ("canvas", 0u32),
        ("webgl", 0),
        ("audio", 0),
        ("fonts", 0),
        ("client_rects", 0),
        ("gpu", 0),
        ("ua", 0),
    ] {
        let mut ids = BTreeSet::new();
        for id in (base + 1)..(base + 16) {
            ids.insert(id);
        }
        pools.insert(dimension.to_string(), ids);
    }
    pools
}

/// `VALID_JSON` with one top-level text field replaced verbatim.
pub fn json_with_field(field: &str, value_json: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    let bytes = VALID_JSON.as_bytes();
    let mut i = 0usize;
    let needle = format!("\"{field}\":");
    while i < bytes.len() {
        let rest = &VALID_JSON[i..];
        match bytes[i] as char {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
        if depth == 1 && rest.starts_with(&needle) {
            out.push_str(&needle);
            out.push_str(value_json);
            i += needle.len();
            // Skip the original value up to the next comma or closing brace.
            let mut nested = 0usize;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c == '{' || c == '[' {
                    nested += 1;
                } else if c == '}' || c == ']' {
                    if nested == 0 {
                        break;
                    }
                    nested -= 1;
                } else if c == ',' && nested == 0 {
                    break;
                } else if c == '"' {
                    i += 1;
                    while i < bytes.len() && bytes[i] as char != '"' {
                        if bytes[i] as char == '\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                i += 1;
            }
            continue;
        }
        let c = bytes[i] as char;
        out.push(c);
        i += 1;
    }
    out
}

/// Parse `VALID_JSON` into a validated profile. Panics with the parse error so
/// a fixture problem is never mistaken for a product bug.
pub fn valid_profile() -> ProfileSpec {
    let spec = ProfileSpec::from_json_str(VALID_JSON)
        .unwrap_or_else(|e| panic!("fixture JSON must be valid: {e}"));
    spec.validate()
        .unwrap_or_else(|e| panic!("fixture profile must validate: {e}"));
    spec
}

/// Mobile variant of the fixture, still contract-valid.
pub fn valid_mobile_json() -> String {
    let json = VALID_JSON
        .replace("\"platform\": \"windows\"", "\"platform\": \"android\"")
        .replace("\"max_touch_points\": 0", "\"max_touch_points\": 5");
    assert!(json.contains("android") && json.contains("\"max_touch_points\": 5"));
    json
}

/// Convenience: platform label used in fixture JSON.
pub fn platform_label(platform: Platform) -> &'static str {
    platform.canonical_label()
}
