//! Canonical encoding and identity-digest tests.
//!
//! The expected bytes and digests below were produced by an independent Python
//! implementation of the documented canonical format (`tools`-style reference in
//! the review directory), not by this crate, so they pin the wire format rather
//! than mirror the Rust code.

use std::collections::BTreeMap;

use lengsuo_browser_profile::{
    HardwareSpec, LocaleSpec, Platform, ProfileSpecV1, ScreenSpec, CANONICAL_DOMAIN,
    CANONICAL_HEADER, DIMENSIONS, SCHEMA_VERSION,
};

mod support;
use support::{slots, GOOD_SEED};

/// Minimal hex helpers so the tests need no extra dev-dependencies.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    assert!(text.len() == 16, "test helper");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("test helper hex"))
        .collect()
}

/// Independent re-implementation of the documented canonical format.
fn reference_canonical(p: &ProfileSpecV1) -> Vec<u8> {
    fn u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn text(out: &mut Vec<u8>, s: &str) {
        u16(out, s.len() as u16);
        out.extend_from_slice(s.as_bytes());
    }
    let platform_code: u8 = match p.platform {
        Platform::Windows => 0,
        Platform::Linux => 1,
        Platform::Macos => 2,
        Platform::Android => 3,
        Platform::Ios => 4,
    };
    let seed = from_hex(&p.noise_seed_hex);
    let mut out = Vec::new();
    out.extend_from_slice(CANONICAL_HEADER);
    u32(&mut out, p.schema_version);
    u32(&mut out, p.noise_version);
    text(&mut out, &p.environment_id);
    text(&mut out, &p.pool_version);
    out.extend_from_slice(&seed);
    out.push(platform_code);
    u32(&mut out, p.screen.width);
    u32(&mut out, p.screen.height);
    out.push(p.screen.color_depth);
    u32(&mut out, p.screen.dpr_milli);
    u16(&mut out, p.hardware.cpu_cores);
    u32(&mut out, p.hardware.memory_mib);
    out.push(p.hardware.max_touch_points);
    text(&mut out, &p.locale.language);
    text(&mut out, &p.locale.timezone);
    u16(&mut out, p.slots.len() as u16);
    for (name, id) in &p.slots {
        text(&mut out, name);
        u32(&mut out, *id);
    }
    out
}

fn golden_profile() -> ProfileSpecV1 {
    ProfileSpecV1 {
        schema_version: SCHEMA_VERSION,
        environment_id: "env-1".to_string(),
        pool_version: "p1".to_string(),
        noise_version: 1,
        noise_seed_hex: to_hex(&[0u8, 1, 2, 3, 4, 5, 6, 7]),
        platform: Platform::Windows,
        screen: ScreenSpec {
            width: 1920,
            height: 1080,
            color_depth: 24,
            dpr_milli: 1000,
        },
        hardware: HardwareSpec {
            cpu_cores: 8,
            memory_mib: 8192,
            max_touch_points: 0,
        },
        locale: LocaleSpec {
            language: "en-US".to_string(),
            timezone: "UTC".to_string(),
        },
        slots: slots(),
    }
}

const GOLDEN_BYTES: [u8; 147] = [
    76, 66, 80, 70, 49, 0, 0, 0, 1, 0, 0, 0, 1, 0, 5, 101, 110, 118, 45, 49, 0, 2, 112, 49, 0, 1,
    2, 3, 4, 5, 6, 7, 0, 0, 0, 7, 128, 0, 0, 4, 56, 24, 0, 0, 3, 232, 0, 8, 0, 0, 32, 0, 0, 0, 5,
    101, 110, 45, 85, 83, 0, 3, 85, 84, 67, 0, 7, 0, 5, 97, 117, 100, 105, 111, 0, 0, 0, 3, 0, 6,
    99, 97, 110, 118, 97, 115, 0, 0, 0, 1, 0, 12, 99, 108, 105, 101, 110, 116, 95, 114, 101, 99,
    116, 115, 0, 0, 0, 5, 0, 5, 102, 111, 110, 116, 115, 0, 0, 0, 4, 0, 3, 103, 112, 117, 0, 0, 0,
    6, 0, 2, 117, 97, 0, 0, 0, 7, 0, 5, 119, 101, 98, 103, 108, 0, 0, 0, 2,
];

/// SHA-256(domain || canonical_bytes) of GOLDEN_BYTES, from the reference tool.
const GOLDEN_DIGEST: &str = "4f697737e51b7179bb1bf9874322494c366e6ea55013ef4f293407c76412d80b";

#[test]
fn canonical_bytes_match_the_reference_encoding() {
    let p = golden_profile();
    p.validate().unwrap();
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(bytes, GOLDEN_BYTES.to_vec());
    assert_eq!(bytes, reference_canonical(&p));
    assert_eq!(bytes.len(), 147);
    assert_eq!(&bytes[..CANONICAL_HEADER.len()], CANONICAL_HEADER);
}

#[test]
fn digest_matches_the_reference_vector() {
    let p = golden_profile();
    let digest = p.identity_digest().unwrap();
    assert_eq!(digest, GOLDEN_DIGEST);
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "digest must be lowercase hex: {digest}"
    );
    assert_eq!(CANONICAL_DOMAIN.len(), 36);
}

#[test]
fn serialization_and_digest_are_deterministic() {
    let p = golden_profile();
    let first = p.canonical_bytes().unwrap();
    for _ in 0..25 {
        assert_eq!(p.canonical_bytes().unwrap(), first);
        assert_eq!(p.identity_digest().unwrap(), GOLDEN_DIGEST);
    }
    // A rebuilt-but-equal profile gives the same bytes.
    let text = serde_json::to_string(&p).unwrap();
    let rebuilt = ProfileSpecV1::from_json_str(&text).unwrap();
    assert_eq!(rebuilt, p);
    assert_eq!(rebuilt.canonical_bytes().unwrap(), first);
    assert_eq!(rebuilt.identity_digest().unwrap(), GOLDEN_DIGEST);
    // JSON key order for the slot map must not change canonical bytes.
    let reordered = serde_json::to_string(&{
        let mut m = BTreeMap::new();
        for dim in DIMENSIONS.iter().rev() {
            m.insert(dim.to_string(), p.slots[*dim]);
        }
        let mut q = p.clone();
        q.slots = m;
        q
    })
    .unwrap();
    assert_eq!(
        ProfileSpecV1::from_json_str(&reordered).unwrap(),
        p,
        "BTreeMap must normalize slot order"
    );
    assert_eq!(
        ProfileSpecV1::from_json_str(&reordered)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        first
    );
}

#[test]
fn every_field_changes_the_digest() {
    let base = golden_profile();
    let base_digest = base.identity_digest().unwrap();

    let mut a = base.clone();
    a.environment_id = "env-2".to_string();
    let mut b = base.clone();
    b.pool_version = "p2".to_string();
    let mut c = base.clone();
    // all-ones seed, built at runtime to keep the source free of hex blobs
    c.noise_seed_hex = "0".repeat(16).replacen('0', "f", 16);
    let mut d = base.clone();
    d.platform = Platform::Ios;
    d.hardware.max_touch_points = 5;
    let mut e = base.clone();
    e.screen.width = 1921;
    let mut f = base.clone();
    f.screen.dpr_milli = 1500;
    let mut g = base.clone();
    g.hardware.cpu_cores = 9;
    let mut h = base.clone();
    h.hardware.memory_mib = 8193;
    let mut i = base.clone();
    i.locale.language = "de-DE".to_string();
    let mut j = base.clone();
    j.locale.timezone = "Europe/Berlin".to_string();
    let mut k = base.clone();
    k.slots.insert("ua".to_string(), 8);
    let mut l = base.clone();
    l.screen.color_depth = 30;
    let mut m = base.clone();
    m.screen.color_depth = 8;

    for variant in [a, b, c, d, e, f, g, h, i, j, k, l, m] {
        variant
            .validate()
            .unwrap_or_else(|err| panic!("{variant:?}: {err}"));
        assert_ne!(
            variant.identity_digest().unwrap(),
            base_digest,
            "digest ignored a change in {variant:?}"
        );
    }
}

#[test]
fn environment_id_is_part_of_the_identity() {
    // Two profiles identical except for environment_id must NOT collide: the
    // digest deliberately includes it so distinct environments cannot be
    // confused for one another in storage, logs or pool bookkeeping.
    let one = golden_profile();
    let mut other = one.clone();
    other.environment_id = "env-2".to_string();
    assert_ne!(
        one.identity_digest().unwrap(),
        other.identity_digest().unwrap()
    );

    // Known reference pair from the independent tool.
    assert_eq!(
        other.identity_digest().unwrap(),
        "dfb661578a3f134b70d0d964e67e5e3af1f3288c64df1cabcf54b73809e389c1"
    );

    // Clone semantics are explicit: the caller supplies the new id, and the
    // contract never rewrites it silently. Everything before the id field is
    // byte-identical, so the divergence is attributable to the id alone.
    let mut cloned = one.clone();
    cloned.environment_id = "env-3".to_string();
    assert_ne!(
        cloned.identity_digest().unwrap(),
        one.identity_digest().unwrap()
    );
    let base_bytes = one.canonical_bytes().unwrap();
    let clone_bytes = cloned.canonical_bytes().unwrap();
    let id_offset = CANONICAL_HEADER.len() + 8; // header + schema + noise
    assert_eq!(&base_bytes[..id_offset], &clone_bytes[..id_offset]);
    assert_eq!(base_bytes.len(), clone_bytes.len());
    assert_ne!(base_bytes, clone_bytes);
}

#[test]
fn slot_membership_change_is_detected() {
    // Same id count, one tier moved: must change both bytes and digest.
    let mut moved = golden_profile();
    moved.slots.insert("ua".to_string(), 8);
    let base = golden_profile();
    assert_ne!(
        moved.canonical_bytes().unwrap(),
        base.canonical_bytes().unwrap()
    );
    assert_eq!(
        moved.identity_digest().unwrap(),
        "47d9fbf448c110bef366a21c77a5cf8e21ccd5343310ffabfa19684ba5db27e7"
    );
}

#[test]
fn mobile_profile_encoding_is_stable() {
    let p = support::mobile_spec();
    p.validate().unwrap();
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(bytes, reference_canonical(&p));
    // Android platform code sits right after the 8 seed bytes.
    let offset =
        CANONICAL_HEADER.len() + 4 + 4 + 2 + p.environment_id.len() + 2 + p.pool_version.len() + 8;
    assert_eq!(bytes[offset], 3);
    assert_eq!(bytes[offset + 1 + 13 + 2 + 4], 5); // max_touch_points
    let digest = p.identity_digest().unwrap();
    assert_eq!(digest.len(), 64);
    assert_eq!(p.identity_digest().unwrap(), digest);
}

#[test]
fn invalid_profile_produces_no_canonical_bytes() {
    let mut p = golden_profile();
    p.schema_version = 7;
    assert!(p.canonical_bytes().is_err());
    assert!(p.identity_digest().is_err());

    let mut p = golden_profile();
    p.noise_seed_hex = GOOD_SEED.to_uppercase();
    assert!(p.canonical_bytes().is_err());

    let mut p = golden_profile();
    p.slots.remove("gpu");
    assert!(p.identity_digest().is_err());
}

#[test]
fn overlong_strings_cannot_forge_the_frame() {
    // Length prefixes are u16; a 700-char field must be refused rather than
    // truncated (which would let two different profiles share a digest).
    let mut p = golden_profile();
    p.environment_id = "e".repeat(700);
    assert!(p.canonical_bytes().is_err());
    assert!(p.identity_digest().is_err());

    let mut p = golden_profile();
    p.locale.timezone = "U".repeat(300);
    assert!(p.canonical_bytes().is_err());
}

#[test]
fn non_ascii_or_non_utf8_strings_are_refused() {
    // The canonical format is ASCII-only for strings; a non-ASCII value must
    // fail rather than be encoded (which would change byte length vs. count).
    let mut p = golden_profile();
    p.environment_id = "env-é".to_string();
    assert!(p.canonical_bytes().is_err());

    let mut p = golden_profile();
    p.slots.insert("fonts".to_string(), 1);
    p.slots.insert("font-s".to_string(), 1);
    assert!(p.canonical_bytes().is_err());
}
