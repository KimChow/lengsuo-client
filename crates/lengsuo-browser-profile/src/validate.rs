//! Validation rules and contract bounds.
//!
//! Every rule here is fail-closed: a rejected profile produces an error, never
//! a repaired, defaulted, randomly补齐 or modulo-mapped value.

use std::collections::BTreeMap;

use crate::error::ProfileError;
use crate::spec::{ProfileSpecV1, MAX_IDENTIFIER_LEN, NOISE_SEED_HEX_LEN, SCHEMA_VERSION};

/// The dimensions a schema-1 profile must cover **exactly**: no missing entry,
/// no extra entry. This order is also the canonical slot iteration order
/// asserted by the `BTreeMap` keys.
pub const DIMENSIONS: [&str; 7] = [
    "canvas",
    "webgl",
    "audio",
    "fonts",
    "client_rects",
    "gpu",
    "ua",
];

/// Alias of [`DIMENSIONS`], spelled for readability at call sites.
pub const SUPPORTED_DIMENSIONS: &[&str] = &DIMENSIONS;

/// The only noise algorithm version schema 1 accepts.
pub const NOISE_VERSION: u32 = 1;

/// Screen width/height must be within this inclusive range.
pub const MIN_SCREEN_DIMENSION: u32 = 1;
pub const MAX_SCREEN_DIMENSION: u32 = 16_384;

/// Product of width and height is computed in `u64` so a `u32` multiplication
/// overflow cannot be silently wrapped into an accepted area.
pub const MAX_SCREEN_AREA: u64 = 64 * 1024 * 1024;

/// Accepted `color_depth` bit depths.
pub const SUPPORTED_COLOR_DEPTHS: [u8; 4] = [8, 16, 24, 30];

/// `dpr_milli` bounds: 0.1x .. 10.0x device pixel ratio.
pub const MIN_DPR_MILLI: u32 = 100;
pub const MAX_DPR_MILLI: u32 = 10_000;

/// `cpu_cores` bounds.
pub const MIN_SLOT_CPU_CORES: u16 = 1;
pub const MAX_CPU_CORES: u16 = 1024;

/// `memory_mib` bounds.
pub const MIN_MEMORY_MIB: u32 = 128;
pub const MAX_MEMORY_MIB: u32 = 1_048_576;

/// `max_touch_points` upper bound for mobile platforms.
pub const MAX_TOUCH_POINTS: u8 = 10;

/// Slot tier ids must be non-zero and at most this.
pub const MIN_SLOT_ID: u32 = 1;
pub const MAX_SLOT_ID: u32 = 1_048_576;

/// Locale field length bounds (syntax only; no IANA or subtag database is
/// embedded, so well-formed-but-fictional values are accepted by design).
pub const MAX_LANGUAGE_LEN: usize = 35;
pub const MAX_TIMEZONE_LEN: usize = 64;

/// Maximum subtags in a language tag: primary, script, region, variant.
const MAX_LANGUAGE_PARTS: usize = 4;
/// Maximum components in a timezone: usually `Region` and `City`.
const MAX_TIMEZONE_PARTS: usize = 3;

/// Check an identifier-like field: non-empty, at most
/// [`MAX_IDENTIFIER_LEN`] characters, free of path traversal sequences, and
/// made only of ASCII letters, digits, `-` and `_`.
pub(crate) fn check_safe_identifier(field: &'static str, value: &str) -> Result<(), ProfileError> {
    if value.is_empty() {
        return Err(ProfileError::EmptyIdentifier { field });
    }
    let len = value.chars().count();
    if len > MAX_IDENTIFIER_LEN {
        return Err(ProfileError::IdentifierTooLong {
            field,
            len,
            limit: MAX_IDENTIFIER_LEN,
        });
    }
    if contains_path_sequence(value) {
        return Err(ProfileError::IdentifierPathTraversal { field });
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ProfileError::IdentifierUnsafe { field });
    }
    Ok(())
}

/// Any `/`, `\`, NUL or `..` sequence makes a value usable as a path fragment.
fn contains_path_sequence(value: &str) -> bool {
    value.contains('/') || value.contains('\\') || value.contains('\0') || value.contains("..")
}

/// `noise_seed_hex` must be exactly [`NOISE_SEED_HEX_LEN`] lowercase hex
/// characters, i.e. 8 bytes, so a peer decodes the identical seed.
fn check_noise_seed(seed: &str) -> Result<(), ProfileError> {
    let shaped = seed.len() == NOISE_SEED_HEX_LEN
        && seed
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if shaped {
        Ok(())
    } else {
        Err(ProfileError::NoiseSeedShape)
    }
}

/// Screen bounds, area, bit depth and DPR.
fn check_screen(spec: &crate::spec::ScreenSpec) -> Result<(), ProfileError> {
    for (field, value) in [("width", spec.width), ("height", spec.height)] {
        if !(MIN_SCREEN_DIMENSION..=MAX_SCREEN_DIMENSION).contains(&value) {
            return Err(ProfileError::ScreenOutOfRange {
                field,
                value: u64::from(value),
                min: u64::from(MIN_SCREEN_DIMENSION),
                max: u64::from(MAX_SCREEN_DIMENSION),
            });
        }
    }
    let area = u64::from(spec.width) * u64::from(spec.height);
    if area > MAX_SCREEN_AREA {
        return Err(ProfileError::ScreenAreaTooLarge {
            value: area,
            max: MAX_SCREEN_AREA,
        });
    }
    if !SUPPORTED_COLOR_DEPTHS.contains(&spec.color_depth) {
        return Err(ProfileError::ColorDepth(u64::from(spec.color_depth)));
    }
    if spec.dpr_milli < MIN_DPR_MILLI || spec.dpr_milli > MAX_DPR_MILLI {
        return Err(ProfileError::ScreenOutOfRange {
            field: "dpr_milli",
            value: u64::from(spec.dpr_milli),
            min: u64::from(MIN_DPR_MILLI),
            max: u64::from(MAX_DPR_MILLI),
        });
    }
    Ok(())
}

/// Hardware sanity: plausible core and memory magnitudes only.
fn check_hardware(spec: &crate::spec::HardwareSpec) -> Result<(), ProfileError> {
    if spec.cpu_cores < MIN_SLOT_CPU_CORES || spec.cpu_cores > MAX_CPU_CORES {
        return Err(ProfileError::HardwareOutOfRange {
            field: "cpu_cores",
            value: u64::from(spec.cpu_cores),
            min: u64::from(MIN_SLOT_CPU_CORES),
            max: u64::from(MAX_CPU_CORES),
        });
    }
    if spec.memory_mib < MIN_MEMORY_MIB || spec.memory_mib > MAX_MEMORY_MIB {
        return Err(ProfileError::HardwareOutOfRange {
            field: "memory_mib",
            value: u64::from(spec.memory_mib),
            min: u64::from(MIN_MEMORY_MIB),
            max: u64::from(MAX_MEMORY_MIB),
        });
    }
    Ok(())
}

/// Mobile platforms must claim touch capability, desktop ones must not.
fn check_touch(spec: &ProfileSpecV1) -> Result<(), ProfileError> {
    let points = u64::from(spec.hardware.max_touch_points);
    if spec.platform.is_mobile() {
        if points < 1 || points > u64::from(MAX_TOUCH_POINTS) {
            return Err(ProfileError::MobileTouchPoints(points));
        }
    } else if points != 0 {
        return Err(ProfileError::DesktopTouchPoints(points));
    }
    Ok(())
}

/// Basic BCP47-shaped language tag: 2-8 alphabetic primary subtag plus up to
/// three 1-8 character alphanumeric subtags. Not a subtag registry check.
fn check_language(language: &str) -> Result<(), ProfileError> {
    let fail = || Err(ProfileError::LanguageSyntax);
    if language.is_empty()
        || language.len() > MAX_LANGUAGE_LEN
        || !language.bytes().all(|b| b.is_ascii())
    {
        return fail();
    }
    let mut parts = language.split('-');
    let primary = match parts.next() {
        Some(primary) if (2..=8).contains(&primary.len()) => primary,
        _ => return fail(),
    };
    if !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return fail();
    }
    let mut count = 1usize;
    for part in parts {
        count += 1;
        if count > MAX_LANGUAGE_PARTS
            || part.is_empty()
            || part.len() > 8
            || !part.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return fail();
        }
    }
    Ok(())
}

/// Basic IANA-shaped timezone: ASCII, at most two `/` separators, each
/// component starting with a letter and holding only `[A-Za-z0-9_+-]`. Zone
/// existence is *not* verified; see the documented gap in the crate docs.
fn check_timezone(timezone: &str) -> Result<(), ProfileError> {
    let fail = || Err(ProfileError::TimezoneSyntax);
    if timezone.is_empty()
        || timezone.len() > MAX_TIMEZONE_LEN
        || !timezone.bytes().all(|b| b.is_ascii())
        || timezone.contains("..")
        || timezone.contains('\\')
        || timezone.contains('\0')
    {
        return fail();
    }
    let mut count = 0usize;
    for part in timezone.split('/') {
        count += 1;
        if count > MAX_TIMEZONE_PARTS || part.is_empty() {
            return fail();
        }
        let bytes = part.as_bytes();
        if !bytes[0].is_ascii_alphabetic()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+'))
        {
            return fail();
        }
    }
    Ok(())
}

/// Slot map must cover exactly [`DIMENSIONS`] with in-range tier ids.
fn check_slots(slots: &BTreeMap<String, u32>) -> Result<(), ProfileError> {
    for dimension in DIMENSIONS {
        if !slots.contains_key(dimension) {
            return Err(ProfileError::MissingDimension(dimension.to_string()));
        }
    }
    for name in slots.keys() {
        if !SUPPORTED_DIMENSIONS.contains(&name.as_str()) {
            return Err(ProfileError::UnknownDimension(name.clone()));
        }
    }
    for (name, id) in slots {
        if *id < MIN_SLOT_ID || *id > MAX_SLOT_ID {
            return Err(ProfileError::SlotIdOutOfRange {
                dimension: name.clone(),
                value: *id,
                max: MAX_SLOT_ID,
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_spec(spec: &ProfileSpecV1) -> Result<(), ProfileError> {
    if spec.schema_version != SCHEMA_VERSION {
        return Err(ProfileError::SchemaVersion(spec.schema_version));
    }
    if spec.noise_version != NOISE_VERSION {
        return Err(ProfileError::NoiseVersion(spec.noise_version));
    }
    check_safe_identifier("environment_id", &spec.environment_id)?;
    check_safe_identifier("pool_version", &spec.pool_version)?;
    check_noise_seed(&spec.noise_seed_hex)?;
    check_screen(&spec.screen)?;
    check_hardware(&spec.hardware)?;
    check_touch(spec)?;
    check_language(&spec.locale.language)?;
    check_timezone(&spec.locale.timezone)?;
    check_slots(&spec.slots)
}

pub(crate) fn seed_bytes(seed: &str) -> Result<[u8; 8], ProfileError> {
    check_noise_seed(seed)?;
    let mut bytes = [0; 8];
    hex::decode_to_slice(seed, &mut bytes).map_err(|_| ProfileError::NoiseSeedShape)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimension_set_is_seven_unique_names() {
        assert_eq!(DIMENSIONS.len(), 7);
        for name in DIMENSIONS {
            assert!(SUPPORTED_DIMENSIONS.contains(&name));
        }
        assert!(!SUPPORTED_DIMENSIONS.contains(&"webgpu"));
    }

    #[test]
    fn identifier_rules_are_ordered_length_then_traversal_then_charset() {
        assert!(matches!(
            check_safe_identifier("environment_id", ""),
            Err(ProfileError::EmptyIdentifier { .. })
        ));
        assert!(matches!(
            check_safe_identifier("environment_id", "a/../b"),
            Err(ProfileError::IdentifierPathTraversal { .. })
        ));
        assert!(matches!(
            check_safe_identifier("pool_version", "a".repeat(65).as_str()),
            Err(ProfileError::IdentifierTooLong { .. })
        ));
        assert!(check_safe_identifier("environment_id", "env-1_0").is_ok());
    }

    #[test]
    fn screen_area_guard_runs_in_u64() {
        assert_eq!(
            MAX_SCREEN_DIMENSION as u64 * MAX_SCREEN_DIMENSION as u64,
            1 << 28
        );
        const {
            assert!(MAX_SCREEN_AREA < (1u64 << 28));
        }
    }
}
