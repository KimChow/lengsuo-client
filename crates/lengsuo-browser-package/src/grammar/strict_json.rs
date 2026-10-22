//! Strict JSON entry point: duplicate keys, unknown keys, and the diagnostics
//! that name the offending key before any typed parsing happens.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::error::PackageError;

/// Ordered key/value pairs of one JSON object, kept as pairs rather than a map.
///
/// `serde_json`'s `Map`/`BTreeMap` visitors silently let the last occurrence of
/// a repeated key win, so a manifest can carry an innocuous-looking `sha256`
/// plus a second, attacker-chosen `sha256`. Deserializing through this type
/// instead asks the *text* parser for every entry it saw, which is the only way
/// to notice the duplication before any typed parsing happens.
pub(crate) struct PairList(pub(crate) Vec<(String, Value)>);

struct PairVisitor;

impl<'de> serde::de::Visitor<'de> for PairVisitor {
    type Value = PairList;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut pairs = Vec::with_capacity(map.size_hint().unwrap_or(0).min(64));
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value::<Value>()?;
            pairs.push((key, value));
        }
        Ok(PairList(pairs))
    }
}

impl<'de> serde::Deserialize<'de> for PairList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(PairVisitor)
    }
}

/// Read a JSON document strictly: exactly one value, no trailing bytes, top
/// level is an object, no key appears twice.
///
/// Only the top level is scanned for duplicates, which is enough for this
/// schema: every field is a top-level key and each field's value must be a
/// string, a number or an array of strings. A nested object can therefore only
/// appear under an unknown key, and unknown keys are rejected below.
pub(crate) fn strict_json_object(text: &str) -> Result<Vec<(String, Value)>, PackageError> {
    let PairList(pairs) = serde_json::from_str::<PairList>(text).map_err(json_error)?;
    let mut seen = BTreeSet::new();
    for (key, _) in &pairs {
        if !seen.insert(key.clone()) {
            return Err(PackageError::DuplicateKey { key: sanitize(key) });
        }
    }
    Ok(pairs)
}

/// Reject keys that are not part of the schema, and report the ones missing.
/// Done before typed parsing so the error names the offender instead of a
/// generic serde message.
///
/// `required` fields must all be present; `optional` fields may be absent.
/// The union of the two is the closed set of known keys, so a key in neither
/// list is still an [`PackageError::UnknownField`].
pub(crate) fn check_field_names(
    pairs: &[(String, Value)],
    required: &[&'static str],
    optional: &[&'static str],
) -> Result<(), PackageError> {
    let present: BTreeSet<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    if present.len() != pairs.len() {
        // Already caught by strict_json_object; keep the invariant explicit.
        return Err(PackageError::InvalidField {
            field: "$",
            reason: "duplicate object key",
        });
    }
    let known: BTreeSet<&str> = required.iter().chain(optional.iter()).copied().collect();
    for (key, _) in pairs {
        if !known.contains(key.as_str()) {
            return Err(PackageError::UnknownField {
                field: sanitize(key),
            });
        }
    }
    for name in required {
        if !present.contains(name) {
            return Err(PackageError::MissingField { field: name });
        }
    }
    Ok(())
}

/// Keep diagnostics printable and bounded even for attacker-controlled keys.
pub(crate) fn sanitize(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().take(128) {
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out.truncate(out.floor_char_boundary(256));
    out
}

pub(crate) fn json_error(error: serde_json::Error) -> PackageError {
    PackageError::JsonSyntax {
        reason: match error.classify() {
            serde_json::error::Category::Io => "input error",
            serde_json::error::Category::Syntax => "invalid syntax",
            serde_json::error::Category::Data => "invalid data type",
            serde_json::error::Category::Eof => "unexpected end of input",
        },
        line: error.line(),
        column: error.column(),
    }
}
