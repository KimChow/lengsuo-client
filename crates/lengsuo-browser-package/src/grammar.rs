//! Character-level grammars for every string in a manifest, plus the strict
//! JSON entry point that keeps duplicate and unknown keys from being absorbed
//! silently.
//!
//! These checks are deliberately *lexical*. They ask "could any honest
//! publisher have written this?" and reject everything else; they never repair,
//! trim, case-fold or pad an input into something acceptable.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::error::PackageError;

/// Longest accepted `version` string.
pub(crate) const MAX_VERSION_LEN: usize = 64;
/// Longest accepted `artifact_name`.
pub(crate) const MAX_ARTIFACT_NAME_LEN: usize = 255;
/// Longest accepted `extension_dir_name`.
pub(crate) const MAX_EXTENSION_DIR_NAME_LEN: usize = 255;
/// Longest accepted identifier token (capability, pool version, ...).
pub(crate) const MAX_TOKEN_LEN: usize = 64;
/// Longest accepted set of tokens, so one hostile manifest cannot make a
/// client allocate a huge collection before it is rejected.
pub(crate) const MAX_COLLECTION_ENTRIES: usize = 64;
/// Largest `size_bytes` a manifest may declare. A real kernel archive is well
/// under this, and the bound stops a client from agreeing to stream an
/// unbounded body just because a manifest asked for it.
pub(crate) const MAX_SIZE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// True if every char is an ASCII digit.
fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `<4 numeric components>.<4 numeric components>.<4 numeric components>.<4
/// numeric components>` — the Chromium version shape, e.g. `155.0.8059.85`.
///
/// Leading zeros are rejected: they are not how any publisher writes versions,
/// and accepting them would let `1.2.3.04` and `1.2.3.4` name two different
/// releases that are numerically identical.
pub(crate) fn version_shape_ok(s: &str) -> bool {
    if s.len() > MAX_VERSION_LEN {
        return false;
    }
    let mut parts = s.split('.');
    // Exactly four parts, each 1..=9 ASCII digits with no leading zero unless
    // the part is literally "0".
    for part in &mut parts {
        if part.is_empty() || part.len() > 10 || !is_ascii_digits(part) {
            return false;
        }
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
        if part.parse::<u32>().is_err() {
            return false;
        }
    }
    // `split('.')` yielded exactly four items.
    parts.next().is_none() && s.matches('.').count() == 3
}

/// Exactly `len` lowercase hex characters.
pub(crate) fn hex_lowercase_of_len(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// True if `s` is a safe single-path-component artifact name.
///
/// Rejected: anything containing `/`, `\`, `:` (Windows separators, drive
/// letters, `file:`-style schemes and NTFS alternate data streams), any control
/// or DEL character, any space or non-ASCII byte, leading `.` or `-` (relative
/// paths, hidden files, accidental CLI flags), trailing `.` or `-` (Windows
/// folds `chrome.dll.` and `chrome.dll ` onto the same file), `..` sequences,
/// and the Win32 reserved device names (`CON`, `NUL`, `COM1`..) which would let
/// a "safe basename" still hijack a write.
pub(crate) fn artifact_name_ok(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_ARTIFACT_NAME_LEN {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    {
        return false;
    }
    let first = s.as_bytes()[0];
    if first == b'.' || first == b'-' {
        return false;
    }
    let last = s.as_bytes()[s.len() - 1];
    if last == b'.' || last == b'-' {
        return false;
    }
    if s.contains("..") {
        return false;
    }
    // Must still look like a file, not a bare run of dots or no extension at
    // all is fine, but `.zip`-less names are the installer's problem, not ours.
    !is_win_reserved(s)
}

/// True if `s` is a safe single-path-component extension directory name.
///
/// The manifest names a directory that ships inside the kernel package
/// layout, so the value must be a *name*, never a path: anything containing
/// `/` or `\` is refused. The alphabet is ASCII letters, digits, `.`, `_`
/// and `-`.
///
/// Also refused: the empty name, a name longer than
/// [`MAX_EXTENSION_DIR_NAME_LEN`], the relative names `.` and `..`, a name
/// starting or ending with `.` or `-` (hidden entries, accidental CLI
/// flags, and the trailing-dot names Windows folds onto their base), and
/// the Win32 reserved device names — reused verbatim from
/// [`artifact_name_ok`], because a directory name that can be a device name
/// can still hijack a write.
pub(crate) fn extension_dir_name_ok(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_EXTENSION_DIR_NAME_LEN {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return false;
    }
    // A name, not a path.
    if s.contains('/') || s.contains('\\') {
        return false;
    }
    if s == "." || s == ".." {
        return false;
    }
    let first = s.as_bytes()[0];
    if first == b'.' || first == b'-' {
        return false;
    }
    let last = s.as_bytes()[s.len() - 1];
    if last == b'.' || last == b'-' {
        return false;
    }
    !is_win_reserved(s)
}

/// Win32 reserved device names, compared the way Windows does: case- and
/// trailing-dot-insensitive, and `COM`/`LPT` accept 1..=9.
pub(crate) fn is_win_reserved(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let stem = upper.split('.').next().unwrap_or_default();
    if matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$") {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(rest) = stem.strip_prefix(prefix) {
            if rest.len() == 1 && matches!(rest.as_bytes()[0], b'1'..=b'9') {
                return true;
            }
        }
    }
    false
}

/// Value-pool version id: a conservative token, same alphabet rules as a
/// capability, but allowed to start with a digit (`2026.10`).
pub(crate) fn pool_version_ok(s: &str) -> bool {
    token_ok(s, true)
}
/// Capability identifier: must start with a lowercase ASCII letter, then
/// `[a-z0-9._-]`. Uppercase is rejected so that `VA-API` and `va-api` cannot be
/// two spellings of one capability, which would make a compatibility check
/// depend on who happened to write the manifest.
pub(crate) fn capability_ok(s: &str) -> bool {
    token_ok(s, false)
}

fn token_ok(s: &str, allow_leading_digit: bool) -> bool {
    if s.is_empty() || s.len() > MAX_TOKEN_LEN {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return false;
    }
    let first = s.as_bytes()[0];
    let first_ok = first.is_ascii_lowercase() || (allow_leading_digit && first.is_ascii_digit());
    if !first_ok {
        return false;
    }
    let last = s.as_bytes()[s.len() - 1];
    if last == b'.' {
        return false;
    }
    !s.contains("..")
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_shape() {
        assert!(version_shape_ok("155.0.8059.85"));
        assert!(version_shape_ok("0.0.0.0"));
        assert!(!version_shape_ok("155.0.8059"));
        assert!(!version_shape_ok("155.0.8059.85.1"));
        assert!(!version_shape_ok("155.0..85"));
        assert!(!version_shape_ok("155.0.8059.085"));
        assert!(!version_shape_ok(" 155.0.8059.85"));
        assert!(!version_shape_ok("155.0.8059.85 "));
        assert!(!version_shape_ok("155.0.8059.x"));
    }

    #[test]
    fn hex_shape() {
        assert!(hex_lowercase_of_len(&"0".repeat(40), 40));
        assert!(!hex_lowercase_of_len(&"0".repeat(39), 40));
        assert!(!hex_lowercase_of_len(&"f".repeat(41), 40));
        assert!(!hex_lowercase_of_len(&("A".repeat(39) + "f"), 40));
        assert!(!hex_lowercase_of_len(&("0".repeat(39) + "g"), 40));
        assert!(!hex_lowercase_of_len(&("0".repeat(39) + " "), 40));
    }

    #[test]
    fn artifact_name_shape() {
        assert!(artifact_name_ok("chrome-linux64.zip"));
        assert!(artifact_name_ok("chrome+x86_64.tar.zst"));
        for hostile in [
            "",
            ".",
            "..",
            "../evil",
            "a/../b",
            "/etc/passwd",
            "C:\\windows",
            "sub/dir.zip",
            "chrome\r\n.dll",
            "nul",
            "CON",
            "COM1",
            "LPT9.",
            "aux.txt",
            "-x",
            ".hidden",
            "chrome .dll",
            "chrome.dll ",
            "\u{7}zip",
            "ünïcode.zip",
            "a:b",
        ] {
            assert!(!artifact_name_ok(hostile), "accepted {hostile:?}");
        }
        assert!(!artifact_name_ok(&"a".repeat(MAX_ARTIFACT_NAME_LEN + 1)));
    }

    #[test]
    fn token_shape() {
        assert!(capability_ok("webauthn-proxy"));
        assert!(capability_ok("vaapi"));
        assert!(!capability_ok("vaApi"));
        assert!(!capability_ok("2026"));
        assert!(!capability_ok("_x"));
        assert!(pool_version_ok("2026.10"));
        assert!(pool_version_ok("pool-2026-10"));
        assert!(!pool_version_ok(""));
        assert!(!pool_version_ok(".."));
        assert!(!pool_version_ok("../etc"));
        assert!(!pool_version_ok(&"p".repeat(MAX_TOKEN_LEN + 1)));
    }

    #[test]
    fn extension_dir_name_shape() {
        assert!(extension_dir_name_ok("lengsuo-credential"));
        assert!(extension_dir_name_ok("credential"));
        assert!(extension_dir_name_ok("cred_2026.10"));
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
            "nul",
            "CON",
            "COM1",
            "aux.txt",
            "ünïcode",
        ] {
            assert!(!extension_dir_name_ok(hostile), "accepted {hostile:?}");
        }
        assert!(!extension_dir_name_ok(
            &"a".repeat(MAX_EXTENSION_DIR_NAME_LEN + 1)
        ));
        assert!(extension_dir_name_ok(
            &"a".repeat(MAX_EXTENSION_DIR_NAME_LEN)
        ));
    }
}
