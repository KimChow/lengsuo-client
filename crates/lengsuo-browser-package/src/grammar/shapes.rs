//! Pure lexical shape checks: the `MAX_*` bounds and the character-level
//! grammars for every string a manifest carries.

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
