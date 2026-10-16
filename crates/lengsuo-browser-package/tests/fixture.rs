//! Shared manifest fixtures for the integration tests.
//!
//! Corpus strategy, so these numbers cannot drift into agreement with the
//! implementation under test:
//! * `sha256` values are SHA-256 digests computed with **Python's `hashlib`**
//!   over the deterministic `lcg_payload` bytes, pasted in here as literals.
//!   `sha2` is what the implementation uses, so agreement proves the wiring
//!   (chunking, length handling, error paths) and not merely that `sha2` equals
//!   `sha2`.
//! * `chromium_revision` is the real Chromium revision recorded for candidate
//!   baseline 155.0.8059.85 in the approved proposal.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io;

use lengsuo_browser_package::Arch;
use lengsuo_browser_package::KernelManifestV1;
use lengsuo_browser_package::Platform;

/// Baseline Chromium revision (proposal §7), 40 lowercase hex.
pub const CHROMIUM_REVISION: &str = "0e66b94549a8bd85f03fbdf189b752d6e7b63c32";
/// Digest of the recorded patch set (independent of any artifact).
pub const PATCHSET_SHA256: &str =
    "5f896d6581df21565699ef4c44695cfb4466fa69a50de3260ff982b5574d872a";
/// SHA-256 of the empty string.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Well-formed 64-char hex digest used where the value must be valid but the
/// bytes are not present (e.g. grammar-only tests).
pub const SYC_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Deterministic pseudo-random byte stream: a 32-bit linear congruential
/// generator, taking the middle byte of each state. Same bytes for any caller,
/// no dependency on a RNG, and reproducible in Python (see the digests below).
pub fn lcg_payload(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x1234_5678;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push(((state >> 16) & 0xFF) as u8);
    }
    out
}

/// `(len, sha256(lcg_payload(len)))` — digests produced by Python `hashlib`.
pub const KNOWN_VECTORS: &[(usize, &str)] = &[
    (
        1,
        "6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d",
    ),
    (
        3,
        "72e857720a94859c6a0501a09dfe098b86ea3c09fedd7bef917c685729a5455d",
    ),
    (
        64,
        "734bcd3e0fb61460e6a628bc3c39966a663c6f5fd737f6fcc15dc9ebb667ce51",
    ),
    (
        8191,
        "2aae6415736eb1368199cced9b1ca1086291134ad1d1539b23db51eab4c1a8f3",
    ),
    (
        8192,
        "12c0ad0070e6cad2a9b1b65431e0781327ec80c4fb3377e3672a591c4b3b2fc0",
    ),
    (
        8193,
        "6513b655fb24614352d64efa03eebcfa66c73bb3b9c41a053c1a21bc737f3b97",
    ),
    (
        16383,
        "e5ac8e79cc2a938980033c1c61ec5299653dc2f8b6a301b5d8a314c7874b3ca4",
    ),
    (
        16384,
        "f3bf2ae21a3ca58d77ef1584565d33cb630021b306f876950c4a7154ad7f2e07",
    ),
    (
        16385,
        "4469f35d3208c95c66907c720f4dd583b7b5072ddb55f153f4f8dfab4156cd07",
    ),
    (
        65536,
        "7bebe47855180279f4de76ed0f0d1d75b94affadbbf367ff75835d2302f8b482",
    ),
    (
        1_048_576,
        "34c6fb8ab50e9c02710cf480549846b119c19a3b152f4f87e66a9a281dd51d92",
    ),
];

/// Digest for `lcg_payload(len)`, from [`KNOWN_VECTORS`].
///
/// Panics for an unlisted length: tests must add the Python-computed digest
/// rather than letting this module compute one with the crate's own hash.
pub fn known_sha256(len: usize) -> String {
    KNOWN_VECTORS
        .iter()
        .find(|(n, _)| *n == len)
        .map(|(_, h)| (*h).to_string())
        .unwrap_or_else(|| panic!("no Python-computed vector registered for {len} bytes"))
}

/// A manifest whose declared `size_bytes`/`sha256` match `lcg_payload(size)`.
pub fn manifest_for(size: usize) -> KernelManifestV1 {
    KernelManifestV1::from_json_str(&json_for(size)).expect("fixture manifest must parse")
}

/// The canonical field list, as `(key, raw JSON value)` pairs.
///
/// Raw values rather than typed fields on purpose: tests can then place a
/// *duplicated* key, an *unknown* key or a value of the wrong JSON type in a
/// document without serde silently collapsing it first.
pub fn fixture_fields(size: usize) -> Vec<(String, String)> {
    vec![
        ("schema_version".into(), "1".into()),
        ("version".into(), r#""155.0.8059.85""#.into()),
        (
            "chromium_revision".into(),
            format!(r#""{CHROMIUM_REVISION}""#),
        ),
        ("patchset_sha256".into(), format!(r#""{PATCHSET_SHA256}""#)),
        ("platform".into(), r#""Linux""#.into()),
        ("arch".into(), r#""X86_64""#.into()),
        (
            "artifact_name".into(),
            r#""chrome-linux-x86_64-155.0.8059.85.tar.zst""#.into(),
        ),
        ("size_bytes".into(), size.to_string()),
        ("sha256".into(), format!(r#""{}""#, known_sha256(size))),
        ("profile_schema_versions".into(), "[1]".into()),
        ("pool_versions".into(), r#"["pool-2026.10"]"#.into()),
        (
            "required_capabilities".into(),
            r#"["webauthn-proxy"]"#.into(),
        ),
    ]
}

/// Render a Rust string as a JSON string literal, so hostile content
/// (control bytes, non-ASCII, quotes) survives into the document exactly.
pub fn json_str(value: &str) -> String {
    serde_json::to_string(value).expect("string always serializes")
}

/// Render an iterable of string-ish values as a JSON array of strings.
pub fn json_array<S: AsRef<str>, I: IntoIterator<Item = S>>(items: I) -> String {
    let rendered: Vec<String> = items.into_iter().map(|v| json_str(v.as_ref())).collect();
    format!("[{}]", rendered.join(","))
}

/// Append one raw pair to an already-rendered object. Typed helpers cannot
/// express a duplicated key, so this builds them by hand.
pub fn extra_pair(json: &str, key: &str, raw: &str) -> String {
    let trimmed = json.trim_end();
    assert!(trimmed.ends_with('}'), "fixture must be an object");
    format!(
        "{},\n  {}: {}\n}}",
        &trimmed[..trimmed.len() - 1],
        serde_json::to_string(key).unwrap(),
        raw
    )
}

/// Render a field list as one JSON object.
pub fn render(fields: &[(String, String)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("  {}: {}", serde_json::to_string(k).unwrap(), v))
        .collect();
    format!("{{\n{}\n}}", body.join(",\n"))
}

/// JSON text for a well-formed manifest declaring a `size`-byte artifact.
pub fn json_for(size: usize) -> String {
    render(&fixture_fields(size))
}

/// JSON with one field dropped entirely.
pub fn without(size: usize, key: &str) -> String {
    let fields: Vec<(String, String)> = fixture_fields(size)
        .into_iter()
        .filter(|(k, _)| k != key)
        .collect();
    assert_eq!(
        fields.len() + 1,
        fixture_fields(size).len(),
        "no such field {key}"
    );
    render(&fields)
}

/// JSON with one field's raw value replaced. Use [`extra`] to duplicate a key.
pub fn replaced(size: usize, key: &str, raw: &str) -> String {
    let mut fields = fixture_fields(size);
    let mut hit = false;
    for (k, v) in fields.iter_mut() {
        if k == key {
            *v = raw.to_string();
            hit = true;
        }
    }
    assert!(hit, "no such field {key}");
    render(&fields)
}

/// JSON with an extra key/value appended, hostile keys allowed.
pub fn extra(size: usize, key: &str, raw: &str) -> String {
    let mut fields = fixture_fields(size);
    fields.push((key.to_string(), raw.to_string()));
    render(&fields)
}

/// The canonical 64-byte manifest.
pub fn good_manifest() -> KernelManifestV1 {
    manifest_for(64)
}

/// Host inputs that match [`good_manifest`].
pub fn good_host_capabilities() -> BTreeSet<String> {
    ["webauthn-proxy".to_string(), "vaapi".to_string()]
        .into_iter()
        .collect()
}

/// Compatible call for [`good_manifest`]: Linux/x86-64, schema 1, known pool.
pub fn check_good(m: &KernelManifestV1) -> Result<(), lengsuo_browser_package::PackageError> {
    m.assert_compatible(
        Platform::Linux,
        Arch::X86_64,
        1,
        "pool-2026.10",
        &good_host_capabilities(),
    )
}

/// A [`Read`] that hands out `chunks.len()` bytes and then fails once.
///
/// The failure is a single, deliberate event — not "every read after position
/// N" — so tests can tell truncation (clean end of stream) apart from a
/// transport error, which is exactly the distinction verify_reader must make.
pub struct FailAfterChunks {
    chunks: Vec<Vec<u8>>,
    index: usize,
    error_kind: io::ErrorKind,
}

impl FailAfterChunks {
    /// Split `data` into `chunk_size` pieces, then fail with `error_kind`.
    pub fn new(data: &[u8], chunk_size: usize, error_kind: io::ErrorKind) -> Self {
        assert!(chunk_size > 0);
        let chunks: Vec<Vec<u8>> = data.chunks(chunk_size).map(<[u8]>::to_vec).collect();
        Self {
            chunks,
            index: 0,
            error_kind,
        }
    }

    /// Zero chunks: the very first read errors.
    pub fn immediate(error_kind: io::ErrorKind) -> Self {
        Self {
            chunks: Vec::new(),
            index: 0,
            error_kind,
        }
    }
}

impl io::Read for FailAfterChunks {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if self.index < self.chunks.len() {
            let chunk = &self.chunks[self.index];
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            // Only safe because chunk_size <= buf size in these tests; consume
            // a chunk fully when it fits.
            if n == chunk.len() {
                self.index += 1;
            } else {
                self.chunks[self.index] = chunk[n..].to_vec();
            }
            return Ok(n);
        }
        Err(io::Error::new(self.error_kind, "injected read failure"))
    }
}

/// A [`Read`] that yields `data` but returns short reads of at most
/// `max_chunk` bytes, including 1-byte reads, to exercise incremental hashing.
pub struct Dribble {
    data: Vec<u8>,
    max_chunk: usize,
    pos: usize,
}

impl Dribble {
    /// Yield at most `max_chunk` bytes per `read` call.
    pub fn new(data: &[u8], max_chunk: usize) -> Self {
        assert!(max_chunk > 0);
        Self {
            data: data.to_vec(),
            max_chunk,
            pos: 0,
        }
    }
}

impl io::Read for Dribble {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let n = (self.data.len() - self.pos)
            .min(self.max_chunk)
            .min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A [`Read`] that reports one byte at a time forever, with no end-of-stream,
/// to prove oversize detection is immediate rather than "read it all first".
pub struct EndlessOversize {
    /// Bytes still allowed before the overrun must be detected.
    pub declared: u64,
    seen: u64,
}

impl EndlessOversize {
    /// Declare that the manifest says `declared` bytes.
    pub fn new(declared: u64) -> Self {
        Self { declared, seen: 0 }
    }
}

impl io::Read for EndlessOversize {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if self.seen > self.declared + 4096 {
            // Should be unreachable: reaching it means the verifier kept
            // streaming past the declared size.
            return Err(io::Error::other(
                "verifier streamed far past the declared size",
            ));
        }
        let n = 1usize.min(buf.len());
        buf[..n].fill(0xA5);
        self.seen += n as u64;
        Ok(n)
    }
}
