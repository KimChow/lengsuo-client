//! The extension directory digest (contract §5.5, algorithm v1) against the
//! fixed vectors shared with the extension repository.
//!
//! The vectors in `tests/vectors/extension-digest-v1.json` are the *only*
//! thing that keeps the Rust and the JavaScript implementations from
//! drifting apart: two independent implementations that agree on nothing
//! externally observable still agree with each other. So every vector is
//! checked twice — once through a real directory on disk, once through the
//! pure function — and the two must agree with each other and with the
//! expected digest.

mod support;

use lengsuo_browser_package::digest_directory;
use lengsuo_browser_package::digest_entries;
use serde_json::Value;
use support::{hex32, hex_bytes, TempDir};

/// Where the extension repository keeps its build output on this machine.
const EXTENSION_DIST: &str = "/home/ubuntu/lengsuo-extension/dist/credential";

/// Every vector in the shared file.
fn vectors() -> Vec<Value> {
    support::vectors()["vectors"]
        .as_array()
        .expect("vectors array")
        .clone()
}

/// The vectors of one section.
fn section(name: &str) -> Vec<Value> {
    vectors()
        .into_iter()
        .filter(|v| v["section"] == name)
        .collect()
}

/// Write the vector's files into a fresh directory and return it.
///
/// The real directory is the point of the exercise: the pure function alone
/// would not exercise path collection, sorting or separator handling.
fn materialize(vector: &Value) -> TempDir {
    let dir = TempDir::new(vector["name"].as_str().expect("vector name"));
    let contents = vector["contents_hex"]
        .as_object()
        .expect("contents_hex object");
    for (path, hex) in contents {
        dir.write(path, &hex_bytes(hex.as_str().expect("hex string")));
    }
    dir
}

/// The `(path, raw sha256)` pairs a vector declares.
fn entries(vector: &Value) -> Vec<(String, [u8; 32])> {
    vector["files"]
        .as_array()
        .expect("files array")
        .iter()
        .map(|f| {
            (
                f["path"].as_str().expect("path").to_string(),
                hex32(f["sha256"].as_str().expect("sha256")),
            )
        })
        .collect()
}

#[test]
fn cross_repo_vectors_are_reproduced_byte_for_byte() {
    let group = section("cross_repo");
    assert_eq!(
        group.len(),
        8,
        "the shared file must carry 8 cross_repo vectors"
    );
    for vector in &group {
        let name = vector["name"].as_str().expect("vector name");
        let expected = vector["expected_digest"].as_str().expect("expected digest");
        let dir = materialize(vector);

        let result =
            digest_directory(dir.path()).unwrap_or_else(|e| panic!("{name}: digest failed: {e}"));
        eprintln!("{name}: expected {expected} / walked {}", result.digest);
        assert_eq!(result.digest, expected, "{name}: directory digest");

        // The pure function must reach the same digest from the per-file
        // digests alone: that is the seam the JavaScript implementation uses.
        assert_eq!(
            digest_entries(entries(vector)),
            expected,
            "{name}: pure function digest"
        );

        // And the directory walk must have counted exactly the declared
        // files, in UTF-8 byte order.
        let mut counted: Vec<String> = result.files.clone();
        let mut declared: Vec<String> = vector["files"]
            .as_array()
            .expect("files array")
            .iter()
            .map(|f| f["path"].as_str().expect("path").to_string())
            .collect();
        counted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        declared.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(counted, declared, "{name}: counted files");
    }
}

#[test]
fn rust_only_vector_pins_utf8_byte_order() {
    // The one vector the JavaScript side cannot reproduce: an astral
    // character sorts differently under UTF-8 byte order (what the contract
    // asks for) and under UTF-16 code unit order (what JavaScript's `<`
    // does). This crate follows the contract; the shared file pins that.
    let group = section("rust_only");
    assert_eq!(
        group.len(),
        1,
        "the shared file must carry 1 rust_only vector"
    );
    let vector = &group[0];
    let expected = vector["expected_digest"].as_str().expect("expected digest");
    let dir = materialize(vector);

    let result = digest_directory(dir.path()).expect("digest");
    eprintln!(
        "astral_unicode: expected {expected} / walked {}",
        result.digest
    );
    assert_eq!(result.digest, expected, "astral vector digest");
    assert_eq!(
        digest_entries(entries(vector)),
        expected,
        "astral pure digest"
    );
}

#[test]
fn the_two_paths_agree_on_every_vector() {
    // Guards the plumbing itself: walking a directory and feeding the
    // per-file digests by hand must be the same computation.
    for vector in vectors() {
        let name = vector["name"].as_str().expect("vector name");
        let dir = materialize(&vector);
        let walked = digest_directory(dir.path()).expect("digest");
        assert_eq!(
            walked.digest,
            digest_entries(entries(&vector)),
            "{name}: walk and pure function disagree"
        );
    }
}

#[test]
fn empty_directories_contribute_nothing() {
    let dir = TempDir::new("empty-dirs");
    dir.write("a.txt", b"a");
    std::fs::create_dir_all(dir.path().join("empty/nested")).expect("mkdir");
    let with_empty = digest_directory(dir.path()).expect("digest");

    let plain = TempDir::new("no-empty-dirs");
    plain.write("a.txt", b"a");
    let without_empty = digest_directory(plain.path()).expect("digest");

    assert_eq!(with_empty.digest, without_empty.digest);
    assert_eq!(with_empty.files, vec!["a.txt".to_string()]);
}

#[test]
fn the_digest_does_not_depend_on_write_order() {
    let first = TempDir::new("order-a");
    first.write("a.txt", b"a");
    first.write("b.txt", b"b");
    first.write("sub/c.txt", b"c");

    let second = TempDir::new("order-b");
    second.write("sub/c.txt", b"c");
    second.write("b.txt", b"b");
    second.write("a.txt", b"a");

    assert_eq!(
        digest_directory(first.path()).expect("digest").digest,
        digest_directory(second.path()).expect("digest").digest
    );
}

#[test]
fn a_renamed_file_changes_the_digest() {
    let dir = TempDir::new("rename");
    dir.write("a.txt", b"a");
    let before = digest_directory(dir.path()).expect("digest").digest;

    std::fs::rename(dir.path().join("a.txt"), dir.path().join("b.txt")).expect("rename");
    let after = digest_directory(dir.path()).expect("digest").digest;

    assert_ne!(before, after, "the path is part of the digest");
}

#[test]
fn changed_content_changes_the_digest() {
    let dir = TempDir::new("content");
    dir.write("a.txt", b"a");
    let before = digest_directory(dir.path()).expect("digest").digest;

    dir.write("a.txt", b"b");
    let after = digest_directory(dir.path()).expect("digest").digest;

    assert_ne!(before, after, "the content is part of the digest");
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_skipped_and_never_followed() {
    let outside = TempDir::new("outside");
    outside.write("secret.txt", b"not part of the extension");

    let dir = TempDir::new("symlinks");
    dir.write("real.txt", b"real");
    // A link to a file: not counted, target not hashed.
    dir.symlink(
        "link.txt",
        &outside.path().join("secret.txt").to_string_lossy(),
    );
    // A link to a directory: not counted, and not walked.
    dir.symlink("linked-dir", &outside.path().to_string_lossy());

    let result = digest_directory(dir.path()).expect("digest");
    assert_eq!(result.files, vec!["real.txt".to_string()]);

    let plain = TempDir::new("symlinks-plain");
    plain.write("real.txt", b"real");
    assert_eq!(
        result.digest,
        digest_directory(plain.path()).expect("digest").digest,
        "links must not change the digest"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_root_is_refused_rather_than_followed() {
    let outside = TempDir::new("root-target");
    outside.write("a.txt", b"a");

    let dir = TempDir::new("root-link");
    dir.symlink("link", &outside.path().to_string_lossy());

    let err =
        digest_directory(&dir.path().join("link")).expect_err("a symlinked root must be refused");
    assert!(
        matches!(
            err,
            lengsuo_browser_package::ExtensionDigestError::NotADirectory { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn a_missing_root_is_refused() {
    let err = digest_directory(std::path::Path::new("/nonexistent/lengsuo-w5"))
        .expect_err("a missing root must be refused");
    assert!(
        matches!(
            err,
            lengsuo_browser_package::ExtensionDigestError::Io { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn the_anchor_files_digest_to_the_expected_value() {
    // The cross-repo anchor: the extension repository's own build output,
    // snapshotted as nine paths and nine per-file digests. Feeding those
    // through the pure function must reproduce the recorded directory
    // digest. If either side drifts, this stops matching.
    let vectors = support::vectors();
    let anchor = &vectors["cross_repo_anchor"];
    let expected = anchor["expected_digest"].as_str().expect("anchor digest");
    assert_eq!(
        expected, "cad5376ed54dc3a7128a5df681c1beb1d2a07007c5f90cb128a5fd8e4b59c820",
        "the anchor digest is the frozen cross-repo value"
    );

    let entries: Vec<(String, [u8; 32])> = anchor["files"]
        .as_array()
        .expect("anchor files")
        .iter()
        .map(|f| {
            (
                f["path"].as_str().expect("path").to_string(),
                hex32(f["sha256"].as_str().expect("sha256")),
            )
        })
        .collect();
    assert_eq!(entries.len(), 9, "the anchor holds nine files");
    assert_eq!(digest_entries(entries), expected);
}

#[test]
fn the_real_extension_repository_output_matches_the_anchor() {
    // The real thing, when this machine has it: the extension repository's
    // build output must digest to the anchored value. `node build/build.mjs
    // --digest` computes the same number on the JavaScript side.
    let anchor = &support::vectors()["cross_repo_anchor"];
    let expected = anchor["expected_digest"].as_str().expect("anchor digest");
    let root = std::path::Path::new(EXTENSION_DIST);
    if !root.is_dir() {
        eprintln!("note: {EXTENSION_DIST} is not present on this machine; anchor not re-checked");
        return;
    }
    let result = digest_directory(root).expect("digest the extension output");
    eprintln!("rust digest of {EXTENSION_DIST}: {}", result.digest);
    assert_eq!(
        result.digest, expected,
        "the extension output no longer matches the anchor. The anchor is a \
         snapshot of the extension repository at commit d113888: when that \
         repository advances, re-snapshot the anchor — do not weaken the check."
    );
    assert_eq!(
        result.files.len(),
        anchor["file_count"].as_u64().expect("file count") as usize
    );
}
