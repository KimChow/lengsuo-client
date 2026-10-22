//! Deterministic digest of an unpacked extension directory.
//!
//! This is the client-side half of the cross-repo contract
//! (`credential-wire-contract.md` §5.5, algorithm v1). The extension repo
//! computes the same value in `build/build.mjs`; both sides must agree
//! byte for byte, which is why the fixed vectors in
//! `tests/vectors/extension-digest-v1.json` are shared by both.
//!
//! # The algorithm (v1, frozen)
//!
//! ```text
//! for each file f in sort(all files by UTF-8 byte order of the relative POSIX path):
//!     stream += path_utf8(f) || 0x00 || sha256(content(f)) || 0x00
//! digest = sha256(stream)
//! ```
//!
//! Rules that are easy to get wrong, and why they are what they are:
//!
//! - **Only regular files count.** Directories (empty ones included) and
//!   special files contribute nothing.
//! - **Relative POSIX paths**, `/` separated, never `\` — on Windows too.
//! - **Sort by UTF-8 byte order.** Not locale collation, not UTF-16 code unit
//!   order. See the note on the astral divergence below.
//! - **Symlinks are skipped entirely and never followed.** The link itself is
//!   not counted and its target is not walked, so a link cannot pull bytes
//!   from outside the extension directory into the digest.
//! - **The per-file digest is the raw 32 bytes**, never a hex string.
//!
//! # Astral filenames and the JS divergence
//!
//! The contract requires UTF-8 byte order. The extension repo's JavaScript
//! sorts with `<`, which is UTF-16 code unit order. The two agree for every
//! BMP character and diverge for astral characters (U+10000 and above, such
//! as emoji). This crate follows the contract; the extension repo needs to
//! sort by UTF-8 bytes to match.

use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Longest relative path we are willing to build while walking a directory.
///
/// A path longer than this is not a real extension layout, and the bound
/// keeps a hostile directory from forcing an unbounded allocation.
const MAX_RELATIVE_PATH_LEN: usize = 4096;

/// One digest result: the digest itself plus the files that went into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionDigest {
    /// The directory digest, 64 lowercase hex characters.
    pub digest: String,
    /// Relative POSIX paths of the counted files, sorted by UTF-8 byte order.
    pub files: Vec<String>,
}

/// Failure while reading an extension directory.
#[derive(Debug, thiserror::Error)]
pub enum ExtensionDigestError {
    /// The extension directory could not be read.
    #[error("extension directory `{path}` cannot be read: {reason}")]
    Io {
        /// What failed, in fixed words.
        reason: &'static str,
        /// The path involved, rendered for humans.
        path: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// The extension root is not a directory (it is missing, a file, or a
    /// symlink — a symlink is refused rather than followed).
    #[error("extension root `{path}` is not a directory")]
    NotADirectory {
        /// The path involved, rendered for humans.
        path: String,
    },

    /// A name inside the extension directory is not valid UTF-8.
    ///
    /// The digest is defined over UTF-8 path bytes, so such a directory
    /// cannot be summarised without inventing bytes. Refused, not repaired.
    #[error("extension directory contains a non-UTF-8 path: `{path}`")]
    NonUtf8Path {
        /// The offending path, rendered for humans.
        path: String,
    },
}

/// Walk `root` and compute the deterministic digest of the extension
/// directory it holds.
///
/// Symbolic links are skipped entirely: they are neither counted nor
/// followed, so nothing outside `root` can influence the digest. The
/// directory is never canonicalised, which would follow links.
///
/// `root` itself must be a real directory; a symlinked root is refused.
pub fn digest_directory(root: &Path) -> Result<ExtensionDigest, ExtensionDigestError> {
    let meta = std::fs::symlink_metadata(root).map_err(|e| ExtensionDigestError::Io {
        reason: "cannot stat extension root",
        path: render(root),
        source: e,
    })?;
    if !meta.is_dir() {
        return Err(ExtensionDigestError::NotADirectory { path: render(root) });
    }

    let mut entries: Vec<(String, [u8; 32])> = Vec::new();
    collect(root, "", &mut entries)?;
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let files = entries.iter().map(|(p, _)| p.clone()).collect();
    let digest = digest_sorted(&entries);
    Ok(ExtensionDigest { digest, files })
}

/// Compute the digest from `(relative path, raw content sha256)` pairs.
///
/// This is the pure half of the algorithm and the seam the cross-repo
/// vectors compare against: it must return the same digest as the extension
/// repo's JavaScript for the same input.
///
/// The entries are sorted here by UTF-8 byte order of the relative path, so
/// the caller does not have to.
pub fn digest_entries<I>(entries: I) -> String
where
    I: IntoIterator<Item = (String, [u8; 32])>,
{
    let mut sorted: Vec<(String, [u8; 32])> = entries.into_iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    digest_sorted(&sorted)
}

/// Digest of already-sorted entries.
fn digest_sorted(entries: &[(String, [u8; 32])]) -> String {
    let mut hasher = Sha256::new();
    for (path, content_digest) in entries {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update(content_digest);
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

/// Recursively collect `(relative POSIX path, raw sha256)` for regular files.
///
/// `rel` is the path of `dir` relative to the root, already in POSIX form
/// (empty for the root itself).
fn collect(
    dir: &Path,
    rel: &str,
    out: &mut Vec<(String, [u8; 32])>,
) -> Result<(), ExtensionDigestError> {
    let reader = std::fs::read_dir(dir).map_err(|e| ExtensionDigestError::Io {
        reason: "cannot list extension directory",
        path: render(dir),
        source: e,
    })?;
    for entry in reader {
        let entry = entry.map_err(|e| ExtensionDigestError::Io {
            reason: "cannot read directory entry",
            path: render(dir),
            source: e,
        })?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| ExtensionDigestError::NonUtf8Path {
                path: render(&entry.path()),
            })?;
        let child_rel = if rel.is_empty() {
            name.to_string()
        } else {
            format!("{rel}/{name}")
        };
        if child_rel.len() > MAX_RELATIVE_PATH_LEN {
            return Err(ExtensionDigestError::NonUtf8Path {
                path: render(&entry.path()),
            });
        }
        let child = dir.join(name);
        // symlink_metadata, not metadata: a link must be recognised as a link
        // instead of being resolved to whatever it points at.
        let meta = std::fs::symlink_metadata(&child).map_err(|e| ExtensionDigestError::Io {
            reason: "cannot stat extension entry",
            path: render(&child),
            source: e,
        })?;
        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect(&child, &child_rel, out)?;
        } else if meta.is_file() {
            let bytes = std::fs::read(&child).map_err(|e| ExtensionDigestError::Io {
                reason: "cannot read extension file",
                path: render(&child),
                source: e,
            })?;
            out.push((child_rel, sha256(&bytes)));
        }
        // Anything else (fifo, socket, device) is not a regular file and is
        // skipped, like the archive reader skips non-regular archive members.
    }
    Ok(())
}

/// Raw SHA-256 of a byte slice.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Render a path for an error message: lossy, single line, bounded.
fn render(path: &Path) -> String {
    let text = path.to_string_lossy();
    let mut out = String::with_capacity(text.len().min(256));
    for c in text.chars().take(256) {
        if c.is_control() {
            out.push('?');
        } else {
            out.push(c);
        }
    }
    out
}
