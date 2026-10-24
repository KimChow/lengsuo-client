//! Archive validation prerequisite only. No extraction/install/authentication.
//!
//! 安装层：见 [`crate::host_manifest`]（[`crate::host_manifest::install_host_manifest`] 等）。
//! 安装时把 host manifest 渲染并按平台落地（Windows 注册表默认值 / POSIX
//! `NativeMessagingHosts`），全部复用 `lengsuo-native-host` 的
//! `render_host_manifest` 与 `plan_*` / `register`，**不复制字节**；本 crate 仍
//! 不做归档解压。
#![forbid(unsafe_code)]
use std::collections::BTreeMap;

pub mod host_manifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub entries: usize,
    pub total_bytes: u64,
    pub entry_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    InvalidPath,
    UnsupportedKind,
    Collision,
    Limit,
}

const MAX_PATH_BYTES: usize = 240;
const MAX_COMPONENTS: usize = 32;

pub struct ArchivePlan {
    entries: BTreeMap<String, EntryKind>,
    limits: Limits,
    total: u64,
}

/// Windows reserved device basename (case-insensitive, extension ignored).
fn is_reserved_device(base: &str) -> bool {
    let up = base.to_ascii_uppercase();
    if matches!(up.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let is_port = (up.starts_with("COM") || up.starts_with("LPT"))
        && up.len() == 4
        && matches!(up.as_bytes()[3], b'1'..=b'9');
    is_port
}

/// Validate one component of a ZIP-style path.
fn validate_component(part: &str) -> Result<(), ArchiveError> {
    if part.is_empty() || part == "." || part == ".." {
        return Err(ArchiveError::InvalidPath);
    }
    if part.contains(['<', '>', ':', '"', '|', '?', '*', '\\', '/']) {
        return Err(ArchiveError::InvalidPath);
    }
    if part.ends_with('.') || part.ends_with(' ') {
        return Err(ArchiveError::InvalidPath);
    }
    let base = part.split('.').next().unwrap_or(part);
    if is_reserved_device(base) {
        return Err(ArchiveError::InvalidPath);
    }
    Ok(())
}

/// Strict ASCII ZIP path subset, <=240 bytes and <=32 components.
/// Reject traversal, backslash, drive/UNC, Windows invalid/device names,
/// trailing dot/space, symlinks, case-insensitive/prefix file collisions.
/// Directories carry size0. Invalid registration leaves all counters unchanged.
impl ArchivePlan {
    pub fn new(limits: Limits) -> Result<Self, ArchiveError> {
        if limits.entries == 0
            || limits.total_bytes == 0
            || limits.entry_bytes == 0
            || limits.entry_bytes > limits.total_bytes
        {
            return Err(ArchiveError::Limit);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            limits,
            total: 0,
        })
    }

    pub fn register(
        &mut self,
        name: &str,
        kind: EntryKind,
        size: u64,
    ) -> Result<String, ArchiveError> {
        if kind == EntryKind::Symlink {
            return Err(ArchiveError::UnsupportedKind);
        }
        if kind == EntryKind::Directory && size != 0 {
            return Err(ArchiveError::Limit);
        }
        if size > self.limits.entry_bytes {
            return Err(ArchiveError::Limit);
        }
        let canonical = Self::validate_path(name, kind)?;
        // Budget and collision checks happen before any mutation.
        if self.entries.len() >= self.limits.entries {
            return Err(ArchiveError::Limit);
        }
        let new_total = self.total.checked_add(size).ok_or(ArchiveError::Limit)?;
        if new_total > self.limits.total_bytes {
            return Err(ArchiveError::Limit);
        }
        let key = canonical.to_ascii_lowercase();
        let prefix = format!("{key}/");
        for (stored, stored_kind) in &self.entries {
            if *stored == key {
                return Err(ArchiveError::Collision);
            }
            // Existing file is a component prefix of the new path.
            if *stored_kind == EntryKind::File
                && key.len() > stored.len()
                && key.starts_with(stored.as_str())
                && key.as_bytes()[stored.len()] == b'/'
            {
                return Err(ArchiveError::Collision);
            }
            // New file is a component prefix of an existing entry.
            if kind == EntryKind::File && stored.starts_with(prefix.as_str()) {
                return Err(ArchiveError::Collision);
            }
        }
        self.entries.insert(key, kind);
        self.total = new_total;
        Ok(canonical)
    }

    fn validate_path(name: &str, kind: EntryKind) -> Result<String, ArchiveError> {
        if name.is_empty() || !name.is_ascii() {
            return Err(ArchiveError::InvalidPath);
        }
        if name.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
            return Err(ArchiveError::InvalidPath);
        }
        let body = if let Some(rest) = name.strip_suffix('/') {
            // Directories may carry exactly one trailing slash; files may not.
            if kind != EntryKind::Directory {
                return Err(ArchiveError::InvalidPath);
            }
            rest
        } else {
            name
        };
        if body.is_empty() || body.len() > MAX_PATH_BYTES {
            return Err(ArchiveError::InvalidPath);
        }
        let mut count = 0usize;
        for part in body.split('/') {
            count += 1;
            if count > MAX_COMPONENTS {
                return Err(ArchiveError::InvalidPath);
            }
            validate_component(part)?;
        }
        Ok(body.to_string())
    }
}

pub use host_manifest::{
    install_host_manifest, HostInstallError, HostInstallOutcome, HostInstallPlan,
    HostInstallRequest,
};
