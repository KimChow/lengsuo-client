//! Adversarial expectations for `ArchivePlan` path-plan validation only.
//!
//! Every expected value below is written by hand or derived from the
//! *declared* boundaries (240-byte path limit, 32-component limit, Windows
//! reserved-device list, directory size 0, capacity budgets). The crate under
//! test is never used as an oracle. Real extraction/install is not
//! implemented and is not certified by this file.

// 用例按主题拆到 `tests/adversarial/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use lengsuo_browser_installer::{ArchiveError, ArchivePlan, EntryKind, Limits};

/// Builds a plan from explicitly stated budgets so each test names its own
/// boundary expectations.
fn plan(entries: usize, total_bytes: u64, entry_bytes: u64) -> ArchivePlan {
    ArchivePlan::new(Limits {
        entries,
        total_bytes,
        entry_bytes,
    })
    .expect("limits are valid by construction")
}

fn lower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

include!("adversarial/limits.rs");
include!("adversarial/paths.rs");
include!("adversarial/duplicates.rs");
include!("adversarial/invariance.rs");
