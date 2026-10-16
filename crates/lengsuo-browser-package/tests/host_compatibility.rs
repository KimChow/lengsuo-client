//! Each compatibility axis rejects independently after manifest validation.
mod fixture;
use fixture::*;
use lengsuo_browser_package::{Arch, PackageError, Platform};
use std::collections::BTreeSet;

#[test]
fn compatible_host_accepts_extra_capabilities() {
    check_good(&good_manifest()).unwrap();
}

#[test]
fn platform_and_architecture_must_match_exactly() {
    let m = good_manifest();
    assert!(matches!(
        m.assert_compatible(
            Platform::Windows,
            Arch::X86_64,
            1,
            "pool-2026.10",
            &good_host_capabilities()
        ),
        Err(PackageError::PlatformMismatch { .. })
    ));
    assert!(matches!(
        m.assert_compatible(
            Platform::Linux,
            Arch::Aarch64,
            1,
            "pool-2026.10",
            &good_host_capabilities()
        ),
        Err(PackageError::ArchMismatch { .. })
    ));
}

#[test]
fn unsupported_profile_and_pool_are_independent_rejections() {
    let m = good_manifest();
    assert!(matches!(
        m.assert_compatible(
            Platform::Linux,
            Arch::X86_64,
            2,
            "pool-2026.10",
            &good_host_capabilities()
        ),
        Err(PackageError::ProfileSchemaUnsupported { wanted: 2 })
    ));
    assert!(matches!(
        m.assert_compatible(
            Platform::Linux,
            Arch::X86_64,
            1,
            "pool-new",
            &good_host_capabilities()
        ),
        Err(PackageError::PoolVersionUnsupported { .. })
    ));
}

#[test]
fn missing_host_capability_is_not_granted_by_manifest() {
    assert!(matches!(
        good_manifest().assert_compatible(
            Platform::Linux,
            Arch::X86_64,
            1,
            "pool-2026.10",
            &BTreeSet::new()
        ),
        Err(PackageError::MissingCapabilities { count: 1, .. })
    ));
}

#[test]
fn hand_built_invalid_manifest_cannot_skip_validation() {
    let mut m = good_manifest();
    m.chromium_revision = "invalid".into();
    assert!(matches!(
        check_good(&m),
        Err(PackageError::InvalidField {
            field: "chromium_revision",
            ..
        })
    ));
}
