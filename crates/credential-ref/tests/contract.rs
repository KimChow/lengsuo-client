//! 接口契约测试：引用只含元数据、展示面脱敏、过期判定。

mod support;

use credential_ref::{CredentialRef, Plaintext, StoreError};
use support::windows_contains;

#[test]
fn credential_ref_type_contains_only_metadata_fields() {
    // 契约：CredentialRef 结构体字段只能是 id/scope/expires_at_ms，
    // 任何新增字段都必须先证明不携带明文。
    let reference = CredentialRef::env("env-1", 1000);
    assert_eq!(reference.scope().target(), "env-1");
    assert_eq!(reference.expires_at_ms(), 1000);
    assert_eq!(reference.scope().kind(), credential_ref::ScopeKind::Env);
}

#[test]
fn scope_variants_map_to_kinds() {
    assert_eq!(
        CredentialRef::session("s", 1).scope().kind(),
        credential_ref::ScopeKind::Session
    );
    assert_eq!(
        CredentialRef::tenant("t", 1).scope().kind(),
        credential_ref::ScopeKind::Tenant
    );
    assert_eq!(
        CredentialRef::env("e", 1).scope().kind(),
        credential_ref::ScopeKind::Env
    );
}

#[test]
fn debug_output_is_redacted() {
    let reference = CredentialRef::env("env-secret-target", 4_321);
    let rendered = format!("{reference:?}");
    assert!(
        !rendered.contains("env-secret-target"),
        "Debug leaks scope target: {rendered}"
    );
    assert!(
        !rendered.contains(&reference.id().as_uuid().to_string()),
        "Debug leaks reference id: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "Debug not redacted: {rendered}"
    );
}

#[test]
fn display_output_is_redacted() {
    let reference = CredentialRef::session("session-secret-target", 99);
    let rendered = reference.to_string();
    assert!(!rendered.contains("session-secret-target"));
    assert!(!rendered.contains(&reference.id().as_uuid().to_string()));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn scope_display_and_debug_are_redacted() {
    let scope = CredentialRef::tenant("tenant-secret", 1).scope().clone();
    assert!(!scope.to_string().contains("tenant-secret"));
    assert!(!format!("{scope:?}").contains("tenant-secret"));
    let id = CredentialRef::env("e", 1).id();
    assert!(!id.to_string().contains(&id.as_uuid().to_string()));
    assert!(!format!("{id:?}").contains(&id.as_uuid().to_string()));
}

#[test]
fn plaintext_debug_and_display_are_redacted() {
    let plaintext = Plaintext::from("hunter2-super-secret");
    assert_eq!(format!("{plaintext:?}"), "Plaintext(<redacted>)");
    assert_eq!(plaintext.to_string(), "<redacted>");
    assert!(!format!("{:?}", plaintext.as_bytes()).contains("hunter2"));
}

#[test]
fn expiry_boundary_is_inclusive_and_clock_free() {
    let reference = CredentialRef::env("e", 500);
    assert!(!reference.is_expired_at(499));
    assert!(
        reference.is_expired_at(500),
        "expires_at_ms itself must be expired"
    );
    assert!(reference.is_expired_at(501));
}

#[test]
fn invalid_reference_is_empty_scope_target() {
    assert!(!CredentialRef::env("", 1).is_valid());
    assert!(!CredentialRef::session(String::new(), 1).is_valid());
    assert!(CredentialRef::tenant("t", 1).is_valid());
}

#[test]
fn refs_have_distinct_ids_and_stable_equality() {
    let a = CredentialRef::env("same", 1);
    let b = CredentialRef::env("same", 1);
    assert_ne!(a.id(), b.id());
    assert_eq!(a, a.clone());
    // 同 id 同元数据即同一引用（从容器还原后仍可定位）。
    let restored = CredentialRef::with_id(a.id(), a.scope().clone(), a.expires_at_ms());
    assert_eq!(a, restored);
}

#[test]
fn error_messages_never_carry_plaintext() {
    // 所有变体的 Display/Debug 均为静态描述；明文与 id 都不得出现。
    let plaintext = "plain-leak-check";
    let reference_id = CredentialRef::env("e", 1).id().as_uuid().to_string();
    let errors = vec![
        StoreError::NotFound,
        StoreError::Expired,
        StoreError::ScopeMismatch,
        StoreError::InvalidReference,
        StoreError::UnsupportedVersion {
            found: 7,
            expected: 1,
        },
        StoreError::WrongPassphrase,
        StoreError::RecordAuthentication,
        StoreError::MalformedContainer("truncated"),
        StoreError::Io(std::io::Error::other("io")),
    ];
    for error in errors {
        let rendered = format!("{error} {error:?}");
        assert!(!windows_contains(rendered.as_bytes(), plaintext.as_bytes()));
        assert!(
            !rendered.contains(&reference_id),
            "error leaks id: {rendered}"
        );
    }
}
