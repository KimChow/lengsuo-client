//! Fixed independent OpenSSL signatures test the package/signature boundary.
mod fixture;
use fixture::*;
use lengsuo_browser_package::{AuthenticatedManifest, PackageError};
use lengsuo_browser_signature::{Error, TrustStore, VerificationPolicy};

// Synthetic test identity shared with the signature crate's independent vector.
const PUBLIC_KEY: &str = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a";
const VALID: &str = include_str!("vectors/valid.json");
fn store() -> TrustStore {
    TrustStore::new([(
        "release-a".into(),
        hex::decode(PUBLIC_KEY).unwrap().try_into().unwrap(),
    )])
    .unwrap()
}
fn policy() -> VerificationPolicy {
    VerificationPolicy {
        now_unix: 100,
        maximum_validity_seconds: 100,
        floor: None,
    }
}
fn authenticated() -> AuthenticatedManifest {
    AuthenticatedManifest::from_verified_payload(store().verify_json(VALID, &policy()).unwrap())
        .unwrap()
}

#[test]
fn independent_signature_and_manifest_and_artifact_chain_succeeds() {
    let authenticated = authenticated();
    assert_eq!(authenticated.manifest(), &good_manifest());
    check_good(authenticated.manifest()).unwrap();
    let report = authenticated.verify_reader(&lcg_payload(64)[..]).unwrap();
    assert_eq!(report.sha256(), known_sha256(64));
    assert_eq!(authenticated.release_floor().sequence, 7);
    authenticated.assert_current(149).unwrap();
}

#[test]
fn real_signature_does_not_make_an_invalid_manifest_valid() {
    for (envelope, field) in [
        (include_str!("vectors/invalid-grammar.json"), "version"),
        (include_str!("vectors/unknown-field.json"), "unrecognized"),
        (include_str!("vectors/duplicate-key.json"), "sha256"),
    ] {
        let proof = store()
            .verify_json(envelope, &policy())
            .expect("OpenSSL signature is genuine");
        let error = AuthenticatedManifest::from_verified_payload(proof).unwrap_err();
        match error {
            PackageError::InvalidField { field: actual, .. } => assert_eq!(actual, field),
            PackageError::UnknownField { field: actual } => assert_eq!(actual, field),
            PackageError::DuplicateKey { key } => assert_eq!(key, field),
            other => panic!("unexpected schema rejection: {other:?}"),
        }
    }
}

#[test]
fn replaced_manifest_cannot_reuse_authenticated_payload_proof() {
    let authenticated = authenticated();
    // A consumer may clone metadata for display, but cannot mutate proof-bound state.
    let mut detached = authenticated.manifest().clone();
    detached.sha256 = "0".repeat(64);
    assert_ne!(detached, *authenticated.manifest());
    assert_eq!(authenticated.manifest().sha256, known_sha256(64));
    authenticated.verify_reader(&lcg_payload(64)[..]).unwrap();

    let mut envelope: serde_json::Value = serde_json::from_str(VALID).unwrap();
    let mut claims: serde_json::Value =
        serde_json::from_str(envelope["payload"].as_str().unwrap()).unwrap();
    claims["manifest_json"] = serde_json::Value::String(serde_json::to_string(&detached).unwrap());
    envelope["payload"] = serde_json::Value::String(claims.to_string());
    assert_eq!(
        store()
            .verify_json(&envelope.to_string(), &policy())
            .unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn preinstall_expiry_and_backwards_time_are_rejected() {
    let authenticated = authenticated();
    assert_eq!(authenticated.assert_current(150), Err(Error::Expired));
    assert_eq!(authenticated.assert_current(99), Err(Error::Policy));
}

#[test]
fn persisted_floor_remains_bound_to_exact_authenticated_release() {
    let authenticated = authenticated();
    let mut policy = policy();
    policy.floor = Some(authenticated.release_floor());
    store().verify_json(VALID, &policy).unwrap();
    policy.floor.as_mut().unwrap().sequence = 8;
    assert_eq!(
        store().verify_json(VALID, &policy).unwrap_err(),
        Error::Rollback
    );
}

#[test]
fn tampering_signed_payload_is_rejected_before_manifest_use() {
    let mut envelope: serde_json::Value = serde_json::from_str(VALID).unwrap();
    let payload = envelope["payload"].as_str().unwrap().to_owned() + " ";
    envelope["payload"] = serde_json::Value::String(payload);
    assert_eq!(
        store()
            .verify_json(&envelope.to_string(), &policy())
            .unwrap_err(),
        Error::InvalidSignature
    );
}
