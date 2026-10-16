use lengsuo_browser_signature::{signing_bytes, Error, TrustStore, VerificationPolicy};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

// Synthetic test key only. Never a production publisher identity.
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn public(pair: &Ed25519KeyPair) -> [u8; 32] {
    pair.public_key().as_ref().try_into().unwrap()
}

fn claims(sequence: u64, issued: u64, expires: u64, manifest: &str) -> Value {
    json!({"schema_version": 1, "sequence": sequence, "issued_at_unix": issued,
           "expires_at_unix": expires, "manifest_json": manifest})
}

fn envelope(pair: &Ed25519KeyPair, id: &str, payload: Value) -> String {
    envelope_raw(pair, id, &payload.to_string())
}

fn envelope_raw(pair: &Ed25519KeyPair, id: &str, payload: &str) -> String {
    // Independent encoder, deliberately not the production signing_bytes.
    let mut bytes = b"Lengsuo/KernelManifestEnvelope/v1\0".to_vec();
    bytes.extend_from_slice(&(id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload.as_bytes());
    json!({"schema_version": 1, "key_id": id, "payload": payload,
           "signature_hex": hex::encode(pair.sign(&bytes).as_ref())})
    .to_string()
}

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        now_unix: 100,
        maximum_validity_seconds: 100,
        floor: None,
    }
}

fn store(pair: &Ed25519KeyPair) -> TrustStore {
    TrustStore::new([("release-a".into(), public(pair))]).unwrap()
}

#[test]
fn validates_authentic_payload_without_exposing_its_text_in_debug() {
    let pair = key(11);
    let text = envelope(
        &pair,
        "release-a",
        claims(7, 90, 150, "{\"sensitive_marker\":1}"),
    );
    let result = store(&pair).verify_json(&text, &policy()).unwrap();
    assert_eq!(result.manifest_json(), "{\"sensitive_marker\":1}");
    assert_eq!(result.sequence(), 7);
    assert_eq!(result.key_id(), "release-a");
    assert_eq!(result.expires_at_unix(), 150);
    assert!(!format!("{result:?}").contains("sensitive_marker"));
}

#[test]
fn signing_bytes_have_explicit_domain_and_lengths() {
    let bytes = signing_bytes("release-a", "{}").unwrap();
    assert_eq!(hex::encode(bytes), "4c656e6773756f2f4b65726e656c4d616e6966657374456e76656c6f70652f763100000972656c656173652d61000000027b7d");
}

#[test]
fn rejects_missing_duplicate_and_unsafe_trust_roots() {
    assert_eq!(TrustStore::new([]).unwrap_err(), Error::EmptyRoots);
    let root = ("release-a".to_owned(), public(&key(11)));
    assert_eq!(
        TrustStore::new([root.clone(), root]).unwrap_err(),
        Error::DuplicateRoot
    );
    for id in ["", "../key", "a b", "a\n", "a:b"] {
        assert_eq!(
            TrustStore::new([(id.to_owned(), public(&key(11)))]).unwrap_err(),
            Error::KeyId
        );
    }
}

#[test]
fn rejects_untrusted_revoked_and_wrong_keys() {
    let pair = key(11);
    let text = envelope(&pair, "release-a", claims(7, 90, 150, "{}"));
    assert_eq!(
        store(&key(12)).verify_json(&text, &policy()).unwrap_err(),
        Error::InvalidSignature
    );
    let revoked = TrustStore::new([("release-b".into(), public(&key(12)))]).unwrap();
    assert_eq!(
        revoked.verify_json(&text, &policy()).unwrap_err(),
        Error::UnknownKey
    );
    let rotated = TrustStore::new([
        ("release-a".into(), public(&pair)),
        ("release-b".into(), public(&key(12))),
    ])
    .unwrap();
    rotated.verify_json(&text, &policy()).unwrap();
    let next = envelope(&key(12), "release-b", claims(8, 90, 150, "{}"));
    rotated.verify_json(&next, &policy()).unwrap();
}

#[test]
fn rejects_tampered_payload_signature_and_key_id() {
    let pair = key(11);
    let text = envelope(&pair, "release-a", claims(7, 90, 150, "{}"));
    let original: Value = serde_json::from_str(&text).unwrap();
    for (field, value) in [
        ("payload", json!(claims(8, 90, 150, "{}").to_string())),
        ("signature_hex", json!("00".repeat(64))),
    ] {
        let mut modified = original.clone();
        modified[field] = value;
        assert_eq!(
            store(&pair)
                .verify_json(&modified.to_string(), &policy())
                .unwrap_err(),
            Error::InvalidSignature
        );
    }
    // Identical public keys under different ids still cannot be relabelled.
    let roots = TrustStore::new([
        ("release-a".into(), public(&pair)),
        ("release-b".into(), public(&pair)),
    ])
    .unwrap();
    let mut changed = original;
    changed["key_id"] = json!("release-b");
    assert_eq!(
        roots
            .verify_json(&changed.to_string(), &policy())
            .unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn enforces_validity_boundaries_and_policy() {
    let pair = key(11);
    for (issued, expires, expected) in [
        (101, 150, Error::Future),
        (90, 100, Error::Expired),
        (100, 100, Error::Window),
        (150, 90, Error::Window),
        (0, 200, Error::Validity),
    ] {
        let text = envelope(&pair, "release-a", claims(7, issued, expires, "{}"));
        assert_eq!(
            store(&pair).verify_json(&text, &policy()).unwrap_err(),
            expected
        );
    }
    let text = envelope(&pair, "release-a", claims(7, 100, 101, "{}"));
    store(&pair).verify_json(&text, &policy()).unwrap();
    let invalid = VerificationPolicy {
        maximum_validity_seconds: 0,
        ..policy()
    };
    assert_eq!(
        store(&pair).verify_json(&text, &invalid).unwrap_err(),
        Error::Policy
    );
}

#[test]
fn rejects_rollback_and_equivocation_but_allows_same_release_reinstall() {
    let pair = key(11);
    let current = envelope(&pair, "release-a", claims(7, 90, 150, "{}"));
    let verified = store(&pair).verify_json(&current, &policy()).unwrap();
    let policy = VerificationPolicy {
        floor: Some(verified.release_floor()),
        ..policy()
    };
    store(&pair).verify_json(&current, &policy).unwrap();
    let old = envelope(&pair, "release-a", claims(6, 90, 150, "{}"));
    assert_eq!(
        store(&pair).verify_json(&old, &policy).unwrap_err(),
        Error::Rollback
    );
    let conflicting = envelope(&pair, "release-a", claims(7, 90, 150, "{\"other\":1}"));
    assert_eq!(
        store(&pair).verify_json(&conflicting, &policy).unwrap_err(),
        Error::Conflict
    );
    let newer = envelope(&pair, "release-a", claims(8, 90, 150, "{}"));
    store(&pair).verify_json(&newer, &policy).unwrap();
}

#[test]
fn rejects_unknown_or_duplicate_json_fields_and_noncanonical_hex() {
    let pair = key(11);
    let original = envelope(&pair, "release-a", claims(7, 90, 150, "{}"));
    let mut value: Value = serde_json::from_str(&original).unwrap();
    value["unexpected"] = json!(1);
    assert_eq!(
        store(&pair)
            .verify_json(&value.to_string(), &policy())
            .unwrap_err(),
        Error::Envelope
    );
    let duplicate = original.replacen('{', "{\"key_id\":\"release-a\",", 1);
    assert_eq!(
        store(&pair).verify_json(&duplicate, &policy()).unwrap_err(),
        Error::Envelope
    );
    value = serde_json::from_str(&original).unwrap();
    value["signature_hex"] = json!("A0".repeat(64));
    assert_eq!(
        store(&pair)
            .verify_json(&value.to_string(), &policy())
            .unwrap_err(),
        Error::SignatureEncoding
    );
    let mut bad_claims = claims(7, 90, 150, "{}");
    bad_claims["unexpected"] = json!(1);
    let text = envelope(&pair, "release-a", bad_claims);
    assert_eq!(
        store(&pair).verify_json(&text, &policy()).unwrap_err(),
        Error::Claims
    );
    let raw = "{\"schema_version\":1,\"sequence\":6,\"sequence\":7,\"issued_at_unix\":90,\"expires_at_unix\":150,\"manifest_json\":\"{}\"}";
    let text = envelope_raw(&pair, "release-a", raw);
    assert_eq!(
        store(&pair).verify_json(&text, &policy()).unwrap_err(),
        Error::Claims
    );
}

#[test]
fn rejects_oversized_or_empty_payloads_and_zero_sequences() {
    let pair = key(11);
    let too_large = " ".repeat(lengsuo_browser_signature::MAX_ENVELOPE_BYTES + 1);
    assert_eq!(
        store(&pair).verify_json(&too_large, &policy()).unwrap_err(),
        Error::TooLarge
    );
    let manifest = "x".repeat(lengsuo_browser_signature::MAX_MANIFEST_BYTES + 1);
    let text = envelope(&pair, "release-a", claims(7, 90, 150, &manifest));
    assert_eq!(
        store(&pair).verify_json(&text, &policy()).unwrap_err(),
        Error::TooLarge
    );
    let text = envelope(&pair, "release-a", claims(0, 90, 150, "{}"));
    assert_eq!(
        store(&pair).verify_json(&text, &policy()).unwrap_err(),
        Error::Claims
    );
    let text = envelope(&pair, "release-a", claims(7, 90, 150, ""));
    assert_eq!(
        store(&pair).verify_json(&text, &policy()).unwrap_err(),
        Error::Claims
    );
}
