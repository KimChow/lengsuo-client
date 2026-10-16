use lengsuo_browser_signature::{Error, TrustStore, VerificationPolicy};
use serde_json::json;

// Independently generated with OpenSSL Ed25519/pkeyutl. Synthetic seed byte 11
// repeated 32 times; this public identity is for tests, never production.
const PUBLIC_KEY: &str = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a";
const SIGNATURE: &str = "5c15145d4dcc3f787ca9a3f5ed673238a36eed648c6639d77546389bca132aa6678efd0e1cdf738793aa1b53bee547b3a649afbc321b25741b469576044c7a02";
const PAYLOAD: &str = r#"{"schema_version":1,"sequence":7,"issued_at_unix":90,"expires_at_unix":150,"manifest_json":"{}"}"#;

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

fn envelope(payload: &str) -> String {
    json!({"schema_version":1,"key_id":"release-a","payload":payload,
           "signature_hex":SIGNATURE})
    .to_string()
}

#[test]
fn accepts_independent_signature_and_exact_message_digest() {
    let verified = store().verify_json(&envelope(PAYLOAD), &policy()).unwrap();
    assert_eq!(verified.sequence(), 7);
    assert_eq!(
        hex::encode(verified.release_floor().envelope_digest),
        "0ac19c05edbe8c4e53585d68c2b88a8db961c324c4f668e7a8be2ca65100dbfd"
    );
}

#[test]
fn semantic_json_equivalence_does_not_rewrite_signed_bytes() {
    let equivalent_json = format!(" {PAYLOAD}");
    assert_eq!(
        store()
            .verify_json(&envelope(&equivalent_json), &policy())
            .unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn download_delay_and_backwards_time_cannot_extend_validity() {
    let verified = store().verify_json(&envelope(PAYLOAD), &policy()).unwrap();
    verified.assert_current(100).unwrap();
    verified.assert_current(149).unwrap();
    assert_eq!(verified.assert_current(150), Err(Error::Expired));
    assert_eq!(verified.assert_current(99), Err(Error::Policy));
}
