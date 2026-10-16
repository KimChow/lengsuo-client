//! Ambiguous map entries and excessive JSON envelopes fail closed.
use lengsuo_browser_profile::{PoolCatalogV1, ProfileSpecV1};
mod support;

#[test]
fn duplicate_slot_dimension_is_rejected() {
    let text = support::spec().to_json_string().unwrap();
    let duplicate = text.replace("\"slots\":{", "\"slots\":{\"canvas\":2,");
    assert_ne!(text, duplicate);
    assert!(ProfileSpecV1::from_json_str(&duplicate).is_err());
}

#[test]
fn duplicate_catalog_dimension_is_rejected() {
    let text = support::catalog().to_json().unwrap();
    let duplicate = text.replace("\"dimensions\":{", "\"dimensions\":{\"canvas\":[8],");
    assert_ne!(text, duplicate);
    assert!(PoolCatalogV1::from_json_str(&duplicate).is_err());
}

#[test]
fn escaped_duplicate_dimension_is_rejected() {
    let text = support::spec().to_json_string().unwrap();
    let duplicate = text.replace("\"slots\":{", r#""slots":{"canv\u0061s":2,"#);
    assert!(ProfileSpecV1::from_json_str(&duplicate).is_err());
}

#[test]
fn envelope_limits_are_separate_from_native_encoding() {
    use lengsuo_browser_profile::{ProfileError, MAX_CATALOG_JSON_BYTES, MAX_PROFILE_JSON_BYTES};
    let mut text = support::spec().to_json_string().unwrap();
    text.extend(std::iter::repeat_n(
        ' ',
        MAX_PROFILE_JSON_BYTES - text.len(),
    ));
    assert!(text.len() > 4096);
    assert!(ProfileSpecV1::from_json_str(&text).is_ok());
    text.push(' ');
    assert!(matches!(
        ProfileSpecV1::from_json_str(&text),
        Err(ProfileError::JsonTooLarge { .. })
    ));
    let text = " ".repeat(MAX_CATALOG_JSON_BYTES + 1);
    assert!(matches!(
        PoolCatalogV1::from_json_str(&text),
        Err(ProfileError::JsonTooLarge { .. })
    ));
}

#[test]
fn duplicate_pool_ids_have_set_semantics() {
    let text = support::catalog().to_json().unwrap();
    let repeated = text.replace("[1,2,3,4,5,6,7,8]", "[1,1,2,3,4,5,6,7,8]");
    assert_ne!(text, repeated);
    assert_eq!(
        PoolCatalogV1::from_json_str(&text).unwrap(),
        PoolCatalogV1::from_json_str(&repeated).unwrap()
    );
}
