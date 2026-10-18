//! JSON shape tests: unknown fields must be rejected, exact field names and
//! lowercase platform tags are required, and hostile JSON must fail closed.

use lengsuo_browser_profile::{Platform, ProfileSpec};

mod support;
use support::spec;

fn json_of(spec: &ProfileSpec) -> serde_json::Value {
    serde_json::to_value(spec).expect("test profile must serialize")
}

fn parse(text: &str) -> ProfileSpec {
    ProfileSpec::from_json_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

#[test]
fn unknown_top_level_field_is_rejected() {
    let mut value = json_of(&spec());
    value
        .as_object_mut()
        .unwrap()
        .insert("proxy_password".to_string(), serde_json::json!("hunter2"));
    let err = ProfileSpec::from_json_str(&value.to_string())
        .expect_err("credential-ish unknown field must be refused");
    assert!(
        err.to_string().contains("unknown field"),
        "expected unknown-field message, got {err}"
    );
}

#[test]
fn future_schema_field_is_not_ignored() {
    // A profile written by a newer client must not be silently accepted here.
    let mut value = json_of(&spec());
    value
        .as_object_mut()
        .unwrap()
        .insert("webgpu".to_string(), serde_json::json!({ "tier": 3 }));
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());
}

#[test]
fn unknown_nested_field_is_rejected() {
    for (path, extra) in [
        ("screen", "refresh_hz"),
        ("hardware", "gpu_vendor"),
        ("locale", "script"),
    ] {
        let mut value = json_of(&spec());
        value[path]
            .as_object_mut()
            .unwrap()
            .insert(extra.to_string(), serde_json::json!(1));
        let text = value.to_string();
        assert!(
            ProfileSpec::from_json_str(&text).is_err(),
            "nested unknown field {path}.{extra} must be refused"
        );
    }
}

#[test]
fn missing_required_field_is_rejected() {
    let mut value = json_of(&spec());
    value.as_object_mut().unwrap().remove("noise_seed_hex");
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());
}

#[test]
fn wrong_field_types_are_rejected() {
    let mut value = json_of(&spec());
    value["schema_version"] = serde_json::json!("1");
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());

    let mut value = json_of(&spec());
    value["screen"]["width"] = serde_json::json!("1920");
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());

    let mut value = json_of(&spec());
    value["environment_id"] = serde_json::json!(123);
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());

    let mut value = json_of(&spec());
    value["screen"]["color_depth"] = serde_json::json!(300);
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());

    let mut value = json_of(&spec());
    value["schema_version"] = serde_json::json!(-1);
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());
}

#[test]
fn noise_seed_must_not_be_a_json_number() {
    // A numeric-looking seed would lose leading zeroes. Parsing a number
    // into the string field fails at the JSON shape layer; a numeric string
    // parses but is then refused by validation. Both entry points must
    // reject, so each case asserts the full parse+validate pipeline.
    let mut value = json_of(&spec());
    value["noise_seed_hex"] = serde_json::json!(0x0123_4567_89ab_cdefu64);
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());

    let mut value = json_of(&spec());
    value["noise_seed_hex"] = serde_json::json!("1.0e16");
    let parsed = ProfileSpec::from_json_str(&value.to_string())
        .expect("numeric string still parses as JSON text");
    assert!(
        parsed.validate().is_err(),
        "a numeric-string seed must fail validation, not be accepted"
    );
}

#[test]
fn platform_tags_are_lowercase_and_closed() {
    let text = serde_json::to_string(&Platform::Macos).unwrap();
    assert_eq!(text, "\"macos\"");
    assert_eq!(serde_json::to_string(&Platform::Ios).unwrap(), "\"ios\"");

    for bad in [
        "\"Windows\"",
        "\"MACOS\"",
        "\"FreeBSD\"",
        "\"android \"",
        "3",
    ] {
        assert!(
            serde_json::from_str::<Platform>(bad).is_err(),
            "platform tag accepted: {bad}"
        );
    }
    assert_eq!(
        serde_json::from_str::<Platform>("\"windows\"").unwrap(),
        Platform::Windows
    );
}

#[test]
fn slots_are_an_object_not_a_sequence() {
    let mut value = json_of(&spec());
    value["slots"] = serde_json::json!([["canvas", 1]]);
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());

    let mut value = json_of(&spec());
    value["slots"]["canvas"] = serde_json::json!("1");
    assert!(ProfileSpec::from_json_str(&value.to_string()).is_err());
}

#[test]
fn empty_or_non_object_input_is_rejected() {
    for text in ["", "   ", "null", "[]", "\"env-1\"", "{}"] {
        assert!(
            ProfileSpec::from_json_str(text).is_err(),
            "accepted non-profile JSON: {text:?}"
        );
    }
}

#[test]
fn valid_profile_parses_and_matches_builder() {
    let original = spec();
    let round = parse(&serde_json::to_string(&original).unwrap());
    assert_eq!(round, original);
    assert_eq!(round.platform, Platform::Windows);
}

#[test]
fn trailing_garbage_is_rejected() {
    let text = format!(
        "{}{}",
        serde_json::to_string(&spec()).unwrap(),
        r#"{"schema_version":1}"#
    );
    assert!(ProfileSpec::from_json_str(&text).is_err());
}
