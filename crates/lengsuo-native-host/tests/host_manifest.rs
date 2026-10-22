//! host manifest 渲染：逐字节等于向量里的手写字面量，`allowed_origins` 只含本扩展。
//!
//! ⛔ 期望值是向量文件里**独立手写**的 JSON 文本，不是把渲染结果反过来当期望；
//! 直接按**逐字节相等**比（不折叠空白），因此实现换字段顺序或加空格都会被抓到。

use lengsuo_native_host::manifest::{render_host_manifest, HOST_NAME};

fn vector() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/native-host-io-v1.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("读不到向量文件"))
        .expect("向量文件必须是合法 JSON")
}

#[test]
fn rendered_bytes_equal_the_hand_written_literal() {
    let v = vector();
    let expected = v["host_manifest"]["rendered"].as_str().unwrap();
    assert_eq!(render_host_manifest(), expected);
    // 无尾换行、无首尾空白。
    assert_eq!(render_host_manifest().trim(), render_host_manifest());
}

#[test]
fn rendered_json_has_exactly_two_fields() {
    let v = vector();
    let rendered: serde_json::Value = serde_json::from_str(&render_host_manifest()).unwrap();
    let object = rendered.as_object().unwrap();
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["allowed_origins", "name"]);
    assert_eq!(object["name"].as_str(), Some(HOST_NAME));
    assert_eq!(object["name"].as_str(), Some("lengsuo.credential"));
    assert_eq!(object["name"].as_str(), v["host_manifest"]["name"].as_str());
}

#[test]
fn allowed_origins_is_exactly_our_origin() {
    let rendered: serde_json::Value = serde_json::from_str(&render_host_manifest()).unwrap();
    let origins = rendered["allowed_origins"].as_array().unwrap();
    assert_eq!(origins.len(), 1, "allowed_origins 只允许一项");
    assert_eq!(
        origins[0].as_str(),
        Some("chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/")
    );
    // 逐字节（含引号）也在渲染文本里。
    assert!(render_host_manifest().contains(
        "\"allowed_origins\":[\"chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/\"]"
    ));
}

#[test]
fn no_wildcard_and_trailing_slash_kept() {
    let text = render_host_manifest();
    assert!(!text.contains('*'), "⛔ 不得通配");
    assert!(!text.contains("all_urls"));
    // 每个 origin 都以 `/` 结尾。
    let rendered: serde_json::Value = serde_json::from_str(&text).unwrap();
    for origin in rendered["allowed_origins"].as_array().unwrap() {
        let origin = origin.as_str().unwrap();
        assert!(origin.ends_with('/'), "{origin} 必须带尾斜杠");
        assert!(origin.starts_with("chrome-extension://"));
    }
}

#[test]
fn render_is_stable_across_calls() {
    assert_eq!(render_host_manifest(), render_host_manifest());
}
