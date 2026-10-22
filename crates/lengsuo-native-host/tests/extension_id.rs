//! 扩展 ID **严格值校验**的 API 级用例 + 固定向量回放。
//!
//! 覆盖派卡要求：
//! - 正例：本 ID（任意大小写）通过；
//! - 反例：**格式合法但值不同**（首字符 `e`→`f`）必须是 `NotOurExtension`，
//!   ⛔ 不能被降级成格式错误、也不能被放行；
//! - 长度不对 / 含 `a`–`p` 外字符 / 带尾部 `/` ⇒ 格式错误；
//! - 来源字符串形状错误 ⇒ `NotExtensionOrigin`；
//! - 派生算法锚点：`derived_bytes_hex` 与 ID 互为逆运算（不改 ID、不改算法）。

use lengsuo_native_host::error::{IdFormatError, OriginError};
use lengsuo_native_host::extension::{
    require_our_extension, require_our_id, strict_eq, EXTENSION_ID, EXTENSION_ORIGIN,
};
use lengsuo_native_host::origin::EXTENSION_ID_LEN;

fn vector() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/native-host-io-v1.json");
    let text = std::fs::read_to_string(&path).expect("读不到向量文件");
    serde_json::from_str(&text).expect("向量文件必须是合法 JSON")
}

/// 把扩展 ID 还原成 16 字节（每位 `a`..`p` → 0..15，高/低半字节）。
fn id_bytes(id: &str) -> Vec<u8> {
    let digits: Vec<u8> = id
        .bytes()
        .map(|b| {
            let b = b.to_ascii_lowercase();
            assert!(b.is_ascii_lowercase(), "非法字符");
            b - b'a'
        })
        .collect();
    assert_eq!(digits.len(), EXTENSION_ID_LEN);
    digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

#[test]
fn canonical_id_and_origin_are_pinned() {
    assert_eq!(EXTENSION_ID, "ejlmmjamfpkoopjachjhcbdjlddknhok");
    assert_eq!(EXTENSION_ID.len(), 32);
    assert_eq!(
        EXTENSION_ORIGIN,
        "chrome-extension://ejlmmjamfpkoopjachjhcbdjlddknhok/"
    );
    assert!(EXTENSION_ORIGIN.ends_with('/'), "规范 origin 必须带尾斜杠");
}

#[test]
fn derivation_anchor_round_trips() {
    let v = vector();
    let anchor = &v["extension_id"];
    assert_eq!(anchor["canonical"].as_str(), Some(EXTENSION_ID));
    let expected = hex::decode(anchor["derived_bytes_hex"].as_str().unwrap()).unwrap();
    assert_eq!(expected.len(), 16, "派生字节是 16 字节");
    // ⭐ 独立锚点：ID ⇄ SHA256 前 16 字节 互为逆运算。
    assert_eq!(id_bytes(EXTENSION_ID), expected);
}

#[test]
fn strict_value_equality_is_what_it_says() {
    assert!(strict_eq(EXTENSION_ID));
    assert!(strict_eq(&EXTENSION_ID.to_uppercase()));
    // 格式合法但值不同。
    assert!(!strict_eq("fjlmmjamfpkoopjachjhcbdjlddknhok"));
    // 只差最后一位。
    assert!(!strict_eq("ejlmmjamfpkoopjachjhcbdjlddknhom"));
    assert!(!strict_eq(""));
}

#[test]
fn legal_id_vectors_pass() {
    for item in vector()["legal_ids"].as_array().unwrap() {
        let id = item["id"].as_str().unwrap();
        assert_eq!(require_our_id(id), Ok(()), "{} 应通过", item["name"]);
        let origin = format!("chrome-extension://{id}/");
        assert_eq!(
            require_our_extension(&origin),
            Ok(id),
            "{} 的 origin 应通过",
            item["name"]
        );
    }
}

#[test]
fn illegal_id_vectors_fail_with_expected_variant() {
    for item in vector()["illegal_ids"].as_array().unwrap() {
        let name = item["name"].as_str().unwrap();
        let id = item["id"].as_str().unwrap();
        match item["expect"].as_str().unwrap() {
            "not_our_extension" => match require_our_id(id) {
                Err(OriginError::NotOurExtension { got, expected }) => {
                    assert_eq!(got, id, "{}：错误里的实际 ID", name);
                    assert_eq!(expected, EXTENSION_ID);
                    assert_eq!(id.len(), 32, "{}：这条必须是格式合法的", name);
                    assert_ne!(id.to_ascii_lowercase(), EXTENSION_ID);
                }
                other => panic!("{}：应为 NotOurExtension，实际 {:?}", name, other),
            },
            "invalid_format" => match require_our_id(id) {
                Err(OriginError::InvalidExtensionId { .. }) => {}
                other => panic!("{}：应为 InvalidExtensionId，实际 {:?}", name, other),
            },
            other => panic!("向量 expect 未知：{}", other),
        }
    }
}

#[test]
fn well_formed_other_value_is_not_downgraded_to_format_error() {
    let other = "fjlmmjamfpkoopjachjhcbdjlddknhok";
    // 格式层（W3b-1）认得它 —— 这正是「格式校验不能代替值校验」的证据。
    assert!(
        lengsuo_native_host::parse_extension_id(&format!("chrome-extension://{other}/")).is_ok()
    );
    assert_eq!(
        require_our_extension(&format!("chrome-extension://{other}/")),
        Err(OriginError::NotOurExtension {
            got: other.to_owned(),
            expected: EXTENSION_ID,
        })
    );
}

#[test]
fn rejects_bad_shape_and_format() {
    for bad in [
        format!("https://{EXTENSION_ID}/"),
        format!("chrome-extension:/{EXTENSION_ID}/"),
        format!("chrome-extension://{EXTENSION_ID}/x"),
        format!("chrome-extension://{EXTENSION_ID}?a=1"),
        "chrome-extension://".to_owned(),
        "chrome-extension://*/".to_owned(),
    ] {
        assert!(
            matches!(
                require_our_extension(&bad),
                Err(OriginError::NotExtensionOrigin(_))
                    | Err(OriginError::InvalidExtensionId { .. })
            ),
            "{bad} 应被拒绝（形状或格式）"
        );
    }
    // 长度不对 ⇒ 具体是 Length。
    let short = &EXTENSION_ID[..31];
    assert_eq!(
        require_our_extension(&format!("chrome-extension://{short}")),
        Err(OriginError::InvalidExtensionId {
            id: short.to_owned(),
            reason: IdFormatError::Length { actual: 31 },
        })
    );
}

#[test]
fn accepts_origin_with_and_without_trailing_slash() {
    assert!(require_our_extension(EXTENSION_ORIGIN).is_ok());
    // 裸 ID 不是 origin 形状 ⇒ 明确拒绝。
    assert_eq!(
        require_our_extension(EXTENSION_ID),
        Err(OriginError::NotExtensionOrigin(EXTENSION_ID.to_owned()))
    );
    let no_slash = format!("chrome-extension://{EXTENSION_ID}");
    assert_eq!(require_our_extension(&no_slash), Ok(EXTENSION_ID));
}
