//! 来源解析的固定向量回放：合法 origin / 非法 origin。

use crate::support::{assert_has_entries, entries, str_field};
use lengsuo_native_host::error::{IdFormatError, OriginError};
use lengsuo_native_host::origin::{parse_extension_id, EXTENSION_ID_LEN, EXTENSION_SCHEME_PREFIX};

#[test]
fn legal_origins_parse_to_expected_extension_id() {
    for item in entries("legal_origins") {
        let name = str_field(item, "name");
        let origin = str_field(item, "origin");
        let expected_id = str_field(item, "extension_id");
        let parsed = parse_extension_id(&origin)
            .unwrap_or_else(|e| panic!("{}：合法 origin 必须能解析：{}", name, e));
        assert_eq!(parsed, expected_id, "{}：解析出的扩展 ID 不符", name);
        assert_eq!(parsed.len(), EXTENSION_ID_LEN, "{}：扩展 ID 长度不对", name);
    }
}

#[test]
fn legal_origins_cover_canonical_slash_uppercase_and_a_second_id() {
    assert_has_entries(
        "legal_origins",
        &[
            "V_ORIGIN_CANONICAL",
            "V_ORIGIN_NO_TRAILING_SLASH",
            "V_ORIGIN_UPPERCASE",
            "V_ORIGIN_SECOND_ID",
        ],
    );
}

#[test]
fn illegal_origins_fail_with_expected_category() {
    for item in entries("illegal_origins") {
        let name = str_field(item, "name");
        let origin = str_field(item, "origin");
        let error = parse_extension_id(&origin).expect_err("非法 origin 必须解析失败");
        match str_field(item, "category").as_str() {
            "not_extension_origin" => match error {
                OriginError::NotExtensionOrigin(got) => {
                    assert_eq!(got, origin, "{}：报错里回显的 origin 不符", name);
                }
                other => panic!("{}：期望 not_extension_origin，实际 {:?}", name, other),
            },
            "invalid_extension_id" => match error {
                OriginError::InvalidExtensionId { id, reason } => {
                    let expected = &item["error"];
                    match str_field(expected, "reason").as_str() {
                        "length" => match reason {
                            IdFormatError::Length { actual } => {
                                assert_eq!(
                                    actual as u64,
                                    expected["actual"].as_u64().unwrap(),
                                    "{}",
                                    name
                                );
                            }
                            other => panic!("{}：期望 length，实际 {:?}", name, other),
                        },
                        "char" => match reason {
                            IdFormatError::Char { char } => {
                                let want = str_field(expected, "char");
                                assert_eq!(char.to_string(), want, "{}", name);
                            }
                            other => panic!("{}：期望 char，实际 {:?}", name, other),
                        },
                        other => panic!("{}：未知失败原因 {}", name, other),
                    }
                    // 报错里回显的是去掉 scheme 前缀后的 ID（可能带尾斜杠）。
                    let after_prefix = origin
                        .strip_prefix(EXTENSION_SCHEME_PREFIX)
                        .unwrap_or_else(|| panic!("{}：该用例必须有 scheme 前缀", name));
                    assert!(
                        after_prefix == id || after_prefix.strip_suffix('/') == Some(id.as_str()),
                        "{}：报错里回显的 ID {:?} 与 origin {:?} 不符",
                        name,
                        id,
                        origin
                    );
                }
                other => panic!("{}：期望 invalid_extension_id，实际 {:?}", name, other),
            },
            other => panic!("{}：未知失败类别 {}", name, other),
        }
    }
}

#[test]
fn illegal_origins_cover_scheme_length_alphabet_and_shape() {
    assert_has_entries(
        "illegal_origins",
        &[
            "V_ORIGIN_WRONG_SCHEME",
            "V_ORIGIN_NO_SCHEME",
            "V_ORIGIN_EMPTY_HOST",
            "V_ORIGIN_SHORT_ID",
            "V_ORIGIN_LONG_ID",
            "V_ORIGIN_BAD_ALPHABET",
            "V_ORIGIN_WITH_PATH",
            "V_ORIGIN_WITH_QUERY",
            "V_ORIGIN_WITH_PORT",
        ],
    );
}
