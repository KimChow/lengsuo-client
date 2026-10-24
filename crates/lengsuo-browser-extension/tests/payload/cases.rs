//! 用例主体：逐段回放 `payload-v1.json`（期望值全部手写字面量，
//! ⛔ 绝不拿实现输出回灌当期望）。

use lengsuo_browser_extension::message::MessageType;
use lengsuo_browser_extension::payload::{
    AuthQueryResponse, GetPasswordResponse, GetTotpResponse, ListCredentialsResponse,
    PasskeyCreateResponse, PasskeyGetResponse, RecoverResponse, Request, Response,
    RevokePasskeyRefResponse, RiskCheckResponse, SavePasswordResponse,
};
use lengsuo_browser_extension::{
    base64, base64url, client_data_json, decode_request, encode_response, json, verify_nonce_echo,
    ClientDataKind, CredentialItem, CredentialKind, Decision, JsonError, PayloadError,
};
use serde_json::Value;

use super::support;

// ------------------------------------------------------------ requests（解码）

#[test]
fn requests_decode_against_hand_written_vectors() {
    for item in support::section("requests") {
        let name = item["name"].as_str().unwrap();
        let number = item["type"].as_u64().unwrap() as u8;
        let message_type = MessageType::from_u8(number).unwrap();
        let request = decode_request(message_type, item["json"].as_str().unwrap().as_bytes())
            .unwrap_or_else(|error| panic!("{name} 不该失败：{error}"));
        let expect = &item["expect"];
        match request {
            Request::ListCredentials(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.store_id, support::opt_str(&expect["store_id"]), "{name}");
            }
            Request::GetPassword(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.origin, expect["origin"].as_str().unwrap(), "{name}");
                assert_eq!(r.username, support::opt_str(&expect["username"]), "{name}");
            }
            Request::GetTotp(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.r#ref, expect["ref"].as_str().unwrap(), "{name}");
            }
            Request::PasskeyCreate(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.origin, expect["origin"].as_str().unwrap(), "{name}");
                assert_eq!(r.rp_id, expect["rp_id"].as_str().unwrap(), "{name}");
                assert_eq!(r.challenge, expect["challenge"].as_str().unwrap(), "{name}");
                assert_eq!(
                    r.user.id,
                    expect["user"]["id"].as_str().unwrap(),
                    "{name} user.id"
                );
                assert_eq!(
                    r.user.name,
                    expect["user"]["name"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    r.user.display_name,
                    expect["user"]["display_name"].as_str().unwrap(),
                    "{name} user.display_name"
                );
            }
            Request::PasskeyGet(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.origin, expect["origin"].as_str().unwrap(), "{name}");
                assert_eq!(r.rp_id, expect["rp_id"].as_str().unwrap(), "{name}");
                assert_eq!(r.challenge, expect["challenge"].as_str().unwrap(), "{name}");
                assert_eq!(
                    r.allow_ids,
                    support::strings(&expect["allow_ids"]),
                    "{name}"
                );
            }
            Request::SavePassword(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.origin, expect["origin"].as_str().unwrap(), "{name}");
                assert_eq!(r.username, expect["username"].as_str().unwrap(), "{name}");
                assert_eq!(r.password, expect["password"].as_str().unwrap(), "{name}");
            }
            Request::RiskCheck(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.origin, expect["origin"].as_str().unwrap(), "{name}");
            }
            Request::RevokePasskeyRef(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.r#ref, expect["ref"].as_str().unwrap(), "{name}");
            }
            Request::Recover(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    r.recovery_code,
                    expect["recovery_code"].as_str().unwrap(),
                    "{name}"
                );
            }
            Request::AuthQuery(r) => {
                assert_eq!(r.nonce, expect["nonce"].as_u64().unwrap(), "{name}");
                assert_eq!(r.store_id, expect["store_id"].as_str().unwrap(), "{name}");
            }
            Request::UseNativeResponse => {
                assert!(expect["nonce"].is_null(), "{name}：type 10 无 nonce");
                assert_eq!(Request::UseNativeResponse.nonce(), None, "{name}");
            }
        }
    }
}

// ----------------------------------------------------------- responses（编码）

/// 按向量名字构造响应结构（字段值与 `expect` 字节**手工协同**，非回灌）。
fn response_for(name: &str) -> Response {
    match name {
        "list_items" => Response::ListCredentials(ListCredentialsResponse {
            nonce: 7,
            items: vec![
                CredentialItem {
                    id: "cred-1".into(),
                    rp_id: "example.com".into(),
                    kind: CredentialKind::Password,
                    username: Some("kim".into()),
                },
                CredentialItem {
                    id: "cred-2".into(),
                    rp_id: "example.com".into(),
                    kind: CredentialKind::Passkey,
                    username: None,
                },
            ],
        }),
        "list_empty" => Response::ListCredentials(ListCredentialsResponse {
            nonce: 8,
            items: Vec::new(),
        }),
        "get_password" => Response::GetPassword(GetPasswordResponse {
            nonce: 9,
            password: "s3cret-synthetic".into(),
        }),
        "get_totp" => Response::GetTotp(GetTotpResponse {
            nonce: 11,
            code: "123456".into(),
            expires_in: 30,
        }),
        "passkey_create" => Response::PasskeyCreate(PasskeyCreateResponse {
            nonce: 21,
            credential_id: "AAEC".into(),
            cose_key_b64: "AwQF".into(),
            auth_data_b64: "BAY".into(),
            client_data_json_b64: "CAk".into(),
            signature_b64: "DA0".into(),
        }),
        "passkey_get_handle" => Response::PasskeyGet(PasskeyGetResponse {
            nonce: 22,
            credential_id: "AAEC".into(),
            auth_data_b64: "BAY".into(),
            client_data_json_b64: "CAk".into(),
            signature_b64: "DA0".into(),
            user_handle: Some("AwQF".into()),
        }),
        "passkey_get_no_handle" => Response::PasskeyGet(PasskeyGetResponse {
            nonce: 22,
            credential_id: "AAEC".into(),
            auth_data_b64: "BAY".into(),
            client_data_json_b64: "CAk".into(),
            signature_b64: "DA0".into(),
            user_handle: None,
        }),
        "save_password" => Response::SavePassword(SavePasswordResponse {
            nonce: 31,
            ok: true,
        }),
        "risk_check" => Response::RiskCheck(RiskCheckResponse {
            nonce: 41,
            decision: Decision::Allow,
        }),
        "revoke_ref" => Response::RevokePasskeyRef(RevokePasskeyRefResponse {
            nonce: 51,
            ok: true,
        }),
        "recover" => Response::Recover(RecoverResponse {
            nonce: 61,
            ok: false,
        }),
        "auth_query" => Response::AuthQuery(AuthQueryResponse {
            nonce: 71,
            granted: true,
        }),
        other => panic!("未知响应向量 {other}"),
    }
}

#[test]
fn responses_encode_to_hand_written_bytes() {
    for item in support::section("responses") {
        let name = item["name"].as_str().unwrap();
        let expected = item["expect"].as_str().unwrap();
        let bytes = encode_response(&response_for(name));
        assert_eq!(
            bytes,
            expected.as_bytes(),
            "{name}：编码字节与手写期望不一致（键名 / 键序 / 无空格）"
        );
        // 编码产物必须仍是本模块能解析的合法 JSON（形状一致性，非验收往返）。
        assert!(json::parse(&bytes).is_ok(), "{name}：编码产物不是合法 JSON");
    }
}

// --------------------------------------------------------------- nonce 回显

#[test]
fn nonce_echo_is_verified_and_byte_identical() {
    let request =
        decode_request(MessageType::GetTotp, br#"{"nonce":11,"ref":"cred-abc"}"#).unwrap();
    let response = Response::GetTotp(GetTotpResponse {
        nonce: 11,
        code: "123456".into(),
        expires_in: 30,
    });
    assert_eq!(verify_nonce_echo(&request, &response), Ok(()));
    // 「逐字节」：编码后的字节里，nonce 的十进制表示与请求完全一致。
    assert!(encode_response(&response)
        .windows(b"\"nonce\":11".len())
        .any(|window| window == b"\"nonce\":11"));

    let wrong = Response::GetTotp(GetTotpResponse {
        nonce: 12,
        code: "123456".into(),
        expires_in: 30,
    });
    assert!(matches!(
        verify_nonce_echo(&request, &wrong),
        Err(PayloadError::NonceMismatch {
            request: 11,
            response: 12
        })
    ));

    // type 10 请求没有 nonce ⇒ 具名错误（而非 panic / 默认值）。
    let fallback = decode_request(MessageType::UseNativeResponse, b"{}").unwrap();
    assert!(matches!(
        verify_nonce_echo(&fallback, &response),
        Err(PayloadError::Json(JsonError::MissingField("nonce")))
    ));
}

// -------------------------------------------------------------------- 转义

#[test]
fn escapes_decode_and_encode_against_hand_written_literals() {
    for item in support::section("escapes") {
        let name = item["name"].as_str().unwrap();
        let value = json::parse(item["json"].as_str().unwrap().as_bytes())
            .unwrap_or_else(|error| panic!("{name} 不该失败：{error}"));
        assert_eq!(
            value.as_str(),
            Some(item["value"].as_str().unwrap()),
            "{name}：解码值与手写期望不一致"
        );
        assert_eq!(
            json::encode(&value),
            item["encoded"].as_str().unwrap(),
            "{name}：规范编码与手写期望不一致"
        );
    }
}

// ---------------------------------------------------------------- base64url

#[test]
fn base64url_matches_hand_written_vectors_and_rejects_standard() {
    for item in support::section("base64url") {
        let name = item["name"].as_str().unwrap();
        let bytes = hex::decode(item["hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            base64url::encode(&bytes),
            item["url"].as_str().unwrap(),
            "{name}：编码与手写期望不一致"
        );
        assert_eq!(
            base64url::decode(item["url"].as_str().unwrap()).unwrap(),
            bytes,
            "{name}：解码与手写字节不一致"
        );
        // ⭐ 两层锚点：同一字节串，标准 base64 与 base64url **必须**不同；
        // base64url 必须拒绝标准字母表（`+` / `/`）。
        if let Some(standard) = item["standard"].as_str() {
            assert_ne!(standard, item["url"].as_str().unwrap(), "{name}");
            assert_eq!(base64::encode(&bytes), standard, "{name}");
            assert!(
                base64url::decode(standard).is_err(),
                "{name}：base64url 必须拒绝标准 base64 串"
            );
        }
    }
    for item in support::section("base64url_decode_errors") {
        let name = item["name"].as_str().unwrap();
        let error = base64url::decode(item["input"].as_str().unwrap())
            .err()
            .unwrap_or_else(|| panic!("{name} 不该解出来"));
        assert_eq!(
            support::base64url_error_name(&error),
            item["error"].as_str().unwrap(),
            "{name}"
        );
    }
}

// ------------------------------------------------------------ clientDataJSON

#[test]
fn client_data_json_is_byte_exact() {
    for item in support::section("client_data_json") {
        let name = item["name"].as_str().unwrap();
        let kind = match item["kind"].as_str().unwrap() {
            "webauthn.create" => ClientDataKind::Create,
            "webauthn.get" => ClientDataKind::Get,
            other => panic!("{name}：未知 kind {other}"),
        };
        let text = client_data_json(
            kind,
            item["challenge"].as_str().unwrap(),
            item["origin"].as_str().unwrap(),
        );
        assert_eq!(
            text,
            item["expect"].as_str().unwrap(),
            "{name}：clientDataJSON 必须逐字节等于契约模板（键序 / 无空格 / crossOrigin）"
        );
    }
}

// ------------------------------------------------------------------ invalid

#[test]
fn invalid_inputs_fail_with_named_errors() {
    for item in support::section("invalid") {
        let name = item["name"].as_str().unwrap();
        let expected = item["error"].as_str().unwrap();
        if let Some(kind) = item["kind"].as_str() {
            let error = CredentialKind::parse(kind)
                .err()
                .unwrap_or_else(|| panic!("{name} 不该通过"));
            assert_eq!(support::payload_error_name(&error), expected, "{name}");
            continue;
        }
        let bytes = item["json"].as_str().unwrap().as_bytes();
        if let Some(number) = item["type"].as_u64() {
            let message_type = MessageType::from_u8(number as u8).unwrap();
            let error = decode_request(message_type, bytes)
                .err()
                .unwrap_or_else(|| panic!("{name} 不该解出来"));
            assert_eq!(support::payload_error_name(&error), expected, "{name}");
        } else {
            let error = json::parse(bytes)
                .err()
                .unwrap_or_else(|| panic!("{name} 不该解出来"));
            assert_eq!(support::json_error_name(&error), expected, "{name}");
        }
    }
}

// -------------------------------------------------- 超限 / 非 UTF-8（纯代码）

#[test]
fn oversize_and_non_utf8_inputs_fail_closed() {
    use lengsuo_browser_extension::json::{MAX_JSON_BYTES, MAX_JSON_DEPTH};
    let oversize = vec![b'0'; MAX_JSON_BYTES + 1];
    assert!(matches!(
        json::parse(&oversize),
        Err(JsonError::InputTooLong(..))
    ));
    // 字符串里夹了一个非法 UTF-8 字节（0xff）。
    assert!(matches!(
        json::parse(b"\"\xff\""),
        Err(JsonError::NotUtf8(_))
    ));
    // 17 层嵌套 > 自设上限 16。
    let deep: String = "[".repeat(MAX_JSON_DEPTH + 1);
    assert!(matches!(
        json::parse(deep.as_bytes()),
        Err(JsonError::DepthExceeded(..))
    ));
}

// ------------------------------------------------------------- kind 三值口径

#[test]
fn credential_kind_accepts_exactly_three_values() {
    for (text, kind) in [
        ("password", CredentialKind::Password),
        ("totp", CredentialKind::Totp),
        ("passkey", CredentialKind::Passkey),
    ] {
        assert_eq!(CredentialKind::parse(text), Ok(kind), "{text}");
        assert_eq!(kind.as_str(), text);
    }
    // 向量外的兜底：空串与大小写变体都必须拒绝（fail-closed）。
    for bad in ["", "Password", "PASSWORD", "hotp", " passkey"] {
        assert!(CredentialKind::parse(bad).is_err(), "{bad:?} 不该通过");
    }
}

// ------------------------------------------------------- 向量文件结构自检

#[test]
fn vector_sections_are_complete() {
    for section_name in [
        "cross_end",
        "requests",
        "responses",
        "escapes",
        "base64url",
        "base64url_decode_errors",
        "client_data_json",
        "invalid",
    ] {
        assert!(
            !support::section(section_name).is_empty(),
            "段 {section_name} 不能为空"
        );
    }
    // type 0–10 每种至少一条请求向量；type 10 必须是 `{}`。
    let mut covered: Vec<u8> = support::section("requests")
        .iter()
        .map(|item| item["type"].as_u64().unwrap() as u8)
        .collect();
    covered.sort_unstable();
    covered.dedup();
    assert_eq!(covered, (0..=10).collect::<Vec<u8>>());
    let use_native: &Value = support::entry("requests", "use_native_empty_payload");
    assert_eq!(use_native["json"].as_str(), Some("{}"));
}
