//! 消息类型表（契约 §5.3）与跨仓编号对照。
//!
//! ⛔ 本文件**不读**向量文件：编号是**手写**的期望值，
//! 用来独立验证「枚举 ⇒ 编号」的映射不被实现悄悄改掉。

use lengsuo_browser_extension::message::{MessageType, HOST_NAME, NATIVE_RESPONSE_FALLBACK_TYPE};

#[test]
fn type_00_is_list_credentials() {
    assert_eq!(MessageType::ListCredentials.to_u8(), 0);
}

#[test]
fn type_01_is_get_password() {
    assert_eq!(MessageType::GetPassword.to_u8(), 1);
}

#[test]
fn type_02_is_get_totp() {
    assert_eq!(MessageType::GetTotp.to_u8(), 2);
}

#[test]
fn type_03_is_passkey_create() {
    assert_eq!(MessageType::PasskeyCreate.to_u8(), 3);
}

#[test]
fn type_04_is_passkey_get() {
    assert_eq!(MessageType::PasskeyGet.to_u8(), 4);
}

#[test]
fn type_05_is_save_password() {
    assert_eq!(MessageType::SavePassword.to_u8(), 5);
}

#[test]
fn type_06_is_risk_check() {
    assert_eq!(MessageType::RiskCheck.to_u8(), 6);
}

#[test]
fn type_07_is_revoke_passkey_ref() {
    assert_eq!(MessageType::RevokePasskeyRef.to_u8(), 7);
}

#[test]
fn type_08_is_recover() {
    assert_eq!(MessageType::Recover.to_u8(), 8);
}

#[test]
fn type_09_is_auth_query() {
    assert_eq!(MessageType::AuthQuery.to_u8(), 9);
}

#[test]
fn type_10_is_use_native_response() {
    assert_eq!(MessageType::UseNativeResponse.to_u8(), 10);
}

#[test]
fn from_u8_round_trips_every_type() {
    for message_type in MessageType::ALL {
        assert_eq!(
            MessageType::from_u8(message_type.to_u8()),
            Some(message_type)
        );
    }
}

#[test]
fn from_u8_rejects_unknown_numbers() {
    for got in [11u8, 12, 100, 254, 255] {
        assert_eq!(MessageType::from_u8(got), None, "编号 {} 必须是未知", got);
    }
}

#[test]
fn the_table_has_exactly_eleven_distinct_types() {
    assert_eq!(MessageType::ALL.len(), 11);
    let mut numbers: Vec<u8> = MessageType::ALL.iter().map(|m| m.to_u8()).collect();
    numbers.sort_unstable();
    assert_eq!(numbers, (0..=10).collect::<Vec<u8>>());
}

#[test]
fn type_10_is_the_only_native_response_fallback() {
    assert!(MessageType::UseNativeResponse.is_native_response_fallback());
    for message_type in MessageType::ALL {
        if message_type == MessageType::UseNativeResponse {
            continue;
        }
        assert!(
            !message_type.is_native_response_fallback(),
            "{} 不是回退信号",
            message_type.name()
        );
    }
    assert_eq!(NATIVE_RESPONSE_FALLBACK_TYPE, 10);
}

#[test]
fn names_match_the_extension_side_keys() {
    // 扩展侧另有一份独立的同协议实现，其 `MSG` 表的键名如下。
    assert_eq!(MessageType::ListCredentials.name(), "LIST_CREDENTIALS");
    assert_eq!(MessageType::GetPassword.name(), "GET_PASSWORD");
    assert_eq!(MessageType::GetTotp.name(), "GET_TOTP");
    assert_eq!(MessageType::PasskeyCreate.name(), "PASSKEY_CREATE");
    assert_eq!(MessageType::PasskeyGet.name(), "PASSKEY_GET");
    assert_eq!(MessageType::SavePassword.name(), "SAVE_PASSWORD");
    assert_eq!(MessageType::RiskCheck.name(), "RISK_CHECK");
    assert_eq!(MessageType::RevokePasskeyRef.name(), "REVOKE_PASSKEY_REF");
    assert_eq!(MessageType::Recover.name(), "RECOVER");
    assert_eq!(MessageType::AuthQuery.name(), "AUTH_QUERY");
    assert_eq!(MessageType::UseNativeResponse.name(), "USE_NATIVE_RESPONSE");
}

#[test]
fn display_renders_the_cross_repo_name() {
    assert_eq!(
        MessageType::UseNativeResponse.to_string(),
        "USE_NATIVE_RESPONSE"
    );
    assert_eq!(MessageType::AuthQuery.to_string(), "AUTH_QUERY");
}

#[test]
fn host_name_is_the_cross_repo_constant() {
    assert_eq!(HOST_NAME, "lengsuo.credential");
}
