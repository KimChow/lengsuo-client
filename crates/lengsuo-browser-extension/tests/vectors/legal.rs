//! 合法帧的向量回放：边界长度 5 条 + 11 种消息类型各 1 条。

use crate::support::assert_legal;

#[test]
fn legal_boundary_len_0() {
    assert_legal("V_BOUNDARY_LEN_0");
}

#[test]
fn legal_boundary_len_1() {
    assert_legal("V_BOUNDARY_LEN_1");
}

#[test]
fn legal_boundary_len_255() {
    assert_legal("V_BOUNDARY_LEN_255");
}

#[test]
fn legal_boundary_len_256() {
    assert_legal("V_BOUNDARY_LEN_256");
}

#[test]
fn legal_boundary_len_65536() {
    assert_legal("V_BOUNDARY_LEN_65536");
}

#[test]
fn legal_type_00_list_credentials() {
    assert_legal("V_TYPE_00_LIST_CREDENTIALS");
}

#[test]
fn legal_type_01_get_password() {
    assert_legal("V_TYPE_01_GET_PASSWORD");
}

#[test]
fn legal_type_02_get_totp() {
    assert_legal("V_TYPE_02_GET_TOTP");
}

#[test]
fn legal_type_03_passkey_create() {
    assert_legal("V_TYPE_03_PASSKEY_CREATE");
}

#[test]
fn legal_type_04_passkey_get() {
    assert_legal("V_TYPE_04_PASSKEY_GET");
}

#[test]
fn legal_type_05_save_password() {
    assert_legal("V_TYPE_05_SAVE_PASSWORD");
}

#[test]
fn legal_type_06_risk_check() {
    assert_legal("V_TYPE_06_RISK_CHECK");
}

#[test]
fn legal_type_07_revoke_passkey_ref() {
    assert_legal("V_TYPE_07_REVOKE_PASSKEY_REF");
}

#[test]
fn legal_type_08_recover() {
    assert_legal("V_TYPE_08_RECOVER");
}

#[test]
fn legal_type_09_auth_query() {
    assert_legal("V_TYPE_09_AUTH_QUERY");
}

#[test]
fn legal_type_10_use_native_response() {
    assert_legal("V_TYPE_10_USE_NATIVE_RESPONSE");
}
