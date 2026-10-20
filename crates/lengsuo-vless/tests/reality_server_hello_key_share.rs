//! ServerHello `key_share` 解析的独立回归用例（对齐 D-1）。
//!
//! 参考 `xtls/reality` `handshake_messages.go:952-964`
//! （`serverHelloMsg.unmarshal` 的 `case extensionKeyShare`）：
//! ServerHello 的 `key_share` 是**单值** `KeyShareEntry`
//! （`group(2) + uint16 长度前缀的 key`），**没有** ClientHello 的
//! 外层 `client_shares` 列表。两个方向必须用不同的解析器。

use lengsuo_vless::reality::tls13::handshake::build_server_hello;
use lengsuo_vless::reality::tls13::messages::{
    build_client_hello, parse_client_hello, parse_handshake, parse_server_hello,
    parse_server_key_share, ClientHelloParams, MessageError, ServerKeyShare,
    CIPHER_SUITE_AES_128_GCM_SHA256, GROUP_X25519, LEGACY_VERSION, VERSION_TLS13,
};

const KEY: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

/// `KeyShareEntry`（ServerHello 单值布局）：`group(2) + uint16 长度 + key`。
fn single_value_ext(group: u16, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + key.len());
    out.extend_from_slice(&group.to_be_bytes());
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(key);
    out
}

/// `client_shares`（ClientHello 列表布局）：`uint16 列表长度 + (group + uint16 + key)`。
fn list_ext(entries: &[(u16, &[u8])]) -> Vec<u8> {
    let mut entries_bytes = Vec::new();
    for (group, key) in entries {
        entries_bytes.extend_from_slice(&single_value_ext(*group, key));
    }
    let mut out = Vec::with_capacity(2 + entries_bytes.len());
    out.extend_from_slice(&(entries_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&entries_bytes);
    out
}

/// 手搓一条 ServerHello 载荷，`key_share` 扩展体由调用方给定（构造畸形输入用）。
fn server_hello_body_with_key_share(key_share_ext: &[u8]) -> Vec<u8> {
    let mut exts = Vec::new();
    // supported_versions
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&VERSION_TLS13.to_be_bytes());
    // key_share
    exts.extend_from_slice(&0x0033u16.to_be_bytes());
    exts.extend_from_slice(&(key_share_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(key_share_ext);

    let mut body = Vec::new();
    body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(&[0x5au8; 32]);
    body.push(0); // session_id 长度 0
    body.extend_from_slice(&CIPHER_SUITE_AES_128_GCM_SHA256.to_be_bytes());
    body.push(0); // compression_method = null
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    body
}

/// 1. 单值布局必须被准确解析：group 与公钥逐字节一致。
///
/// 改之前这里会被当成列表长度（`0x001d` = 29），在完整 ServerHello 上
/// 直接 `Truncated`；单值解析器直接调用时也会读错布局。
#[test]
fn server_hello_single_value_key_share_parses() {
    let ext_data = single_value_ext(GROUP_X25519, &KEY);
    assert_eq!(
        parse_server_key_share(&ext_data).expect("单值 key_share 应能解析"),
        ServerKeyShare::Share {
            group: GROUP_X25519,
            key: KEY.to_vec(),
        }
    );

    // 走完整 ServerHello 路径：扩展头 + 单值体。
    let body = server_hello_body_with_key_share(&ext_data);
    let info = parse_server_hello(&body).expect("完整 ServerHello 应能解析");
    assert_eq!(info.x25519_key_share, Some(KEY));
}

/// 2. ClientHello 的列表布局喂给单值解析器必须 fail-closed。
///
/// 不得把外层列表长度当成 group，不得 panic，不得越界读取。
#[test]
fn server_hello_parser_rejects_client_hello_list_format() {
    let list = list_ext(&[(GROUP_X25519, &KEY)]);
    assert_eq!(list.len(), 2 + 2 + 2 + 32);

    let err = parse_server_key_share(&list).expect_err("列表布局必须被拒绝");
    assert!(matches!(
        err,
        MessageError::LengthMismatch | MessageError::MalformedExtension
    ));

    // 完整 ServerHello 里嵌入列表布局同样要报错，而不是静默忽略。
    let body = server_hello_body_with_key_share(&list);
    assert!(parse_server_hello(&body).is_err());
}

/// 2b. 空 key 的 KeyShareEntry 也必须拒绝（参考 ClientHello 侧同样拒绝空 key）。
#[test]
fn server_hello_parser_rejects_empty_key() {
    let ext_data = single_value_ext(GROUP_X25519, &[]);
    assert!(parse_server_key_share(&ext_data).is_err());
}

/// 3. 长度前缀声明 32 但只给 16 字节 ⇒ 截断错误。
#[test]
fn server_hello_truncated_key_share_errors() {
    let mut ext_data = Vec::new();
    ext_data.extend_from_slice(&GROUP_X25519.to_be_bytes());
    ext_data.extend_from_slice(&32u16.to_be_bytes());
    ext_data.extend_from_slice(&KEY[..16]);
    assert_eq!(
        parse_server_key_share(&ext_data),
        Err(MessageError::Truncated)
    );

    assert_eq!(
        parse_server_key_share(&ext_data[..3]),
        Err(MessageError::Truncated)
    );
}

/// 3b. 2 字节扩展体是 HelloRetryRequest 的 `selected_group`（参考 :955-958）。
#[test]
fn server_hello_two_byte_key_share_is_hello_retry_request() {
    assert_eq!(
        parse_server_key_share(&GROUP_X25519.to_be_bytes()).expect("HRR 形态应能解析"),
        ServerKeyShare::HelloRetryRequest {
            selected_group: GROUP_X25519,
        }
    );
}

/// 4. ClientHello 列表解析回归：列表布局行为不变。
#[test]
fn client_hello_list_key_share_still_parses() {
    let params = ClientHelloParams {
        random: [0x33u8; 32],
        session_id: [0u8; 32],
        server_name: "example.com".to_owned(),
        key_share: KEY,
    };
    let hello = build_client_hello(&params);
    let (kind, body, consumed) = parse_handshake(&hello).expect("ClientHello 应能分帧");
    assert_eq!(kind, 1);
    assert_eq!(consumed, hello.len());

    let info = parse_client_hello(body).expect("ClientHello 应能解析");
    assert_eq!(info.x25519_key_share, Some(KEY));
    assert_eq!(info.server_name.as_deref(), Some("example.com"));
}

/// 5. 服务端构造侧（`build_server_hello`）与本卡解析器闭环。
#[test]
fn server_built_server_hello_roundtrips_key_share() {
    let msg = build_server_hello([0x77u8; 32], &[0u8; 32], &KEY);
    let (kind, body, consumed) = parse_handshake(&msg).expect("ServerHello 应能分帧");
    assert_eq!(kind, 2);
    assert_eq!(consumed, msg.len());

    let info = parse_server_hello(body).expect("ServerHello 应能解析");
    assert_eq!(info.random, [0x77u8; 32]);
    assert_eq!(info.x25519_key_share, Some(KEY));
    assert_eq!(info.supported_version, Some(VERSION_TLS13));
}
