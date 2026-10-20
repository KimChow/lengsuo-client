//! 第 4 层：**Rust↔Rust 端到端**（回环 TCP）与 REALITY 准入负例。

use crate::support::{e2e, ClientIdentity, ServerIdentity};

use lengsuo_vless::reality::server::RealityReject;

/// 固定的「现在」（Unix 秒），用于服务端的时间窗判定。
const NOW: u32 = 1_705_618_800;

/// 服务端身份与客户端身份的固定种子（假值）。
fn identities() -> (ServerIdentity, ClientIdentity) {
    let server = ServerIdentity::new(lengsuo_vless::reality::hash::sha::sha256(b"server-seed"));
    let client = ClientIdentity::new(lengsuo_vless::reality::hash::sha::sha256(b"client-seed"));
    (server, client)
}

/// 端到端：握手成功 + REALITY 认证成功 + 双向载荷**逐字节**一致。
#[tokio::test]
async fn reality_rust_to_rust_handshake_and_payload() {
    let (server, client) = identities();
    let client_payload: Vec<u8> = (0u32..4096).map(|i| (i % 251) as u8).collect();
    let server_payload: Vec<u8> = (0u32..1024).map(|i| (i % 253) as u8).collect();

    let result = e2e::run_handshake(
        &server,
        &client,
        server.short_id,
        &server.server_name,
        NOW,
        &client_payload,
        &server_payload,
    )
    .await
    .expect("端到端握手应成功");

    // 服务端必须逐字节收到客户端载荷。
    assert_eq!(result.server_received, client_payload);
    // 客户端必须逐字节收到服务端载荷。
    assert_eq!(result.client_received, server_payload);
    // 服务端叶子证书必须存在且是 Ed25519 自签证书。
    assert!(!result.peer_certificate.is_empty());
}

/// 端到端：空载荷也必须能正确交换（零长度记录）。
#[tokio::test]
async fn reality_rust_to_rust_handshake_empty_payload() {
    let (server, client) = identities();
    let result = e2e::run_handshake(
        &server,
        &client,
        server.short_id,
        &server.server_name,
        NOW,
        b"",
        b"",
    )
    .await
    .expect("端到端握手应成功");
    assert!(result.server_received.is_empty());
    assert!(result.client_received.is_empty());
}

/// REALITY 准入负例：错误的短 ID 必须被拒绝。
#[test]
fn reality_rejects_wrong_short_id() {
    let (server, client) = identities();
    let wrong_short_id = *b"87654321";
    let hello = e2e::build_hello(&server, &client, wrong_short_id, &server.server_name, NOW);
    let err = e2e::authenticate(&server, &hello, NOW).expect_err("错短 ID 必须被拒绝");
    assert_eq!(err, RealityReject::ShortIdNotAllowed);
}

/// REALITY 准入负例：错误的 SNI（server_name）必须被拒绝。
#[test]
fn reality_rejects_wrong_server_name() {
    let (server, client) = identities();
    let hello = e2e::build_hello(
        &server,
        &client,
        server.short_id,
        "not-allowed.example.com",
        NOW,
    );
    let err = e2e::authenticate(&server, &hello, NOW).expect_err("错 SNI 必须被拒绝");
    assert_eq!(err, RealityReject::ServerNameNotAllowed);
}

/// REALITY 准入负例：重放的认证载荷（时间窗外）必须被拒绝。
#[test]
fn reality_rejects_replayed_auth_payload() {
    let (server, client) = identities();
    // 用一个很早的时间戳构造 ClientHello（模拟重放旧包）。
    let hello = e2e::build_hello(
        &server,
        &client,
        server.short_id,
        &server.server_name,
        1_000_000_000,
    );
    // 服务端当前时间远在窗口之外（窗口 60 秒）。
    let err = e2e::authenticate(&server, &hello, NOW).expect_err("重放的认证载荷必须被拒绝");
    assert_eq!(err, RealityReject::TimeOutOfRange);
    // 同一份字节在它自己的时间戳上仍然通过（证明拒绝原因是时间窗）。
    assert!(e2e::authenticate(&server, &hello, 1_000_000_000).is_ok());
}

/// REALITY 准入负例：错口令（服务端私钥不同 ⇒ `auth_key` 不同）必须被拒绝。
#[test]
fn reality_rejects_wrong_password() {
    let (server, client) = identities();
    let hello = e2e::build_hello(&server, &client, server.short_id, &server.server_name, NOW);
    // 用另一套服务端身份（等价于错口令）去认证。
    let other = ServerIdentity::new(lengsuo_vless::reality::hash::sha::sha256(
        b"other-server-seed",
    ));
    let err = e2e::authenticate(&other, &hello, NOW).expect_err("错口令必须被拒绝");
    assert_eq!(err, RealityReject::AuthRejected);
}

/// REALITY 准入负例：篡改 ClientHello 的认证密文必须被拒绝。
#[test]
fn reality_rejects_tampered_client_hello() {
    let (server, client) = identities();
    let mut hello = e2e::build_hello(&server, &client, server.short_id, &server.server_name, NOW);
    // 翻转认证密文区的一个 bit（`raw[39..71]`）。
    hello.raw[39] ^= 0x01;
    let err = e2e::authenticate(&server, &hello, NOW).expect_err("被篡改的 ClientHello 必须被拒绝");
    assert_eq!(err, RealityReject::AuthRejected);
}

/// REALITY 准入负例：截断的 ClientHello 必须被拒绝（不得 panic）。
#[test]
fn reality_rejects_truncated_client_hello() {
    let (server, client) = identities();
    let mut hello = e2e::build_hello(&server, &client, server.short_id, &server.server_name, NOW);
    hello.raw.truncate(40);
    let err = e2e::authenticate(&server, &hello, NOW).expect_err("截断的 ClientHello 必须被拒绝");
    assert_eq!(err, RealityReject::BufferTooShort { need: 71, got: 40 });
}
