//! `POST /rpc` 对 mock 本地网关的**真实回环** roundtrip（AGENT-KICKOFF.md §6）。
//!
//! 与 `src/gateway/rpc.rs` 里那 9 条只测信封映射的单元测试分工不同：本文件全程走真
//! socket，断言 `X-Gateway-Token` 头确实上线、请求体形如 `{action, payload}`，以及
//! 成功 / 403 / 404 / 408 / 业务码 / 非法信封 / 挂起 / 断线各条路径的错误映射。
//! 握手文件一侧的链路在 `gateway_handshake.rs`，事件流在 `gateway_events.rs`。
//!
//! 所有 IO 都有有限超时（客户端 800ms，个别路径更短）；token 一律是测试专用假值，
//! 断言用布尔匹配而非等值打印，避免值进失败文本。

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_shell::gateway::{GatewayClient, GatewayHandshake, RpcError};
use serde_json::Value;
use support::{MockGateway, RpcBehaviour};

/// 测试专用假 token（AGENTS.md §3：禁止真实凭据）。
const FAKE: &str = "fake-loopback-token-a";
/// 另一个假 token：模拟「与网关不一致」的客户端侧凭据。
const WRONG: &str = "fake-loopback-token-b";

/// 构造指向 mock 地址的客户端，超时压到 800ms 保证测试有限时长。
fn client_at(addr: SocketAddr, token: &str) -> GatewayClient {
    GatewayClient::from_handshake(GatewayHandshake {
        port: addr.port(),
        pid: std::process::id(),
        token: token.to_owned(),
    })
    .with_timeout(Duration::from_millis(800))
}

/// mock 记录的第 N 条请求是否带上了预期的假 token（不打印 token 值本身）。
fn token_matches(seen: &[support::SeenRequest], idx: usize, want: &str) -> bool {
    seen.get(idx)
        .and_then(|r| r.token.as_deref())
        .is_some_and(|t| t == want)
}

#[tokio::test]
async fn rpc_success_returns_data_and_puts_token_on_the_wire() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: r#"{"sessions":[{"id":"s1"}]}"#,
        }],
        Some(FAKE.to_owned()),
    )
    .await;

    let data = client_at(mock.addr(), FAKE)
        .session_list()
        .await
        .expect("code==0 信封应返回 data");
    assert_eq!(data["sessions"][0]["id"], "s1");

    let seen = mock.seen();
    assert_eq!(seen.len(), 1, "一次 RPC 应产生一条请求");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/rpc");
    assert!(
        token_matches(&seen, 0, FAKE),
        "X-Gateway-Token 头未随请求上线"
    );
    let body: Value = serde_json::from_str(&seen[0].body).expect("请求体应为 JSON");
    assert_eq!(body["action"], "session:list");
    assert_eq!(body["payload"], Value::Null);

    mock.shutdown().await;
}

#[tokio::test]
async fn rpc_payload_shape_survives_the_loopback() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: r#"{"accepted":true}"#,
        }],
        Some(FAKE.to_owned()),
    )
    .await;

    let c = client_at(mock.addr(), FAKE);
    c.session_send("s1", "hello")
        .await
        .expect("session:send 应成功");
    c.approval_respond("s1", "a1", "allow")
        .await
        .expect("approval:respond 应成功");

    let seen = mock.seen();
    assert_eq!(seen.len(), 2, "每请求一条连接");
    let first: Value = serde_json::from_str(&seen[0].body).expect("请求体应为 JSON");
    assert_eq!(first["action"], "session:send");
    assert_eq!(first["payload"]["id"], "s1");
    assert_eq!(first["payload"]["content"], "hello");
    let second: Value = serde_json::from_str(&seen[1].body).expect("请求体应为 JSON");
    assert_eq!(second["action"], "approval:respond");
    assert_eq!(second["payload"]["decision"], "allow");
    assert!(
        token_matches(&seen, 0, FAKE) && token_matches(&seen, 1, FAKE),
        "两次请求都应带 token 头"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn rpc_http_403_on_token_mismatch_is_unauthorized() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: "null",
        }],
        Some(FAKE.to_owned()),
    )
    .await;

    let err = client_at(mock.addr(), WRONG)
        .sys_ping()
        .await
        .expect_err("token 不符应被网关拒绝");
    assert!(
        matches!(err, RpcError::Unauthorized),
        "403 应映射为 Unauthorized，实际为 {err:?}"
    );
    let seen = mock.seen();
    assert!(
        token_matches(&seen, 0, WRONG),
        "网关应收到客户端实际携带的那个 token"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn rpc_envelope_404_is_action_not_found_but_raw_404_stays_http() {
    let mock = MockGateway::rpc(
        vec![
            RpcBehaviour::Envelope {
                code: 404,
                msg: "browser:open",
                data: "null",
            },
            RpcBehaviour::Raw {
                status: 404,
                body: "no such route",
            },
        ],
        None,
    )
    .await;
    let c = client_at(mock.addr(), FAKE);

    let err = c
        .rpc("browser:open", Value::Null)
        .await
        .expect_err("未注册动作应失败");
    assert!(
        matches!(err, RpcError::ActionNotFound { .. }),
        "信封 code 404 应映射 ActionNotFound，实际 {err:?}"
    );

    let err = c.session_list().await.expect_err("裸 404 应失败");
    assert!(
        matches!(err, RpcError::Http { status: 404, .. }),
        "无信封的 HTTP 404 应保持 Http，实际 {err:?}"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn rpc_timeout_arrives_from_envelope_408_raw_408_and_a_hang() {
    // 信封 408：网关内部超时，仍是一条正常 HTTP 响应。
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 408,
            msg: "gateway timeout",
            data: "null",
        }],
        None,
    )
    .await;
    let err = client_at(mock.addr(), FAKE)
        .session_get("s1")
        .await
        .expect_err("信封 408 应失败");
    assert!(
        matches!(err, RpcError::Timeout),
        "信封 code 408 应映射 Timeout，实际 {err:?}"
    );
    mock.shutdown().await;

    // 裸 HTTP 408：无信封，同样判超时。
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Raw {
            status: 408,
            body: "timeout",
        }],
        None,
    )
    .await;
    let err = client_at(mock.addr(), FAKE)
        .tool_list()
        .await
        .expect_err("裸 408 应失败");
    assert!(
        matches!(err, RpcError::Timeout),
        "HTTP 408 应映射 Timeout，实际 {err:?}"
    );
    mock.shutdown().await;

    // 网关收下请求但不回任何字节：客户端侧等待超时。
    let mock = MockGateway::rpc(vec![RpcBehaviour::Hang], None).await;
    let err = client_at(mock.addr(), FAKE)
        .config_get("theme")
        .await
        .expect_err("挂起的网关应触发超时");
    assert!(
        matches!(err, RpcError::Timeout),
        "客户端等待超时应映射 Timeout，实际 {err:?}"
    );
    mock.shutdown().await;
}

#[tokio::test]
async fn rpc_business_and_malformed_envelopes_are_distinguished() {
    let mock = MockGateway::rpc(
        vec![
            RpcBehaviour::Envelope {
                code: 1042,
                msg: "会话不存在",
                data: "null",
            },
            RpcBehaviour::Raw {
                status: 200,
                body: "<html>not json</html>",
            },
            RpcBehaviour::Raw {
                status: 500,
                body: "boom",
            },
        ],
        None,
    )
    .await;
    let c = client_at(mock.addr(), FAKE);

    let err = c.session_get("nope").await.expect_err("业务码应失败");
    match err {
        RpcError::Business { code, .. } => assert_eq!(code, 1042),
        other => panic!("期望 Business，实际 {other:?}"),
    }
    let err = c.session_list().await.expect_err("200 + 非 JSON 应失败");
    assert!(
        matches!(err, RpcError::MalformedEnvelope(_)),
        "期望 MalformedEnvelope，实际 {err:?}"
    );
    let err = c.tool_list().await.expect_err("裸 500 应失败");
    assert!(
        matches!(err, RpcError::Http { status: 500, .. }),
        "期望 Http(500)，实际 {err:?}"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn rpc_invalid_action_is_rejected_before_any_connection() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: "null",
        }],
        None,
    )
    .await;

    let err = client_at(mock.addr(), FAKE)
        .rpc("browser open", Value::Null)
        .await
        .expect_err("非法动作名应在联网之前被拒");
    assert!(
        matches!(err, RpcError::InvalidAction(_)),
        "期望 InvalidAction，实际 {err:?}"
    );
    assert!(mock.seen().is_empty(), "客户端侧拒绝不应产生连接");

    mock.shutdown().await;
}

#[tokio::test]
async fn rpc_connection_refused_is_transport_error_not_silent_fallback() {
    // 起一个 mock 只为拿到一个确定空闲的端口，随后关掉：客户端必须 fail-closed。
    let mock = MockGateway::rpc(vec![RpcBehaviour::Hang], None).await;
    let addr = mock.addr();
    mock.shutdown().await;

    let err = client_at(addr, FAKE)
        .sys_ping()
        .await
        .expect_err("无网关监听应失败");
    assert!(
        matches!(err, RpcError::Transport(_)),
        "期望 Transport，实际 {err:?}"
    );
}

#[tokio::test]
async fn token_never_leaks_into_debug_or_error_text() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: "null",
        }],
        Some(FAKE.to_owned()),
    )
    .await;
    let handshake = GatewayHandshake {
        port: mock.addr().port(),
        pid: std::process::id(),
        token: FAKE.to_owned(),
    };
    assert!(
        !format!("{handshake:?}").contains(FAKE),
        "握手 Debug 需对 token 脱敏"
    );

    let c = client_at(mock.addr(), WRONG);
    assert!(!format!("{c:?}").contains(WRONG), "客户端 Debug 需脱敏");
    let err = c.session_list().await.expect_err("token 不符应失败");
    let text = format!("{err:?}");
    assert!(
        !text.contains(FAKE) && !text.contains(WRONG),
        "RPC 错误文本不应回显任何 token"
    );

    mock.shutdown().await;
}
