//! `GET /events` 事件流对 mock WebSocket 网关的真实回环测试。
//!
//! 覆盖 AGENT-KICKOFF.md §2/§3 对事件面的冻结语义：
//! - 一帧一个 JSON，按网关推送顺序逐条交付，`seq` / `kind` / `payload` 不串位。
//! - 握手带 `X-Gateway-Token`，token 不符由网关在握手阶段拒绝（客户端归传输错误）。
//! - 未知 `kind` 与非法帧必须显式失败，不静默丢弃；对端关闭归 `Closed`。
//! - 全部等待都有有限超时，卡住的网关只会得到 `Timeout`。

mod support;

use std::time::Duration;

use lengsuo_shell::gateway::{EventError, EventKind, GatewayClient, GatewayHandshake};
use support::{event_json, EventsBehaviour, MockGateway};

/// 测试专用假 token。
const FAKE: &str = "fake-loopback-token-a";
const WRONG: &str = "fake-loopback-token-b";

fn client_at(addr: std::net::SocketAddr, token: &str) -> GatewayClient {
    GatewayClient::from_handshake(GatewayHandshake {
        port: addr.port(),
        pid: std::process::id(),
        token: token.to_owned(),
    })
    .with_timeout(Duration::from_millis(800))
}

#[tokio::test]
async fn events_deliver_in_order_with_typed_kinds() {
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![
            event_json(1, "s1", "thinking", r#"{"delta":"想"}"#, 1_700_000_000_000),
            event_json(
                2,
                "s1",
                "tool_use",
                r#"{"name":"file:read_all"}"#,
                1_700_000_000_001,
            ),
            event_json(3, "s1", "text", r#"{"delta":"hi"}"#, 1_700_000_000_002),
            event_json(
                4,
                "s1",
                "approval_request",
                r#"{"approval_id":"a1"}"#,
                1_700_000_000_003,
            ),
            event_json(5, "s1", "done", "null", 1_700_000_000_004),
        ],
        expected_token: Some(FAKE.to_owned()),
        close_after_frames: false,
    })
    .await;

    let mut sub = client_at(mock.addr(), FAKE)
        .subscribe_events()
        .await
        .expect("token 正确应完成 WS 握手");

    let mut seqs = Vec::new();
    let mut kinds = Vec::new();
    for _ in 0..5 {
        let ev = sub.next().await.expect("应按顺序取到事件");
        seqs.push(ev.seq);
        kinds.push(ev.kind);
        assert_eq!(ev.session_id, "s1");
    }
    assert_eq!(seqs, vec![1, 2, 3, 4, 5], "seq 需按网关推送顺序交付");
    assert_eq!(
        kinds,
        vec![
            EventKind::Thinking,
            EventKind::ToolUse,
            EventKind::Text,
            EventKind::ApprovalRequest,
            EventKind::Done,
        ]
    );
    sub.close().await.expect("主动关闭不应报错");

    mock.shutdown().await;
}

#[tokio::test]
async fn events_carry_payload_and_remaining_frozen_kinds() {
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![
            event_json(7, "s2", "tool_result", r#"{"result_ref":"r1"}"#, 42),
            event_json(8, "s2", "files", r#"{"paths":["a.rs"]}"#, 43),
            event_json(9, "s2", "session_update", r#"{"status":"idle"}"#, 44),
        ],
        expected_token: None,
        close_after_frames: false,
    })
    .await;

    let mut sub = client_at(mock.addr(), FAKE)
        .subscribe_events()
        .await
        .expect("mock 不校验 token 时也应握手成功");
    let a = sub.next().await.expect("tool_result");
    assert_eq!(a.kind, EventKind::ToolResult);
    assert_eq!(a.payload["result_ref"], "r1");
    assert_eq!(a.ts_ms, 42);
    let b = sub.next().await.expect("files");
    assert_eq!(b.kind, EventKind::Files);
    assert_eq!(b.payload["paths"][0], "a.rs");
    let c = sub.next().await.expect("session_update");
    assert_eq!(c.kind, EventKind::SessionUpdate);
    assert_eq!(c.payload["status"], "idle");
    assert_eq!(c.seq, 9, "会话内序号应原样透传，不由客户端重算");

    mock.shutdown().await;
}

#[tokio::test]
async fn events_unknown_kind_fails_without_silent_drop() {
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![
            event_json(1, "s1", "text", r#"{"delta":"ok"}"#, 1),
            event_json(2, "s1", "quantum_flux", "null", 2),
        ],
        expected_token: None,
        close_after_frames: false,
    })
    .await;

    let mut sub = client_at(mock.addr(), FAKE)
        .subscribe_events()
        .await
        .expect("握手成功");
    let first = sub.next().await.expect("第一帧应正常解析");
    assert_eq!(first.kind, EventKind::Text);
    let err = sub
        .next()
        .await
        .expect_err("未知事件名必须失败，不静默跳过");
    match err {
        EventError::UnknownKind { kind } => assert_eq!(kind, "quantum_flux"),
        other => panic!("期望 UnknownKind，实际 {other:?}"),
    }

    mock.shutdown().await;
}

#[tokio::test]
async fn events_malformed_frames_are_rejected_without_leaking_content() {
    // 帧内容刻意带假凭据样式字符串：解析失败的错误文本不得把它带出来。
    let secret = "MIIB fake-private-key-material";
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![
            r#"{"not":"an event"}"#.to_owned(),
            "this is not json".to_owned(),
            format!(r#"{{"seq":1,"kind":"text","payload":"{secret}"}}"#),
        ],
        expected_token: None,
        close_after_frames: false,
    })
    .await;

    let mut sub = client_at(mock.addr(), FAKE)
        .subscribe_events()
        .await
        .expect("握手成功");
    for _ in 0..3 {
        let err = sub.next().await.expect_err("非法帧必须失败");
        match err {
            EventError::Malformed { reason } => {
                assert!(!reason.contains(secret), "解析摘要不应回显帧载荷内容");
                assert!(!reason.contains('\n'), "摘要应压成一行");
            }
            other => panic!("期望 Malformed，实际 {other:?}"),
        }
    }

    mock.shutdown().await;
}

#[tokio::test]
async fn events_silence_times_out_with_finite_wait() {
    // 握手成功但不推任何帧：单帧等待超时（默认 5s，这里压到 300ms 保持测试有限时长）。
    let mock = MockGateway::events(EventsBehaviour {
        frames: Vec::new(),
        expected_token: None,
        close_after_frames: false,
    })
    .await;
    let mut sub = client_at(mock.addr(), FAKE)
        .subscribe_events()
        .await
        .expect("握手成功")
        .with_frame_timeout(Duration::from_millis(300));
    let err = sub.next().await.expect_err("静默网关应触发帧超时");
    assert!(
        matches!(err, EventError::Timeout),
        "期望 Timeout，实际 {err:?}"
    );
    mock.shutdown().await;
}

#[tokio::test]
async fn events_gateway_close_is_reported_as_closed() {
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![event_json(1, "s1", "done", "null", 1)],
        expected_token: None,
        close_after_frames: true,
    })
    .await;
    let mut sub = client_at(mock.addr(), FAKE)
        .subscribe_events()
        .await
        .expect("握手成功")
        .with_frame_timeout(Duration::from_millis(800));
    assert_eq!(sub.next().await.expect("done 事件").kind, EventKind::Done);
    let err = sub.next().await.expect_err("网关关断后应报 Closed");
    assert!(
        matches!(err, EventError::Closed),
        "期望 Closed，实际 {err:?}"
    );
    mock.shutdown().await;
}

#[tokio::test]
async fn events_handshake_is_rejected_when_token_mismatches() {
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![event_json(1, "s1", "text", "null", 1)],
        expected_token: Some(FAKE.to_owned()),
        close_after_frames: false,
    })
    .await;

    let err = client_at(mock.addr(), WRONG)
        .subscribe_events()
        .await
        .expect_err("token 不符应在握手阶段被拒");
    let text = format!("{err:?}");
    assert!(
        !text.contains(FAKE) && !text.contains(WRONG),
        "握手错误不应回显 token"
    );
    assert!(
        matches!(err, EventError::Transport(_)),
        "期望传输错误（HTTP 拒绝），实际 {err:?}"
    );

    mock.shutdown().await;
}

#[tokio::test]
async fn events_connection_refused_is_transport_error() {
    let mock = MockGateway::events(EventsBehaviour {
        frames: Vec::new(),
        expected_token: None,
        close_after_frames: false,
    })
    .await;
    let addr = mock.addr();
    mock.shutdown().await;

    let err = client_at(addr, FAKE)
        .subscribe_events()
        .await
        .expect_err("无监听端口应失败，不回退任何地址");
    assert!(
        matches!(err, EventError::Transport(_)),
        "期望 Transport，实际 {err:?}"
    );
}
