//! control 面与事件队列路由测试（内存 mock 传输，不 spawn 进程）。
//!
//! 覆盖：未认领 control 请求入队后由上层应答、已注册 subtype handler 内联应答、
//! 未知 subtype（含 `Unknown`）可观测、`control_response` 完成 control pending、
//! `control_notification` 不作隐式匹配、control 载荷必须可摊平为对象、
//! 事件队列满丢最旧并计数。
//!
//! JSON-RPC 面（请求-响应、id 关联、终止语义）见 `transport_client.rs`；
//! 真实子进程见 `stdio_transport.rs`。

use std::time::{Duration, Instant};

use agent_acp::client::{Client, ClientConfig, NextEvent};
use agent_acp::codec::decode_frame;
use agent_acp::control::TopLevel;
use agent_acp::message::RequestId;
use agent_acp::router::ClientEvent;
use agent_acp::transport::{mock_transport, MockPeer};
use agent_acp::ControlSubtype;
use serde_json::json;

const WAIT: Duration = Duration::from_secs(2);

fn client_with(max_events: usize) -> (Client, MockPeer) {
    let (transport, peer) = mock_transport();
    let client = Client::with_config(
        transport,
        ClientConfig {
            max_events,
            poll_interval: Duration::from_millis(5),
        },
    );
    (client, peer)
}

/// 轮询等待条件成立（路由线程异步推进，断言前必须等到）。
fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "等待超时：{what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// 收一帧出站字节并解成顶层归类。
fn recv_frame(peer: &MockPeer) -> TopLevel {
    let bytes = peer.recv_outgoing(WAIT).expect("应有出站帧");
    decode_frame(&bytes).expect("出站帧可解码")
}

#[test]
fn unclaimed_control_request_goes_to_events_then_responds() {
    let (client, peer) = client_with(8);
    peer.feed_line(
        br#"{"type":"control_request","request_id":"req-77","request":{"subtype":"elicitation_create","sessionId":"sess-42"}}"#,
    );
    let NextEvent::Event(ClientEvent::ControlRequest(req)) = client.next_event(WAIT) else {
        panic!("未认领 control 请求应入事件队列");
    };
    assert_eq!(req.request_id, RequestId::String("req-77".into()));
    assert_eq!(req.request.subtype, ControlSubtype::ElicitationCreate);

    client
        .respond_control(&req.request_id, Ok(json!({"env": "prod"})))
        .expect("应答");
    let TopLevel::ControlResponse(resp) = recv_frame(&peer) else {
        panic!("应答应为 control_response 信封");
    };
    assert_eq!(resp.request_id, RequestId::String("req-77".into()));
    assert_eq!(resp.response["env"], "prod");
}

#[test]
fn control_handler_answers_inline_and_unknown_subtype_is_observable() {
    let (client, peer) = client_with(8);
    client.on_control(ControlSubtype::SessionUpdate, |_| Ok(json!("ack")));
    peer.feed_line(
        br#"{"type":"control_request","request_id":5,"request":{"subtype":"session_update"}}"#,
    );
    let TopLevel::ControlResponse(resp) = recv_frame(&peer) else {
        panic!("已注册 subtype 应自动回 control_response");
    };
    assert_eq!(resp.request_id, RequestId::Number(5));
    assert_eq!(resp.response, json!("ack"));

    // 未注册 subtype（含 Unknown）→ 事件队列，由上层决定。
    peer.feed_line(
        br#"{"type":"control_request","request_id":6,"request":{"subtype":"future_thing"}}"#,
    );
    let NextEvent::Event(ClientEvent::ControlRequest(req)) = client.next_event(WAIT) else {
        panic!("未知 subtype 应入队");
    };
    assert_eq!(req.request.subtype, ControlSubtype::Unknown);
    assert!(!client.is_closed());
}

#[test]
fn control_response_completes_control_pending() {
    let (client, peer) = client_with(8);
    let handle = client
        .send_control_request(
            RequestId::String("c-1".into()),
            ControlSubtype::FsReadTextFile,
            json!({"path": "/tmp/a.txt", "subtype": "should_be_overridden"}),
        )
        .expect("发送 control 请求");
    let TopLevel::ControlRequest(req) = recv_frame(&peer) else {
        panic!("出站应为 control_request 信封");
    };
    assert_eq!(req.request.subtype, ControlSubtype::FsReadTextFile);
    assert_eq!(req.request.payload["path"], "/tmp/a.txt");
    // 载荷里的 subtype 键被剔除：不产生重复键。
    assert!(req.request.payload.get("subtype").is_none());

    peer.feed_json(&json!({
        "type": "control_response", "request_id": "c-1", "response": {"content": "hi"}
    }));
    let value = handle.wait_timeout(WAIT).expect("未超时").expect("成功");
    assert_eq!(value["content"], "hi");
}

#[test]
fn control_notification_is_an_event_not_an_implicit_reply() {
    let (client, peer) = client_with(8);
    let handle = client
        .send_control_request(
            RequestId::Number(1),
            ControlSubtype::TerminalCreate,
            json!({}),
        )
        .expect("发送");
    // 对端以 control_notification 形态回传完成（互通二态）：不得隐式匹配 pending。
    peer.feed_json(
        &json!({"type": "control_notification", "subtype": "terminal_create", "requestId": 1}),
    );
    let NextEvent::Event(ClientEvent::ControlNotification(n)) = client.next_event(WAIT) else {
        panic!("control_notification 应入事件队列");
    };
    assert_eq!(n.payload["subtype"], "terminal_create");
    assert!(
        handle.wait_timeout(Duration::from_millis(80)).is_err(),
        "未做隐式匹配时 pending 应超时（由上层按 request_id 关联）"
    );
    assert_eq!(client.unknown_id_count(), 0);
}

/// 出站编码器对无法摊平的 control 载荷拒绝（不写半帧、不留 pending）。
#[test]
fn control_payload_must_be_object() {
    let (client, peer) = client_with(8);
    let err = client
        .send_control_request(
            RequestId::Number(1),
            ControlSubtype::SessionUpdate,
            json!([1, 2]),
        )
        .expect_err("数组载荷必须拒绝");
    assert!(matches!(err, agent_acp::Error::MalformedMessage { .. }));

    // 拒绝后不得残留 pending：同一 id 再发可正常关联。
    let handle = client
        .send_control_request(
            RequestId::Number(1),
            ControlSubtype::SessionUpdate,
            json!({}),
        )
        .expect("重发");
    let TopLevel::ControlRequest(_) = recv_frame(&peer) else {
        panic!("应出 control_request");
    };
    peer.feed_json(&json!({"type": "control_response", "request_id": 1, "response": 1}));
    assert!(handle.wait_timeout(WAIT).expect("未超时").is_ok());
}

#[test]
fn bounded_event_queue_drops_oldest_and_counts() {
    let (client, peer) = client_with(2);
    for i in 1..=5 {
        peer.feed_json(&json!({
            "jsonrpc": "2.0", "method": "session/update",
            "params": {"sessionId": format!("s-{i}"), "update": {"sessionUpdate": "current_mode", "modeId": "plan"}}
        }));
    }
    wait_until("丢最旧计数 = 3", || client.dropped_event_count() == 3);
    assert_eq!(client.max_events(), 2);

    // 队列只剩最后两条（s-4、s-5）。
    let mut kept = Vec::new();
    while let Some(ev) = client.poll_event() {
        kept.push(ev);
    }
    assert_eq!(kept.len(), 2, "容量上限必须硬生效");
    let ids: Vec<String> = kept
        .iter()
        .map(|ev| match ev {
            ClientEvent::Notification(n) => n.params.as_ref().expect("params")["sessionId"]
                .as_str()
                .expect("sessionId")
                .to_string(),
            other => panic!("应为通知，得到 {other:?}"),
        })
        .collect();
    assert_eq!(ids, vec!["s-4".to_string(), "s-5".to_string()]);
}
