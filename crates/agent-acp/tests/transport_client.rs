//! P2 JSON-RPC 路由测试：内存 mock 传输（不 spawn 进程）驱动 [`Client`] 语义面。
//!
//! 覆盖：金向量 round-trip、id 关联与乱序响应、字符串/数字 id 区分、未知 id 与
//! 未知通知存活、畸形帧拒绝但字节流继续、未注册入站请求自动 -32601、handler
//! 应答与错误应答、出站帧即真实 wire 帧、连接终止撤 pending 与事件排空顺序。
//!
//! control 面与事件队列容量见 `control_routing.rs`；真实子进程见
//! `stdio_transport.rs`。

use std::time::{Duration, Instant};

use agent_acp::client::{Client, ClientConfig, NextEvent};
use agent_acp::codec::{decode_frame, decode_message};
use agent_acp::control::TopLevel;
use agent_acp::message::{JsonRpcNotification, JsonRpcRequest, Message, RequestId};
use agent_acp::method;
use agent_acp::router::{ClientEvent, RpcOutcome, ACP_ERROR_CONNECTION_CLOSED};
use agent_acp::transport::{mock_transport, SourceEvent};
use serde_json::{json, Value};

const WAIT: Duration = Duration::from_secs(2);

fn client_with(max_events: usize) -> (Client, agent_acp::transport::MockPeer) {
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
fn recv_frame(peer: &agent_acp::transport::MockPeer) -> TopLevel {
    let bytes = peer.recv_outgoing(WAIT).expect("应有出站帧");
    decode_frame(&bytes).expect("出站帧可解码")
}

#[test]
fn golden_round_trip_initialize() {
    let (client, peer) = client_with(8);
    let params = json!({"protocolVersion": 1, "clientInfo": {"name": "lengsuo-client"}});
    let handle = client
        .send_request(method::INITIALIZE, params.clone())
        .expect("发送");
    assert_eq!(handle.id, RequestId::Number(1));

    // 出站帧 = P1 金向量形态（P1 解码器 + 强类型校验）。
    let TopLevel::Rpc(Message::Request(req)) = recv_frame(&peer) else {
        panic!("出站应为 JSON-RPC 请求");
    };
    assert_eq!(req.method, "initialize");
    assert_eq!(req.params, Some(params));

    // 对端回金向量响应：id 关联回原 handle。
    peer.feed_json(&json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"protocolVersion": 1, "agentInfo": {"name": "codebuddy-cli"}}
    }));
    let outcome = handle.wait_timeout(WAIT).expect("未超时").expect("成功");
    assert_eq!(outcome["agentInfo"]["name"], "codebuddy-cli");
}

#[test]
fn out_of_order_responses_match_their_ids() {
    let (client, peer) = client_with(8);
    let h1 = client
        .send_request(method::INITIALIZE, json!({"protocolVersion": 1}))
        .expect("发送 1");
    let h2 = client
        .send_request(method::SESSION_NEW, json!({"cwd": "/tmp/ws"}))
        .expect("发送 2");
    assert_eq!(h1.id, RequestId::Number(1));
    assert_eq!(h2.id, RequestId::Number(2));

    // 逆序回：先 2 后 1。
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": 2, "result": {"sessionId": "sess-42"}}));
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": 1}}));

    let r1 = h1.wait_timeout(WAIT).expect("1 未超时").expect("1 成功");
    let r2 = h2.wait_timeout(WAIT).expect("2 未超时").expect("2 成功");
    assert_eq!(r1["protocolVersion"], 1);
    assert_eq!(r2["sessionId"], "sess-42");
    assert_eq!(client.unknown_id_count(), 0, "乱序不得误判为未知 id");
}

#[test]
fn string_ids_are_distinct_from_numbers() {
    let (client, peer) = client_with(8);
    let hs = client
        .send_request_id(
            RequestId::String("auth-1".into()),
            method::AUTHENTICATE,
            json!({}),
        )
        .expect("发送");
    let hn = client
        .send_request(method::LOGOUT, Value::Null)
        .expect("发送");
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": "auth-1", "result": {"ok": true}}));
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": 1, "result": {"bye": true}}));
    assert_eq!(hs.wait_timeout(WAIT).expect("s").expect("s")["ok"], true);
    assert_eq!(hn.wait_timeout(WAIT).expect("n").expect("n")["bye"], true);
}

#[test]
fn unknown_response_id_is_counted_not_fatal() {
    let (client, peer) = client_with(8);
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": 999, "result": {}}));
    wait_until("未知 id 计数", || client.unknown_id_count() == 1);

    // 连接存活：后续请求照常往返。
    let handle = client
        .send_request(method::LOGOUT, Value::Null)
        .expect("发送");
    let id = handle.id.clone();
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true}}));
    assert!(handle.wait_timeout(WAIT).expect("未超时").is_ok());
    assert!(!client.is_closed());
}

#[test]
fn unknown_notification_is_enqueued_and_survivable() {
    let (client, peer) = client_with(8);
    peer.feed_json(&json!({"jsonrpc": "2.0", "method": "future/event", "params": {"x": 1}}));
    match client.next_event(WAIT) {
        NextEvent::Event(ClientEvent::Notification(n)) => {
            assert_eq!(n.method, "future/event");
        }
        other => panic!("应为未知通知事件，得到 {other:?}"),
    }
    assert!(!client.is_closed(), "未知通知不得终止连接");
}

#[test]
fn malformed_frames_are_rejected_but_stream_survives() {
    let (client, peer) = client_with(8);
    peer.feed_line(b"{ not json");
    peer.feed_line(b"[1,2]"); // JSON 合法但非可归类形态
    wait_until("畸形帧计数 = 2", || client.bad_frame_count() == 2);

    // 字节流仍对齐：正常往返不受影响。
    let handle = client
        .send_request(method::LOGOUT, Value::Null)
        .expect("发送");
    let id = handle.id.clone();
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true}}));
    assert!(handle.wait_timeout(WAIT).expect("未超时").is_ok());
    assert!(!client.is_closed());
}

#[test]
fn unhandled_inbound_request_answers_method_not_found() {
    let (client, peer) = client_with(8);
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": 42, "method": "session/nope", "params": {}}));
    let TopLevel::Rpc(Message::Response(resp)) = recv_frame(&peer) else {
        panic!("应自动回响应");
    };
    assert_eq!(resp.id, RequestId::Number(42));
    let err = resp.error.expect("应为错误响应");
    assert_eq!(err.code, -32601, "未注册方法必须回 -32601 而非静默丢弃");
    assert!(!client.is_closed());
}

#[test]
fn registered_handler_answers_inbound_request() {
    let (client, peer) = client_with(8);
    client.on_request(method::SESSION_SET_MODE, |req| {
        let mode = req.params.as_ref().expect("params")["modeId"].clone();
        Ok(json!({"applied": mode}))
    });
    peer.feed_json(&json!({
        "jsonrpc": "2.0", "id": "set-1", "method": "session/set_mode",
        "params": {"sessionId": "sess-42", "modeId": "plan"}
    }));
    let TopLevel::Rpc(Message::Response(resp)) = recv_frame(&peer) else {
        panic!("应回响应");
    };
    assert_eq!(resp.id, RequestId::String("set-1".into()));
    assert_eq!(resp.result.expect("result")["applied"], "plan");
}

#[test]
fn closed_drains_pending_and_reports_reason() {
    let (client, peer) = client_with(8);
    let handle = client
        .send_request(method::SESSION_PROMPT, json!({"sessionId": "s"}))
        .expect("发送");
    peer.feed_event(SourceEvent::Closed {
        reason: Some("agent 崩溃".into()),
    });
    let outcome = handle
        .wait_timeout(WAIT)
        .expect("终止必须撤 pending 并唤醒");
    let err = outcome.expect_err("连接终止应为错误结局");
    assert_eq!(err.code, ACP_ERROR_CONNECTION_CLOSED);
    assert!(client.is_closed());
    assert_eq!(client.closed_reason().as_deref(), Some("agent 崩溃"));
    assert_eq!(
        client.next_event(Duration::from_millis(50)),
        NextEvent::Closed
    );
}

#[test]
fn queued_events_survive_until_drained_then_closed() {
    let (client, peer) = client_with(8);
    peer.feed_json(&json!({"jsonrpc": "2.0", "method": "session/update", "params": {}}));
    peer.feed_event(SourceEvent::Closed { reason: None });
    // 终止前入队的事件先取出，之后才是 Closed。
    let first = client.next_event(WAIT);
    assert!(
        matches!(first, NextEvent::Event(ClientEvent::Notification(_))),
        "得到 {first:?}"
    );
    wait_until("closed 置位", || client.is_closed());
    assert_eq!(client.next_event(WAIT), NextEvent::Closed);
    assert_eq!(client.closed_reason(), None, "干净收尾无原因");
}

#[test]
fn next_event_idles_when_quiet_and_send_fails_after_close() {
    let (mut client, _peer) = client_with(8);
    assert_eq!(
        client.next_event(Duration::from_millis(30)),
        NextEvent::Idle
    );
    assert_eq!(client.poll_event(), None);

    client.close();
    assert!(client.is_closed());
    assert!(
        client.send_request(method::LOGOUT, Value::Null).is_err(),
        "终止后不得再写"
    );
    assert_eq!(
        client.next_event(Duration::from_millis(30)),
        NextEvent::Closed
    );
}

#[test]
fn handler_error_becomes_error_response() {
    let (client, peer) = client_with(8);
    client.on_request(method::SESSION_CANCEL, |_| {
        Err(agent_acp::JsonRpcErrorObject {
            code: -32602,
            message: "bad params".into(),
            data: None,
        })
    });
    peer.feed_json(&json!({"jsonrpc": "2.0", "id": 7, "method": "session/cancel"}));
    let TopLevel::Rpc(Message::Response(resp)) = recv_frame(&peer) else {
        panic!("应回响应");
    };
    assert_eq!(resp.error.expect("错误响应").code, -32602);
}

#[test]
fn outbound_notification_frame_is_a_real_wire_frame() {
    let (client, peer) = client_with(8);
    let notif = JsonRpcNotification::new(method::SESSION_CANCEL, json!({"sessionId": "sess-42"}));
    client
        .send_notification(method::SESSION_CANCEL, json!({"sessionId": "sess-42"}))
        .expect("发送通知");
    let bytes = peer.recv_outgoing(WAIT).expect("出站帧");
    let decoded = decode_message(&bytes).expect("解码");
    assert_eq!(decoded, Message::Notification(notif));
    assert!(bytes.ends_with(b"\n"), "行帧必须以换行收尾");

    // 请求帧同款：编码器产物能被 P1 解码器读回。
    let handle = client
        .send_request(method::LOGOUT, Value::Null)
        .expect("发送");
    let req = JsonRpcRequest::new(handle.id.clone(), method::LOGOUT, Value::Null);
    assert_eq!(
        decode_message(&peer.recv_outgoing(WAIT).expect("帧")).expect("解码"),
        Message::Request(req)
    );
    drop(handle);
}

#[test]
fn timeout_cancels_pending_so_late_reply_counts_as_unknown() {
    let (client, peer) = client_with(8);
    let handle = client
        .send_request(method::SESSION_LOAD, json!({}))
        .expect("发送");
    let id = handle.id.clone();
    assert!(
        handle.wait_timeout(Duration::from_millis(30)).is_err(),
        "无响应应超时"
    );

    peer.feed_json(&json!({"jsonrpc": "2.0", "id": id, "result": {}}));
    wait_until("迟到响应计为未知 id", || {
        client.unknown_id_count() == 1
    });
    let _: RpcOutcome = Ok(Value::Null); // 类型别名可用性（编译期）
}
