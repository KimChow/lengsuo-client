//! 帧编解码与 control 信封测试（自 golden_vectors.rs 按主题拆出，断言不变）。
//!
//! 覆盖：行帧增量解码状态机（切分/空行/`\r\n`/fail-closed）、非法形态拒绝、
//! control_request/control_notification 信封（18 册 §2 逐字抄录样例）。
//! 方法面金向量见同目录 `golden_vectors.rs`。

use agent_acp::{
    decode_frame, decode_message, encode_frame, ControlSubtype, LineDecoder, Message, RequestId,
    TopLevel,
};
use serde_json::{json, Value};

#[test]
fn control_request_envelope_doc_sample() {
    // 样例：18 册 §2 逐字抄录的信封形态——
    // {type:"control_request", request_id, request:{subtype:"elicitation_create",…}}。
    let sample = r#"{"type":"control_request","request_id":"req-77","request":{"subtype":"elicitation_create","sessionId":"sess-42","message":"选一个分支"}}"#;
    let frame = decode_frame(sample.as_bytes()).expect("解码");
    let TopLevel::ControlRequest(req) = frame else {
        panic!("应为 control_request，得到 {frame:?}");
    };
    assert_eq!(req.request_id, RequestId::String("req-77".into()));
    assert_eq!(req.request.subtype, ControlSubtype::ElicitationCreate);
    assert_eq!(
        req.request.payload.get("message").and_then(Value::as_str),
        Some("选一个分支")
    );

    // 客户端回 control_notification（18 册：完成走通知）。
    let back =
        r#"{"type":"control_notification","subtype":"elicitation_complete","sessionId":"sess-42"}"#;
    let TopLevel::ControlNotification(notif) = decode_frame(back.as_bytes()).expect("解码")
    else {
        panic!("应为 control_notification");
    };
    assert_eq!(
        notif.payload.get("subtype").and_then(Value::as_str),
        Some("elicitation_complete")
    );

    // 信封 round-trip：control_request 编码后可再次归类解出。
    let bytes = encode_frame(&req).expect("编码");
    let again = decode_frame(&bytes).expect("解码");
    assert_eq!(TopLevel::ControlRequest(req.clone()), again);
}

#[test]
fn control_unknown_subtype_survives() {
    let sample =
        r#"{"type":"control_request","request_id":5,"request":{"subtype":"future_thing","x":1}}"#;
    let TopLevel::ControlRequest(req) = decode_frame(sample.as_bytes()).expect("解码") else {
        panic!("应为 control_request");
    };
    assert_eq!(req.request.subtype, ControlSubtype::Unknown);
    assert_eq!(req.request_id, RequestId::Number(5));
}

#[test]
fn line_codec_splits_and_buffers_frames() {
    let a = encode_frame(&Message::Notification(agent_acp::JsonRpcNotification::new(
        "session/cancel",
        json!({"sessionId": "s1"}),
    )))
    .expect("编码");
    let b = encode_frame(&Message::Request(agent_acp::JsonRpcRequest::new(
        RequestId::Number(1),
        "ping",
        Value::Null,
    )))
    .expect("编码");

    let mut dec = LineDecoder::default();
    // 故意切在帧中间：先喂 a 的前半（无换行，不应吐帧），
    // 再喂剩余 + 空行 + b。空行应被忽略；a 的行尾换成 \r\n 验证 \r 容忍。
    let mut got = Vec::new();
    let cut = a.len() / 2; // a 形如 `{...}\n`
    got.extend(dec.feed(&a[..cut]).expect("第一次 feed（未完结）"));
    assert!(got.is_empty(), "没有换行前不吐帧");
    // a 的剩余是 `}\n`：改写成 `}\r\n` 并夹一个空行，再接 b（自带 \n）。
    let rest = [&a[cut..a.len() - 1], b"\r\n", b"\n", &b].concat();
    got.extend(dec.feed(&rest).expect("第二次 feed"));
    dec.finish().expect("无残留");
    assert_eq!(got.len(), 2, "空行应被忽略，两条帧");
    let Message::Notification(n) = decode_message(&got[0]).expect("帧 0") else {
        panic!("第一条应为通知");
    };
    assert_eq!(n.method, "session/cancel");
    let Message::Request(r) = decode_message(&got[1]).expect("帧 1") else {
        panic!("第二条应为请求");
    };
    assert_eq!(r.method, "ping");
    assert_eq!(r.params, None, "Null params 应省略");
}

#[test]
fn line_decoder_fail_closed_on_overlong() {
    let mut dec = LineDecoder::new(32);
    let junk = vec![b'x'; 100]; // 无换行的超长行
    let err = dec.feed(&junk).expect_err("超长必须报错");
    assert!(matches!(err, agent_acp::Error::FrameTooLarge { limit: 32 }));
    assert!(dec.is_broken());
    // 损坏后继续喂字节：同一错误，fail-closed 不复活。
    let again = dec.feed(b"\n").expect_err("损坏后不可恢复");
    assert!(matches!(again, agent_acp::Error::Broken { .. }));
}

#[test]
fn malformed_shapes_are_rejected() {
    // 既无 method 也无 result/error 的对象。
    let err = decode_message(br#"{"jsonrpc":"2.0","id":1}"#).expect_err("缺 method/result");
    assert!(matches!(err, agent_acp::Error::MalformedMessage { .. }));
    // 非对象帧。
    assert!(decode_message(br#"[1,2]"#).is_err());
    // 非 2.0 版本。
    assert!(decode_message(br#"{"jsonrpc":"1.0","method":"x"}"#).is_err());
    // control 信封不能按纯 RPC 解。
    assert!(decode_message(
        br#"{"type":"control_request","request_id":"a","request":{"subtype":"session_update"}}"#
    )
    .is_err());
}
