//! 契约面守卫：把「搬过来不能改」的那几条钉死。
//!
//! 本卡把网关客户端从 `lengsuo-agent` 的 `lengsuo-shell` 搬到本 crate。
//! 搬的是**线上真实行为**，不是「看起来差不多」的实现 ⇒ 下面几条一旦漂移，
//! 就是行为回归，必须红：
//!
//! 1. **事件 payload 键名是 camelCase**（`argsRef` / `resultRef` / `tsMs` /
//!    `chars` / `preview` / `name` / `args`）。⚠️ 文档 §3 里写的 Rust 侧
//!    snake_case 字段名**不是线上那一份**；线上由服务端发射端决定，客户端只透传。
//!    历史上真出过漂移：服务端发 `argsRef`、壳侧读 `args_ref` ⇒ 参数引用恒为 `None`。
//! 2. **鉴权头名是 `X-Gateway-Token`**（大小写不敏感地按原样发出）。
//! 3. **握手文件字段是 `{port, pid, token}`**，且路径默认 `%LOCALAPPDATA%/lengsuo/gateway.json`。
//! 4. **错误码语义**：`0` 成功 / `400` 参数或请求体非法 / `403` 鉴权拒 /
//!    `404` 未注册动作 / `408` 超时 / `409` 会话已结束 / `500` 内部错误 /
//!    `502` ACP 转发传输失败。客户端只认自己这一侧能判定的那些，其余原样上抛。
//!
//! 事件流的 `EventKind` 名字（`user` / `thinking` / `text` / `tool_use` /
//! `tool_result` / `approval_request` / `approval_resolved` / `files` / `done` /
//! `error` / `session_update`）由 `crates/lengsuo-ipc/tests/gateway_events.rs`
//! 与服务端侧的穷举断言共同守住。

mod support;

use lengsuo_ipc::{EventKind, GatewayClient, GatewayHandshake, RpcError};
use serde_json::Value;
use support::{event_json, EventsBehaviour, MockGateway, RpcBehaviour};

/// 测试专用假 token。
const FAKE: &str = "fake-loopback-token-a";

/// 客户端透传的 payload 键名必须与线上 camelCase **逐字一致**。
///
/// 做法：把一帧真实形态的 `tool_use` / `tool_result` 事件推进 mock 网关，
/// 客户端解出来的 `payload` 必须**原样**带着 camelCase 键名——一个字符都不能变。
/// 任何「顺手改成 snake_case」或「加了 serde rename」的改动都会在这里红。
#[tokio::test]
async fn event_payload_keys_stay_camel_case() {
    // 线上真实形态（服务端发射端的键名，见 `agent-core` 的 runtime 发射点）。
    let tool_use =
        r#"{"name":"fs.read","args":{"path":"a.rs"},"argsRef":"blob-args-1","tsMs":1700000000000}"#;
    let tool_result = r#"{"name":"fs.read","chars":4,"resultRef":"blob-result-1","preview":"abcd","tsMs":1700000000001}"#;
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![
            event_json(1, "s1", "tool_use", tool_use, 1_700_000_000_000),
            event_json(2, "s1", "tool_result", tool_result, 1_700_000_000_001),
        ],
        expected_token: None,
        close_after_frames: false,
    })
    .await;

    let mut sub = GatewayClient::from_handshake(GatewayHandshake {
        port: mock.addr().port(),
        pid: std::process::id(),
        token: FAKE.to_owned(),
    })
    .subscribe_events()
    .await
    .expect("握手成功");

    let use_ev = sub.next().await.expect("tool_use 事件");
    assert_eq!(use_ev.kind, EventKind::ToolUse);
    let use_payload = &use_ev.payload;
    // camelCase 键名逐个断言存在。
    for key in ["name", "args", "argsRef", "tsMs"] {
        assert!(
            use_payload.get(key).is_some(),
            "tool_use payload 必须带 camelCase 键 `{key}`，实际键集：{:?}",
            use_payload
                .as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>())
        );
    }
    assert_eq!(use_payload["argsRef"], "blob-args-1");
    assert_eq!(use_payload["tsMs"], 1_700_000_000_000i64);
    // snake_case 形态**不得**出现（历史上正是这里漂移过）。
    assert!(
        use_payload.get("args_ref").is_none(),
        "线上没有 snake_case 的 `args_ref`，客户端不得凭空造一个"
    );

    let result_ev = sub.next().await.expect("tool_result 事件");
    assert_eq!(result_ev.kind, EventKind::ToolResult);
    let result_payload = &result_ev.payload;
    for key in ["name", "chars", "resultRef", "preview", "tsMs"] {
        assert!(
            result_payload.get(key).is_some(),
            "tool_result payload 必须带 camelCase 键 `{key}`，实际键集：{:?}",
            result_payload
                .as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>())
        );
    }
    assert_eq!(result_payload["resultRef"], "blob-result-1");
    assert_eq!(result_payload["chars"], 4);
    assert_eq!(result_payload["preview"], "abcd");
    assert!(
        result_payload.get("result_ref").is_none(),
        "线上没有 snake_case 的 `result_ref`，客户端不得凭空造一个"
    );

    mock.shutdown().await;
}

/// 帧外壳字段名是 snake_case（`seq` / `session_id` / `kind` / `payload` / `ts_ms`）
/// ——**与 payload 内部键名是两套约定**，别混。
#[tokio::test]
async fn event_frame_outer_fields_stay_snake_case() {
    let mock = MockGateway::events(EventsBehaviour {
        frames: vec![event_json(5, "s1", "text", r#"{"delta":"hi"}"#, 42)],
        expected_token: None,
        close_after_frames: false,
    })
    .await;
    let mut sub = GatewayClient::from_handshake(GatewayHandshake {
        port: mock.addr().port(),
        pid: std::process::id(),
        token: FAKE.to_owned(),
    })
    .subscribe_events()
    .await
    .expect("握手成功");

    let ev = sub.next().await.expect("text 事件");
    assert_eq!(ev.seq, 5);
    assert_eq!(ev.session_id, "s1");
    assert_eq!(ev.kind, EventKind::Text);
    assert_eq!(ev.ts_ms, 42);
    assert_eq!(ev.payload["delta"], "hi");

    mock.shutdown().await;
}

/// 事件名穷举：11 个冻结 kind 必须都能解出来。
#[tokio::test]
async fn all_frozen_event_kinds_decode() {
    let kinds = [
        "user",
        "thinking",
        "text",
        "tool_use",
        "tool_result",
        "approval_request",
        "approval_resolved",
        "files",
        "done",
        "error",
        "session_update",
    ];
    let frames: Vec<String> = kinds
        .iter()
        .enumerate()
        .map(|(i, kind)| event_json(i as u64 + 1, "s1", kind, "null", i as u64))
        .collect();
    let mock = MockGateway::events(EventsBehaviour {
        frames,
        expected_token: None,
        close_after_frames: false,
    })
    .await;
    let mut sub = GatewayClient::from_handshake(GatewayHandshake {
        port: mock.addr().port(),
        pid: std::process::id(),
        token: FAKE.to_owned(),
    })
    .subscribe_events()
    .await
    .expect("握手成功");

    for (i, kind) in kinds.iter().enumerate() {
        let ev = sub
            .next()
            .await
            .unwrap_or_else(|e| panic!("kind `{kind}` 应可解码，实际 {e:?}"));
        assert_eq!(ev.kind.as_str(), *kind, "第 {i} 帧的 kind 应为 `{kind}`");
    }

    mock.shutdown().await;
}

/// 鉴权头名必须是 `X-Gateway-Token`（不是别的拼法）。
#[tokio::test]
async fn auth_header_name_is_x_gateway_token() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: "null",
        }],
        Some(FAKE.to_owned()),
    )
    .await;
    let c = GatewayClient::from_handshake(GatewayHandshake {
        port: mock.addr().port(),
        pid: std::process::id(),
        token: FAKE.to_owned(),
    });
    c.sys_ping().await.expect("token 正确应成功");

    let seen = mock.seen();
    let token = seen[0].token.as_deref();
    assert_eq!(
        token,
        Some(FAKE),
        "请求必须带 `X-Gateway-Token` 头（mock 按该头名提取）"
    );

    mock.shutdown().await;
}

/// 握手文件字段名固定为 `{port, pid, token}`；路径默认形态是
/// `<base>/lengsuo/gateway.json`。
#[test]
fn handshake_fields_and_default_path_are_frozen() {
    // 字段名：少一个都应 fail-closed。
    for body in [
        r#"{"pid":1,"token":"t"}"#,
        r#"{"port":1,"token":"t"}"#,
        r#"{"port":1,"pid":1}"#,
    ] {
        let err = GatewayHandshake::parse(body, std::path::Path::new("/tmp/gateway.json"))
            .expect_err("缺字段应拒绝");
        assert!(
            matches!(err, lengsuo_ipc::HandshakeError::Invalid { .. }),
            "缺字段应 Invalid，实际 {err:?}"
        );
    }
    // 三个字段齐 ⇒ 解析成功，值原样取出。
    let ok = GatewayHandshake::parse(
        r#"{"port":4242,"pid":7,"token":"tok"}"#,
        std::path::Path::new("/tmp/gateway.json"),
    )
    .expect("三字段齐应成功");
    assert_eq!(ok.port, 4242);
    assert_eq!(ok.pid, 7);
    assert_eq!(ok.token, "tok");

    // 默认路径：以 `lengsuo/gateway.json` 结尾。
    let p = GatewayHandshake::default_path().expect("默认路径可得");
    assert!(
        p.ends_with("lengsuo/gateway.json"),
        "默认路径应以 `lengsuo/gateway.json` 结尾，实际 {p:?}"
    );
}

/// 错误码语义：客户端这一侧能判定的码必须映射到对应变体。
///
/// `0` 成功 → 返回 `data`；
/// `403` → `Unauthorized`（鉴权拒）；
/// `404` → `ActionNotFound`（未注册动作）；
/// `408` → `Timeout`；
/// `400` / `409` / `500` / `502` 属业务码 → 原样上抛 `Business { code }`，不改写。
///
/// ⚠️ `400` / `409` / `500` / `502` 在服务端契约里由网关产出；客户端只保证
/// **不改写**它们（不吞、不改判），映射细节由 `contracts-check` 的契约面守住。
#[tokio::test]
async fn error_code_semantics_are_preserved() {
    let mock = MockGateway::rpc(
        vec![
            RpcBehaviour::Envelope {
                code: 400,
                msg: "参数非法",
                data: "null",
            },
            RpcBehaviour::Envelope {
                code: 403,
                msg: "鉴权拒",
                data: "null",
            },
            RpcBehaviour::Envelope {
                code: 404,
                msg: "browser:open",
                data: "null",
            },
            RpcBehaviour::Envelope {
                code: 408,
                msg: "网关超时",
                data: "null",
            },
            RpcBehaviour::Envelope {
                code: 409,
                msg: "会话已结束",
                data: "null",
            },
            RpcBehaviour::Envelope {
                code: 500,
                msg: "内部错误",
                data: "null",
            },
            RpcBehaviour::Envelope {
                code: 502,
                msg: "ACP 转发失败",
                data: "null",
            },
        ],
        None,
    )
    .await;
    let c = GatewayClient::from_handshake(GatewayHandshake {
        port: mock.addr().port(),
        pid: std::process::id(),
        token: FAKE.to_owned(),
    });

    // mock 按连接序号取规则（`rules[N]`），故这里必须**按规则下标顺序**发请求。
    // 400：参数/请求体非法 ⇒ 业务码原样上抛。
    let err = c
        .rpc("sys:ping", Value::Null)
        .await
        .expect_err("400 应失败");
    match err {
        RpcError::Business { code, .. } => assert_eq!(code, 400, "400 应原样上抛"),
        other => panic!("期望 Business(400)，实际 {other:?}"),
    }
    // 403：鉴权拒。
    assert!(matches!(
        c.rpc("sys:ping", Value::Null)
            .await
            .expect_err("403 应失败"),
        RpcError::Unauthorized
    ));
    // 404：未注册动作。
    match c
        .rpc("sys:ping", Value::Null)
        .await
        .expect_err("404 应失败")
    {
        RpcError::ActionNotFound { msg } => assert_eq!(msg, "browser:open"),
        other => panic!("期望 ActionNotFound，实际 {other:?}"),
    }
    // 408：超时。
    assert!(matches!(
        c.rpc("sys:ping", Value::Null)
            .await
            .expect_err("408 应失败"),
        RpcError::Timeout
    ));
    // 409 / 500 / 502：业务码原样上抛，不改写、不吞掉。
    for code in [409i64, 500, 502] {
        let err = c
            .rpc("sys:ping", Value::Null)
            .await
            .expect_err("非 0 信封应失败");
        match err {
            RpcError::Business { code: got, .. } => assert_eq!(got, code, "业务码应原样上抛"),
            other => panic!("期望 Business({code})，实际 {other:?}"),
        }
    }

    mock.shutdown().await;
}

/// `code == 0` 成功时返回 `data`，信封其余字段不外泄。
#[tokio::test]
async fn success_envelope_returns_data_only() {
    let mock = MockGateway::rpc(
        vec![RpcBehaviour::Envelope {
            code: 0,
            msg: "ok",
            data: r#"{"pong":true}"#,
        }],
        None,
    )
    .await;
    let c = GatewayClient::from_handshake(GatewayHandshake {
        port: mock.addr().port(),
        pid: std::process::id(),
        token: FAKE.to_owned(),
    });
    let data = c.sys_ping().await.expect("成功信封应返回 data");
    assert_eq!(data["pong"], Value::Bool(true));
    assert!(
        data.get("code").is_none(),
        "成功路径只回 data，不回整个信封"
    );
    assert!(data.get("msg").is_none(), "成功路径只回 data，不回整个信封");

    mock.shutdown().await;
}
