//! 错误映射契约：CoreError → 信封 code 的翻译表，以及请求体校验的 400 路径。
//! 覆盖缺口：SessionNotFound→404、SessionClosed→409、InvalidConfig→400、
//! 非法/缺失 id 参数→400、config:set 非法值与未知 key→400、config:get 缺 key→400。

use agent_core::{
    provider::EchoProvider,
    runtime::{CreateSession, Runtime},
    schema::{Isolation, Mode},
};
use agent_gateway::{GatewayConfig, GatewayHandle};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn request(port: u16, token: &str, action: &str, payload: Value) -> (u16, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let body=json!({"action":action,"payload":payload}).to_string();
        let mut s=tokio::net::TcpStream::connect(("127.0.0.1",port)).await.unwrap();
        let wire=format!("POST /rpc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Gateway-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len());
        s.write_all(wire.as_bytes()).await.unwrap();let mut out=Vec::new();s.read_to_end(&mut out).await.unwrap();
        let text=String::from_utf8(out).unwrap();let (head,body)=text.split_once("\r\n\r\n").unwrap();
        (head.split_whitespace().nth(1).unwrap().parse().unwrap(),serde_json::from_str(body).unwrap())
    }).await.expect("bounded RPC")
}

fn runtime(dir: &std::path::Path) -> Runtime {
    Runtime::builder()
        .workdir(dir)
        .provider(Arc::new(EchoProvider))
        .build()
        .unwrap()
}

async fn gateway(dir: &std::path::Path) -> GatewayHandle {
    GatewayHandle::start(
        runtime(dir),
        GatewayConfig::new(dir.join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn session_actions_map_missing_and_bad_id_to_envelope_codes() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    // 不存在但格式合法的 uuid → SessionNotFound → 404（不得泄露内部消息）。
    for action in ["session:get", "session:stop", "session:send"] {
        let payload = match action {
            "session:send" => json!({"id":uuid::Uuid::new_v4().to_string(),"text":"x"}),
            _ => json!({"id":uuid::Uuid::new_v4().to_string()}),
        };
        let (status, v) = request(g.port(), g.token(), action, payload).await;
        assert_eq!(status, 200, "{action}");
        assert_eq!(v["code"], 404, "{action}: {v}");
        assert_eq!(v["msg"], "not found", "{action}");
        assert_eq!(v["data"], Value::Null);
    }
    // 缺失 id / 非 uuid 字符串 / 数字类型 → 请求体校验 400。
    let (_, v) = request(g.port(), g.token(), "session:get", json!({})).await;
    assert_eq!(v["code"], 400);
    assert_eq!(v["msg"], "invalid payload");
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:get",
        json!({"id":"not-a-uuid"}),
    )
    .await;
    assert_eq!(v["code"], 400);
    let (_, v) = request(g.port(), g.token(), "session:get", json!({"id":42})).await;
    assert_eq!(v["code"], 400);
    // session:send 缺文本：id 合法但无 text/content → 400。
    let (_, created) = request(g.port(), g.token(), "session:create", json!({"title":"t"})).await;
    let id = created["data"]["id"].clone();
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:send",
        json!({"id": id, "text": 7}),
    )
    .await;
    assert_eq!(v["code"], 400);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn send_to_finished_session_maps_to_conflict_409() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    let session = rt
        .create_session(&CreateSession::plain("closed", Isolation::local_default()))
        .unwrap();
    rt.finish_session(session.id).unwrap();
    let g = {
        let path = dir.path().join("gw.json");
        GatewayHandle::start(rt, GatewayConfig::new(path, Isolation::local_default()))
            .await
            .unwrap()
    };
    // SessionClosed → 409 "session closed"（错误映射表第三行）。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:send",
        json!({"id": session.id.to_string(), "text": "late"}),
    )
    .await;
    assert_eq!(v["code"], 409, "{v}");
    assert_eq!(v["msg"], "session closed");
    // stop 走同一 get/update 路径但状态可回 idle：先验证 send 是唯一拒绝口。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:stop",
        json!({"id": session.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 0, "stop 重开为 idle: {v}");
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:send",
        json!({"id": session.id.to_string(), "text": "again"}),
    )
    .await;
    assert_eq!(v["code"], 0, "stop 后允许新回合: {v}");
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn config_errors_map_to_invalid_configuration_400() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    // 未知配置字段 → InvalidConfig → 400，msg 不得透出内部 reason 文本。
    let (_, v) = request(
        g.port(),
        g.token(),
        "config:set",
        json!({"key": "nope", "value": 1}),
    )
    .await;
    assert_eq!(v["code"], 400);
    assert_eq!(v["msg"], "invalid configuration");
    // 非法值：rpcTimeoutMs=0 → 同样 400。
    let (_, v) = request(
        g.port(),
        g.token(),
        "config:set",
        json!({"rpcTimeoutMs": 0}),
    )
    .await;
    assert_eq!(v["code"], 400);
    assert_eq!(v["msg"], "invalid configuration");
    // 失败的 set 不改动现值：config:get 仍是默认 30000。
    let (_, v) = request(
        g.port(),
        g.token(),
        "config:get",
        json!({"key":"rpcTimeoutMs"}),
    )
    .await;
    assert_eq!(v["code"], 0);
    assert_eq!(v["data"], 30_000);
    // config:get 未知 key → 400 invalid payload（找不到即 bad()）。
    let (_, v) = request(g.port(), g.token(), "config:get", json!({"key":"missing"})).await;
    assert_eq!(v["code"], 400);
    assert_eq!(v["msg"], "invalid payload");
    // config:get 无 key → 全量对象，冻结 camelCase 四字段。
    let (_, v) = request(g.port(), g.token(), "config:get", json!({})).await;
    assert_eq!(v["code"], 0);
    for field in [
        "approvalTimeoutMs",
        "rpcTimeoutMs",
        "defaultMode",
        "memoryEnabled",
    ] {
        assert!(v["data"].get(field).is_some(), "missing {field}");
    }
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_create_validates_mode_and_permission_mode() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    // 非法 mode 字符串 → 400。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:create",
        json!({"mode": "turbo"}),
    )
    .await;
    assert_eq!(v["code"], 400);
    assert_eq!(v["msg"], "invalid payload");
    // 非法 permissionMode → 400。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:create",
        json!({"permissionMode": "yolo"}),
    )
    .await;
    assert_eq!(v["code"], 400);
    // 合法 plan + readonly → 建会话成功且字段回显。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:create",
        json!({"mode":"plan","permissionMode":"readonly","title":"ok"}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(v["data"]["mode"], "plan");
    assert_eq!(v["data"]["permissionMode"], "readonly");
    assert_eq!(v["data"]["title"], "ok");
    // envBinding 别名同样被服务端身份防线拦截（与 isolation/env_binding 一致）。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:create",
        json!({"envBinding": "env-1"}),
    )
    .await;
    assert_eq!(v["code"], 403);
    assert_eq!(v["msg"], "server-bound identity");
    // 默认 title/mode：不传时用 "New session" 与 default_mode（ask）。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:create",
        json!({"mode": Mode::Quick.as_str()}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(v["data"]["title"], "New session");
    assert_eq!(v["data"]["mode"], "quick");
    // 会话创建时 isolation 由服务端注入：调用方拿不到越权 env。
    assert_eq!(v["data"]["isolation"]["userId"], "local");
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn unknown_action_and_bad_payload_never_leak_internals() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    // 未知 action → 404，msg 固定，不泄露 dispatch 表。
    let (_, v) = request(g.port(), g.token(), "session:teleport", json!({})).await;
    assert_eq!(v["code"], 404);
    assert_eq!(v["msg"], "unknown action");
    // 空 action → 404（空串也不在任何分支）。
    let (_, v) = request(g.port(), g.token(), "", json!({})).await;
    assert_eq!(v["code"], 404);
    // 信封形状冻结：任何失败都是 code/msg/data:null 三件套。
    for payload in [json!([]), json!("str"), json!(7)] {
        let (_, v) = request(g.port(), g.token(), "session:get", payload).await;
        assert_eq!(v["code"], 400);
        assert!(v["data"].is_null());
        assert!(v["msg"].is_string());
        assert_eq!(v.as_object().unwrap().len(), 3, "envelope keys: {v}");
    }
    g.shutdown().await.unwrap();
}
