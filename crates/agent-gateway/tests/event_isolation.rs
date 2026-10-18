//! 事件流隔离契约：`/events` 订阅按网关隔离域过滤 ——
//! 其他 isolation 的会话事件不得越域推送（server.rs 的 stream 内过滤分支），
//! `session:list` 同样只回本域会话。

use agent_core::{
    provider::EchoProvider,
    runtime::{CreateSession, Runtime},
    schema::Isolation,
};
use agent_gateway::{GatewayConfig, GatewayHandle};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

async fn request(port: u16, token: &str, action: &str, payload: Value) -> (u16, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let body=json!({"action":action,"payload":payload}).to_string();
        let mut s=tokio::net::TcpStream::connect(("127.0.0.1",port)).await.unwrap();
        let wire=format!("POST /rpc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Gateway-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len());
        s.write_all(wire.as_bytes()).await.unwrap();let mut out=Vec::new();s.read_to_end(&mut out).await.unwrap();
        let text=String::from_utf8(out).unwrap();let (head,body)=text.split_once("\r\n\r\n").unwrap();
        (head.split_whitespace().nth(1).unwrap().parse().unwrap(),serde_json::from_str(body).unwrap())
    })
    .await
    .expect("bounded RPC")
}

fn foreign() -> Isolation {
    Isolation {
        user_id: "other".into(),
        tenant_id: "other".into(),
        env_id: None,
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open_events(g: &GatewayHandle) -> Ws {
    let url = format!("ws://127.0.0.1:{}/events", g.port());
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("X-Gateway-Token", g.token().parse().unwrap());
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio_tungstenite::connect_async(req),
    )
    .await
    .unwrap()
    .unwrap()
    .0
}

/// 读一帧文本事件并解析（带超时；跳过 Ping/Pong 等控制帧）。
async fn next_event(ws: &mut Ws) -> Value {
    use tokio_tungstenite::tungstenite::Message;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("event arrives within bound")
            .expect("stream alive")
            .expect("no protocol error");
        if let Message::Text(t) = frame {
            return serde_json::from_str(t.as_str()).unwrap();
        }
    }
}

#[tokio::test]
async fn events_stream_only_own_isolation_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::builder()
        .workdir(dir.path())
        .provider(Arc::new(EchoProvider))
        .build()
        .unwrap();
    let mine = rt
        .create_session(&CreateSession::plain("mine", Isolation::local_default()))
        .unwrap();
    let theirs = rt
        .create_session(&CreateSession::plain("theirs", foreign()))
        .unwrap();
    let g = GatewayHandle::start(
        rt.clone(),
        GatewayConfig::new(dir.path().join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap();
    let mut ws = open_events(&g).await;
    // 越域写入：their 会话跑一个回合，产生一整串事件。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:send",
        json!({"id": theirs.id.to_string(), "text": "cross-domain"}),
    )
    .await;
    // their 会话不属于本域 → 网关自己就拒绝（own 校验 403）。
    assert_eq!(v["code"], 403, "foreign session send: {v}");
    // 绕过网关直接在宿主 runtime 上产生越域事件：不同隔离键走不同总线，
    // 订阅端根本不应看到（逐会话过滤分支由 env-drift 用例覆盖）。
    rt.send_text(theirs.id, "host-side").unwrap();
    // 本域写入产生可见事件。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:send",
        json!({"id": mine.id.to_string(), "text": "seen"}),
    )
    .await;
    assert_eq!(v["code"], 0, "own session send: {v}");
    // 收到的每一帧都必须属于本域会话；直到看到本域 done 事件为止。
    let mut saw_done = false;
    while !saw_done {
        let event = next_event(&mut ws).await;
        assert_ne!(
            event["session_id"].as_str().unwrap(),
            theirs.id.to_string(),
            "foreign event leaked: {event}"
        );
        assert_eq!(event["session_id"], mine.id.to_string(), "{event}");
        if event["kind"] == "done" {
            saw_done = true;
        }
    }
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn events_stream_filters_same_key_different_env_sessions() {
    // server.rs:206 的逐会话过滤分支：隔离键（user-tenant）相同但 env_id 不同
    // 的会话，事件会进入同一条总线，必须由 stream 内的相等判定丢弃。
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::builder()
        .workdir(dir.path())
        .provider(Arc::new(EchoProvider))
        .build()
        .unwrap();
    let mine = rt
        .create_session(&CreateSession::plain("mine", Isolation::local_default()))
        .unwrap();
    let env_drift = rt
        .create_session(&CreateSession::plain(
            "env-drift",
            Isolation {
                user_id: "local".into(),
                tenant_id: "local".into(),
                env_id: Some("env-x".into()),
            },
        ))
        .unwrap();
    let g = GatewayHandle::start(
        rt.clone(),
        GatewayConfig::new(dir.path().join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap();
    // RPC 层同样视其为外来会话（isolation 全等校验）。
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:get",
        json!({"id": env_drift.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 403, "env mismatch must not be readable: {v}");
    let mut ws = open_events(&g).await;
    // 宿主侧直接在同键总线上产生 env 会话事件：订阅流收到后必须过滤。
    rt.send_text(env_drift.id, "host-side-env").unwrap();
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:send",
        json!({"id": mine.id.to_string(), "text": "seen"}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    let mut saw_done = false;
    while !saw_done {
        let event = next_event(&mut ws).await;
        assert_eq!(
            event["session_id"],
            mine.id.to_string(),
            "env-drift event leaked into stream: {event}"
        );
        if event["kind"] == "done" {
            saw_done = true;
        }
    }
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_list_is_scoped_to_gateway_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::builder()
        .workdir(dir.path())
        .provider(Arc::new(EchoProvider))
        .build()
        .unwrap();
    let _theirs = rt
        .create_session(&CreateSession::plain("theirs", foreign()))
        .unwrap();
    let _theirs2 = rt
        .create_session(&CreateSession::plain("theirs2", foreign()))
        .unwrap();
    let mine = rt
        .create_session(&CreateSession::plain("mine", Isolation::local_default()))
        .unwrap();
    let g = GatewayHandle::start(
        rt,
        GatewayConfig::new(dir.path().join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap();
    let (_, v) = request(g.port(), g.token(), "session:list", json!({})).await;
    assert_eq!(v["code"], 0, "{v}");
    let ids: Vec<&str> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![mine.id.to_string().as_str()], "{v}");
    // 现状契约：session:list 返回完整 Session 对象（含 messages 体），
    // 而非 summary 视图 —— 记录行为，不做修改（逻辑零改动红线）。
    let first = &v["data"][0];
    assert_eq!(first["title"], "mine");
    assert!(first.get("messages").is_some(), "{first}");
    assert!(first.get("isolation").is_some(), "{first}");
    g.shutdown().await.unwrap();
}
