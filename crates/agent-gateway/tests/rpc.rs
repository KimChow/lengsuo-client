use agent_core::{provider::EchoProvider, runtime::Runtime, schema::Isolation};
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
#[tokio::test]
async fn authenticated_roundtrip_and_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.json");
    let g = GatewayHandle::start(
        runtime(dir.path()),
        GatewayConfig::new(&path, Isolation::local_default()),
    )
    .await
    .unwrap();
    let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(v["port"], g.port());
    assert_eq!(
        request(g.port(), "wrong", "sys:ping", json!({})).await.0,
        403
    );
    assert_eq!(
        request(g.port(), g.token(), "sys:ping", json!({})).await.1["code"],
        0
    );
    assert_eq!(
        request(g.port(), g.token(), "not:registered", json!({}))
            .await
            .1["code"],
        404
    );
    let (_, created) = request(
        g.port(),
        g.token(),
        "session:create",
        json!({"title":"demo"}),
    )
    .await;
    assert_eq!(created["code"], 0);
    let id = created["data"]["id"].clone();
    let (_, sent) = request(
        g.port(),
        g.token(),
        "session:send",
        json!({"id":id,"text":"hello"}),
    )
    .await;
    assert_eq!(sent["code"], 0);
    let (_, got) = request(g.port(), g.token(), "session:get", json!({"id":id})).await;
    assert_eq!(got["data"]["messages"].as_array().unwrap().len(), 2);
    assert_eq!(
        request(
            g.port(),
            g.token(),
            "config:set",
            json!({"memoryEnabled":true})
        )
        .await
        .1["data"]["memoryEnabled"],
        true
    );
    g.shutdown().await.unwrap();
    assert!(!path.exists());
}
#[tokio::test]
async fn session_identity_is_bound_by_server() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    let foreign = rt
        .create_session(&agent_core::runtime::CreateSession::plain(
            "foreign",
            Isolation {
                user_id: "other".into(),
                tenant_id: "other".into(),
                env_id: None,
            },
        ))
        .unwrap();
    let g = GatewayHandle::start(
        rt,
        GatewayConfig::new(dir.path().join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap();
    let (_, v) = request(g.port(), g.token(), "session:get", json!({"id":foreign.id})).await;
    assert_eq!(v["code"], 403);
    let (_, v) = request(
        g.port(),
        g.token(),
        "session:create",
        json!({"isolation":{"user_id":"other","tenant_id":"other"}}),
    )
    .await;
    assert_eq!(v["code"], 403);
    g.shutdown().await.unwrap();
}
#[tokio::test]
async fn existing_handshake_cannot_be_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gw.json");
    std::fs::write(&path, "existing").unwrap();
    assert!(GatewayHandle::start(
        runtime(dir.path()),
        GatewayConfig::new(&path, Isolation::local_default())
    )
    .await
    .is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "existing");
}

#[tokio::test]
async fn websocket_auth_and_ordered_events() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    let session = rt
        .create_session(&agent_core::runtime::CreateSession::plain(
            "events",
            Isolation::local_default(),
        ))
        .unwrap();
    let g = GatewayHandle::start(
        rt,
        GatewayConfig::new(dir.path().join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap();
    let url = format!("ws://127.0.0.1:{}/events", g.port());
    assert!(tokio_tungstenite::connect_async(&url).await.is_err());
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("X-Gateway-Token", g.token().parse().unwrap());
    let (mut ws, _) = tokio::time::timeout(
        Duration::from_secs(3),
        tokio_tungstenite::connect_async(req),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        request(
            g.port(),
            g.token(),
            "session:send",
            json!({"id":session.id,"text":"event payload"})
        )
        .await
        .1["code"],
        0
    );
    let mut last = 0;
    let mut kinds = Vec::new();
    while !kinds.iter().any(|s| s == "done") {
        let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let event: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
        let seq = event["seq"].as_u64().unwrap();
        assert!(seq > last);
        last = seq;
        assert_eq!(event["session_id"], session.id.to_string());
        kinds.push(event["kind"].as_str().unwrap().to_owned());
    }
    assert!(kinds.iter().any(|s| s == "text"));
    g.shutdown().await.unwrap();
}
#[tokio::test]
async fn fifty_sessions_do_not_block_the_listener() {
    let dir = tempfile::tempdir().unwrap();
    let g = GatewayHandle::start(
        runtime(dir.path()),
        GatewayConfig::new(dir.path().join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap();
    let mut tasks = Vec::new();
    for i in 0..50 {
        let port = g.port();
        let token = g.token().to_owned();
        tasks.push(tokio::spawn(async move {
            let (_, v) = request(
                port,
                &token,
                "session:create",
                json!({"title":format!("s{i}")}),
            )
            .await;
            assert_eq!(v["code"], 0);
            assert_eq!(
                request(
                    port,
                    &token,
                    "session:send",
                    json!({"id":v["data"]["id"],"text":"hello"})
                )
                .await
                .1["code"],
                0
            );
        }));
    }
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }
    let (_, v) = request(g.port(), g.token(), "session:list", json!({})).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 50);
    g.shutdown().await.unwrap();
}
#[tokio::test]
async fn rpc_timeout_keeps_ping_responsive() {
    struct Slow;
    impl agent_core::provider::Provider for Slow {
        fn next_steps(
            &self,
            _: uuid::Uuid,
            _: &str,
        ) -> Result<Vec<agent_core::provider::ProviderStep>, agent_core::error::CoreError> {
            std::thread::sleep(Duration::from_millis(100));
            Ok(vec![agent_core::provider::ProviderStep::Finished])
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let rt = Runtime::builder()
        .workdir(dir.path())
        .provider(Arc::new(Slow))
        .build()
        .unwrap();
    rt.config_set(&json!({"rpcTimeoutMs":20})).unwrap();
    let session = rt
        .create_session(&agent_core::runtime::CreateSession::plain(
            "slow",
            Isolation::local_default(),
        ))
        .unwrap();
    let g = GatewayHandle::start(
        rt,
        GatewayConfig::new(dir.path().join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap();
    assert_eq!(
        request(
            g.port(),
            g.token(),
            "session:send",
            json!({"id":session.id,"text":"slow"})
        )
        .await
        .1["code"],
        408
    );
    assert_eq!(
        request(g.port(), g.token(), "sys:ping", json!({})).await.1["code"],
        0
    );
    g.shutdown().await.unwrap();
}
#[cfg(unix)]
#[tokio::test]
async fn handshake_is_private_and_tokens_rotate() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gw.json");
    let g = GatewayHandle::start(
        runtime(dir.path()),
        GatewayConfig::new(&path, Isolation::local_default()),
    )
    .await
    .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let old = g.token().to_owned();
    g.shutdown().await.unwrap();
    let g = GatewayHandle::start(
        runtime(dir.path()),
        GatewayConfig::new(&path, Isolation::local_default()),
    )
    .await
    .unwrap();
    assert_ne!(g.token(), old);
    assert_eq!(request(g.port(), &old, "sys:ping", json!({})).await.0, 403);
    g.shutdown().await.unwrap();
}
