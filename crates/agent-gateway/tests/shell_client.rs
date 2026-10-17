use agent_core::{provider::EchoProvider, runtime::Runtime, schema::Isolation};
use agent_gateway::{GatewayConfig, GatewayHandle};
use lengsuo_shell::{EventKind, GatewayClient};
use serde_json::json;
use std::{sync::Arc, time::Duration};
#[tokio::test]
async fn actual_shell_client_can_talk_to_actual_gateway() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.json");
    let rt = Runtime::builder()
        .workdir(dir.path())
        .provider(Arc::new(EchoProvider))
        .build()
        .unwrap();
    let g = GatewayHandle::start(rt, GatewayConfig::new(&path, Isolation::local_default()))
        .await
        .unwrap();
    let c = GatewayClient::connect(&path)
        .await
        .unwrap()
        .with_timeout(Duration::from_secs(3));
    c.sys_ping().await.unwrap();
    let s = c
        .session_create(json!({"title":"real client"}))
        .await
        .unwrap();
    let id = s["id"].as_str().unwrap();
    let mut events = c.subscribe_events().await.unwrap();
    c.session_send(id, "hello from shell").await.unwrap();
    let got = c.session_get(id).await.unwrap();
    assert_eq!(got["messages"].as_array().unwrap().len(), 2);
    c.config_set("memoryEnabled", json!(true)).await.unwrap();
    assert_eq!(c.config_get("memoryEnabled").await.unwrap(), true);
    c.tool_list().await.unwrap();
    let mut saw_text = false;
    loop {
        let event = events.next().await.unwrap();
        if event.kind == EventKind::Text {
            saw_text = true;
        }
        if event.kind == EventKind::Done {
            break;
        }
    }
    assert!(saw_text);
    c.session_stop(id).await.unwrap();
    g.shutdown().await.unwrap();
}
