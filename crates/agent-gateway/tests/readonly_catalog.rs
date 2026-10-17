//! 卡 W3：`tool:list` 在有会话时必须同时遵守模式白名单与会话 `PermissionMode`。
//!
//! 行为来源：PC05 §2（readonly 只允许只读类工具）、PC06 §3（工具管控）。
//! 约定：readonly 会话隐藏非 `ToolKind::Read` 工具；full 会话保留白名单；
//! 无会话请求沿用 `default_mode` 白名单（现有兼容行为）；他人会话 403。

use agent_core::{
    permission::PermissionGate,
    provider::EchoProvider,
    runtime::{CreateSession, Runtime},
    schema::{Isolation, Mode, PermissionMode},
    tool::{ToolKind, ToolRegistry, ToolSpec},
};
use agent_gateway::{GatewayConfig, GatewayHandle};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn request(port: u16, token: &str, action: &str, payload: Value) -> (u16, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let body = json!({"action":action,"payload":payload}).to_string();
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let wire = format!(
            "POST /rpc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Gateway-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(wire.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        (
            head.split_whitespace().nth(1).unwrap().parse().unwrap(),
            serde_json::from_str(body).unwrap(),
        )
    })
    .await
    .expect("bounded RPC")
}

fn spec(name: &str, kind: ToolKind) -> ToolSpec {
    ToolSpec {
        name: name.to_owned(),
        description: format!("{name} 测试工具"),
        kind,
        sensitive_arguments: kind != ToolKind::Read,
        timeout_ms: 1_000,
    }
}

fn names(items: &Value) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

fn set(values: &[&str]) -> std::collections::BTreeSet<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

/// 三个已注册工具：Read / Write / Exec；白名单覆盖 ask、craft、expert。
fn gate() -> PermissionGate {
    let mut registry = ToolRegistry::new();
    registry.register(spec("read_file", ToolKind::Read));
    registry.register(spec("write_file", ToolKind::Write));
    registry.register(spec("run_cmd", ToolKind::Exec));
    PermissionGate::new(registry)
        .with_whitelist(Mode::Ask, set(&["read_file", "write_file", "run_cmd"]))
        .with_whitelist(Mode::Craft, set(&["read_file", "write_file"]))
        .with_whitelist(Mode::Expert, set(&["read_file", "ghost_tool"]))
}

fn runtime(dir: &std::path::Path) -> Runtime {
    Runtime::builder()
        .workdir(dir)
        .provider(Arc::new(EchoProvider))
        .gate(gate())
        .build()
        .unwrap()
}

fn session(mode: Mode, permission_mode: PermissionMode, isolation: Isolation) -> CreateSession {
    CreateSession {
        title: "catalog".into(),
        workspace_root: None,
        mode,
        permission_mode,
        env_binding: None,
        isolation,
    }
}

async fn gateway(dir: &std::path::Path, rt: Runtime) -> GatewayHandle {
    GatewayHandle::start(
        rt,
        GatewayConfig::new(dir.join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn readonly_session_hides_non_read_tools() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    let s = rt
        .create_session(&session(
            Mode::Ask,
            PermissionMode::ReadOnly,
            Isolation::local_default(),
        ))
        .unwrap();
    let g = gateway(dir.path(), rt).await;
    let (_, v) = request(
        g.port(),
        g.token(),
        "tool:list",
        json!({"id": s.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(names(&v["data"]), vec!["read_file".to_owned()]);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn full_session_keeps_mode_whitelist() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    // craft 白名单不含 run_cmd：full 只放宽 readonly，不放宽白名单。
    let s = rt
        .create_session(&session(
            Mode::Craft,
            PermissionMode::Full,
            Isolation::local_default(),
        ))
        .unwrap();
    let g = gateway(dir.path(), rt).await;
    let (_, v) = request(
        g.port(),
        g.token(),
        "tool:list",
        json!({"sessionId": s.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(
        names(&v["data"]),
        vec!["read_file".to_owned(), "write_file".to_owned()]
    );
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn readonly_and_quick_and_sessionless_paths() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    // expert 白名单里有未注册名：readonly 过滤后仍只剩已注册的只读工具。
    let ro = rt
        .create_session(&session(
            Mode::Expert,
            PermissionMode::ReadOnly,
            Isolation::local_default(),
        ))
        .unwrap();
    // quick 未配置白名单 → deny-by-default 空集。
    let quick = rt
        .create_session(&session(
            Mode::Quick,
            PermissionMode::Full,
            Isolation::local_default(),
        ))
        .unwrap();
    let foreign = rt
        .create_session(&session(
            Mode::Ask,
            PermissionMode::Full,
            Isolation {
                user_id: "other".into(),
                tenant_id: "other".into(),
                env_id: None,
            },
        ))
        .unwrap();
    let g = gateway(dir.path(), rt).await;
    let (_, v) = request(
        g.port(),
        g.token(),
        "tool:list",
        json!({"session_id": ro.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(names(&v["data"]), vec!["read_file".to_owned()]);
    let (_, v) = request(
        g.port(),
        g.token(),
        "tool:list",
        json!({"id": quick.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(v["data"].as_array().unwrap().len(), 0);
    let (_, v) = request(
        g.port(),
        g.token(),
        "tool:list",
        json!({"id": foreign.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 403, "{v}");
    // 无会话：沿用 default_mode（ask）白名单，不做 readonly 过滤。
    let (_, v) = request(g.port(), g.token(), "tool:list", json!({})).await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(
        names(&v["data"]),
        vec![
            "read_file".to_owned(),
            "run_cmd".to_owned(),
            "write_file".to_owned()
        ]
    );
    g.shutdown().await.unwrap();
}
