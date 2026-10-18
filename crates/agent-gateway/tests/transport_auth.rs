//! 传输层鉴权与路由契约：所有端点统一走 `X-Gateway-Token` 中间件，
//! 未匹配路由 404 信封，坏请求体 400 信封（HTTP 层仍 200）。
//! 覆盖缺口：缺头 / 长度不符 token / fallback 路由 / JSON 解析失败 / GET 方法不允许。

use agent_core::{provider::EchoProvider, runtime::Runtime, schema::Isolation};
use agent_gateway::{GatewayConfig, GatewayHandle};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 原始 HTTP/1.1 客户端：返回 (状态码, JSON 体或空 Value)。
async fn raw_request(
    port: u16,
    token: Option<&str>,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let auth = match token {
            Some(t) => format!("X-Gateway-Token: {t}\r\n"),
            None => String::new(),
        };
        let wire = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(wire.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        (
            head.split_whitespace().nth(1).unwrap().parse().unwrap(),
            serde_json::from_str(body).unwrap_or(Value::Null),
        )
    })
    .await
    .expect("bounded HTTP roundtrip")
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
async fn gateway_rejects_missing_token() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    let body = json!({"action":"sys:ping"}).to_string();
    // 缺头：中间件必须先于路由拒绝。
    let (status, v) = raw_request(g.port(), None, "POST", "/rpc", &body).await;
    assert_eq!(status, 403, "missing header must be 403");
    assert_eq!(v["code"], 403);
    assert_eq!(v["msg"], "forbidden");
    // 空值头同样拒绝。
    let (status, _) = raw_request(g.port(), Some(""), "POST", "/rpc", &body).await;
    assert_eq!(status, 403);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_rejects_wrong_length_and_same_length_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    let body = json!({"action":"sys:ping"}).to_string();
    // 长度不符：equal_token 的短路分支。
    let (status, _) = raw_request(g.port(), Some("short"), "POST", "/rpc", &body).await;
    assert_eq!(status, 403);
    // 长度相同但内容不符：逐字节异或分支。
    let same_len = "f".repeat(g.token().len());
    assert_eq!(same_len.len(), g.token().len());
    assert_ne!(same_len, g.token());
    let (status, _) = raw_request(g.port(), Some(&same_len), "POST", "/rpc", &body).await;
    assert_eq!(status, 403);
    // 真 token 仍然放行（防止上文误伤）。
    let (status, v) = raw_request(g.port(), Some(g.token()), "POST", "/rpc", &body).await;
    assert_eq!(status, 200);
    assert_eq!(v["code"], 0);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_unknown_route_returns_404_envelope_after_auth() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    // 未认证时 fallback 不得泄露：先 403。
    let (status, _) = raw_request(g.port(), None, "GET", "/nope", "").await;
    assert_eq!(status, 403);
    // 认证后 fallback：404 + JSON 信封。
    let (status, v) = raw_request(g.port(), Some(g.token()), "GET", "/nope", "").await;
    assert_eq!(status, 404);
    assert_eq!(v["code"], 404);
    assert_eq!(v["msg"], "unknown route");
    // /rpc 只接受 POST：方法不允许不得被当成未知路由。
    let (status, _) = raw_request(g.port(), Some(g.token()), "GET", "/rpc", "").await;
    assert_eq!(status, 405);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_malformed_body_maps_to_400_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    let t = g.token();
    // 非法 JSON：信封 400，HTTP 传输层仍是 200。
    let (status, v) = raw_request(g.port(), Some(t), "POST", "/rpc", "not-json{").await;
    assert_eq!(status, 200);
    assert_eq!(v["code"], 400);
    assert_eq!(v["msg"], "invalid JSON");
    // 合法 JSON 但缺 action 字段：结构不合规同样 400。
    let (status, v) = raw_request(g.port(), Some(t), "POST", "/rpc", "{\"payload\":{}}").await;
    assert_eq!(status, 200);
    assert_eq!(v["code"], 400);
    // 合法 JSON 但类型不符（数组当对象）：400。
    let (status, v) = raw_request(g.port(), Some(t), "POST", "/rpc", "[1,2,3]").await;
    assert_eq!(status, 200);
    assert_eq!(v["code"], 400);
    // 空 body：400。
    let (status, v) = raw_request(g.port(), Some(t), "POST", "/rpc", "").await;
    assert_eq!(status, 200);
    assert_eq!(v["code"], 400);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn websocket_endpoint_requires_same_token() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    let url = format!("ws://127.0.0.1:{}/events", g.port());
    // 无 token 的 WS 握手必须失败（中间件在 upgrade 之前拦截）。
    assert!(tokio_tungstenite::connect_async(&url).await.is_err());
    // 带 token 才能建立订阅。
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
    // 客户端主动关闭后，服务端流必须有限步内终止（不得悬挂）。
    ws.close(None).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) => break true,
                Some(Ok(Message::Close(_))) => break true,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("websocket closes within bound");
    assert!(closed);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_shutdown_closes_open_websocket_streams() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
    let dir = tempfile::tempdir().unwrap();
    let g = gateway(dir.path()).await;
    let url = format!("ws://127.0.0.1:{}/events", g.port());
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("X-Gateway-Token", g.token().parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    // 保持一条打开的流，再关闭网关：shutdown 必须不被挂住的订阅拖死，
    // 且订阅端有限步内收到流终止。
    let joined = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                match ws.next().await {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break true,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await
        .unwrap_or(false)
    });
    g.shutdown().await.unwrap();
    assert!(
        joined.await.unwrap(),
        "open websocket must terminate after gateway shutdown"
    );
    assert!(!dir.path().join("gw.json").exists());
}
