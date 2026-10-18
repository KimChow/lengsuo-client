//! 审批应答契约（approval:respond）：现有测试完全未覆盖此动作。
//! 契约：先归属校验（403）→ 必须在pending集合内（否则403，不泄露404差别）→
//! approved/decision两种写法映射 → 一次性应答 → 过期应答落为timedOut deny。

use agent_core::{
    permission::PermissionGate,
    provider::EchoProvider,
    runtime::{CreateSession, Runtime},
    schema::{Isolation, PermissionMode},
    tool::ToolRegistry,
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

/// 审批超时压到 80ms：快速验证过期路径而不拖慢测试。
fn runtime(dir: &std::path::Path) -> Runtime {
    let gate =
        PermissionGate::new(ToolRegistry::new()).with_approval_timeout(Duration::from_millis(80));
    Runtime::builder()
        .workdir(dir)
        .provider(Arc::new(EchoProvider))
        .gate(gate)
        .build()
        .unwrap()
}

async fn gateway(dir: &std::path::Path, rt: Runtime) -> GatewayHandle {
    GatewayHandle::start(
        rt,
        GatewayConfig::new(dir.join("gw.json"), Isolation::local_default()),
    )
    .await
    .unwrap()
}

fn local_session(rt: &Runtime, title: &str) -> agent_core::schema::Session {
    rt.create_session(&CreateSession {
        title: title.into(),
        workspace_root: None,
        mode: agent_core::schema::Mode::Ask,
        permission_mode: PermissionMode::Full,
        env_binding: None,
        isolation: Isolation::local_default(),
    })
    .unwrap()
}

#[tokio::test]
async fn approval_respond_accepts_bool_and_decision_forms() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    let session = local_session(&rt, "approve-me");
    let a1 = rt
        .request_approval(session.id, "write_file", &json!({"path":"a"}))
        .unwrap();
    let a2 = rt
        .request_approval(session.id, "run_cmd", &json!({"cmd":"ls"}))
        .unwrap();
    let g = gateway(dir.path(), rt.clone()).await;
    // approved: true 写法。
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":a1.id.to_string(),"approved":true}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(v["data"], json!({"approved":true,"timedOut":false}));
    // decision: "allow"/"deny" 字符串写法。
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"session_id":session.id.to_string(),"approval_id":a2.id.to_string(),"decision":"deny"}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(v["data"], json!({"approved":false,"timedOut":false}));
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn approval_respond_rejects_unauthorized_and_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    let session = local_session(&rt, "mine");
    let foreign = rt
        .create_session(&CreateSession::plain(
            "foreign",
            Isolation {
                user_id: "other".into(),
                tenant_id: "other".into(),
                env_id: None,
            },
        ))
        .unwrap();
    let mine_pending = rt.request_approval(session.id, "t", &json!({})).unwrap();
    // 他人隔离域下也挂起一个同名可见 id 空间之外的审批：不得被本域应答。
    let theirs = rt.request_approval(foreign.id, "t", &json!({})).unwrap();
    let g = gateway(dir.path(), rt.clone()).await;
    // 归属失败优先于 pending 检查：foreign 会话 id → 403。
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":foreign.id.to_string(),"approvalId":mine_pending.id.to_string(),"approved":true}),
    )
    .await;
    assert_eq!(v["code"], 403, "{v}");
    // 会话归属合法但审批不属于该会话的 pending 集 → 403（不区分“不存在”）。
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":theirs.id.to_string(),"approved":true}),
    )
    .await;
    assert_eq!(v["code"], 403, "{v}");
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":uuid::Uuid::new_v4().to_string(),"approved":true}),
    )
    .await;
    assert_eq!(v["code"], 403, "unknown approval id must not 404-leak: {v}");
    // 缺 approvalId / 缺 approved 与 decision / decision 非法值 → 400。
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 400);
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":mine_pending.id.to_string()}),
    )
    .await;
    assert_eq!(v["code"], 400);
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":mine_pending.id.to_string(),"decision":"maybe"}),
    )
    .await;
    assert_eq!(v["code"], 400);
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn approval_respond_is_one_shot() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path());
    let session = local_session(&rt, "once");
    let a = rt.request_approval(session.id, "t", &json!({})).unwrap();
    let g = gateway(dir.path(), rt.clone()).await;
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":a.id.to_string(),"approved":true}),
    )
    .await;
    assert_eq!(v["data"]["approved"], true);
    // 应答后离开 pending 集：重复应答走 403（一次性语义，防重放）。
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":a.id.to_string(),"approved":false}),
    )
    .await;
    assert_eq!(v["code"], 403, "second respond must be rejected: {v}");
    g.shutdown().await.unwrap();
}

#[tokio::test]
async fn approval_response_after_expiry_is_timed_out_deny() {
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(dir.path()); // 80ms 审批超时
    let session = local_session(&rt, "late");
    let a = rt.request_approval(session.id, "t", &json!({})).unwrap();
    let g = gateway(dir.path(), rt.clone()).await;
    // 等到截止点之后再应答：即便 approved:true 也必须落为过期 deny。
    tokio::time::sleep(Duration::from_millis(150)).await;
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":a.id.to_string(),"approved":true}),
    )
    .await;
    assert_eq!(v["code"], 0, "{v}");
    assert_eq!(
        v["data"],
        json!({"approved":false,"timedOut":true}),
        "late approval must fail closed"
    );
    // 过期应答已占掉一次性应答位：再次应答 → 403。
    let (_, v) = request(
        g.port(),
        g.token(),
        "approval:respond",
        json!({"id":session.id.to_string(),"approvalId":a.id.to_string(),"approved":true}),
    )
    .await;
    assert_eq!(v["code"], 403, "{v}");
    g.shutdown().await.unwrap();
}
