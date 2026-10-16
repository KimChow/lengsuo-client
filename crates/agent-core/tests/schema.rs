//! 会话/消息 schema 与会话 CRUD 往返（开工说明 §3、§5、§6）。

use std::path::PathBuf;

use agent_core::blobs::BlobStore;
use agent_core::provider::EchoProvider;
use agent_core::runtime::{CreateSession, Runtime};
use agent_core::schema::{Isolation, Message, Mode, PermissionMode, Role, SCHEMA_VERSION};
use serde_json::json;
use std::sync::Arc;

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agent-core-schema-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create workdir");
    dir
}

fn isolation() -> Isolation {
    Isolation {
        user_id: "u-1".into(),
        tenant_id: "t-1".into(),
        env_id: Some("env-1".into()),
    }
}

#[test]
fn schema_json_field_names_are_frozen() {
    // 协议冻结点：字段名与枚举字符串值不得随意变更（轨道 E 依赖）。
    let value = serde_json::to_value(Mode::Craft).expect("mode");
    assert_eq!(value, json!("craft"));
    assert_eq!(
        serde_json::to_value(PermissionMode::ReadOnly).unwrap(),
        json!("readonly")
    );
    assert_eq!(
        serde_json::to_value(Role::ToolCall).unwrap(),
        json!("tool_call")
    );
    let parsed: Mode = serde_json::from_str("\"plan\"").expect("parse mode");
    assert_eq!(parsed, Mode::Plan);
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn session_create_get_roundtrip() {
    let rt = Runtime::builder()
        .workdir(workdir("cr"))
        .provider(Arc::new(EchoProvider))
        .build()
        .expect("runtime");
    let created = rt
        .create_session(&CreateSession {
            title: "首发会话".into(),
            workspace_root: Some("/tmp/ws".into()),
            mode: Mode::Ask,
            permission_mode: PermissionMode::ReadOnly,
            env_binding: Some("env-42".into()),
            isolation: isolation(),
        })
        .expect("create");
    assert_eq!(created.title, "首发会话");
    assert_eq!(created.mode, Mode::Ask);
    assert_eq!(created.env_binding.as_deref(), Some("env-42"));
    assert_eq!(created.isolation.env_id.as_deref(), Some("env-42"));
    assert!(created.messages.is_empty());
    assert_eq!(created.status, agent_core::schema::SessionStatus::Idle);

    let fetched = rt.get_session(created.id).expect("get");
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.created_at_ms, created.created_at_ms);

    let listed = rt.list_sessions(&isolation());
    assert_eq!(listed.len(), 1);
    let other = Isolation {
        user_id: "u-2".into(),
        tenant_id: "t-1".into(),
        env_id: None,
    };
    assert!(
        rt.list_sessions(&other).is_empty(),
        "隔离键必须过滤会话列表"
    );
}

#[test]
fn session_get_unknown_id_fails() {
    let rt = Runtime::builder()
        .workdir(workdir("miss"))
        .provider(Arc::new(EchoProvider))
        .build()
        .expect("runtime");
    let err = rt
        .get_session(uuid::Uuid::nil())
        .expect_err("missing session must fail");
    assert!(matches!(
        err,
        agent_core::error::CoreError::SessionNotFound(_)
    ));
}

#[test]
fn send_appends_user_and_assistant_messages() {
    let rt = Runtime::builder()
        .workdir(workdir("send"))
        .provider(Arc::new(EchoProvider))
        .build()
        .expect("runtime");
    let session = rt
        .create_session(&CreateSession::plain("s", isolation()))
        .expect("create");
    let receipt = rt.send_text(session.id, "你好").expect("send");
    assert!(!receipt.events.is_empty(), "发送必须产生事件");
    let after = rt.get_session(session.id).expect("get");
    assert_eq!(after.messages.len(), 2);
    assert_eq!(after.messages[0].role, Role::User);
    assert_eq!(after.messages[0].content, "你好");
    assert_eq!(after.messages[1].role, Role::Assistant);
    assert!(after.updated_at_ms >= after.created_at_ms);
}

#[test]
fn stop_marks_session_idle_and_rejects_send_when_done() {
    let rt = Runtime::builder()
        .workdir(workdir("stop"))
        .provider(Arc::new(EchoProvider))
        .build()
        .expect("runtime");
    let session = rt
        .create_session(&CreateSession::plain("s", isolation()))
        .expect("create");
    rt.stop_session(session.id).expect("stop");
    let after = rt.get_session(session.id).expect("get");
    assert_eq!(after.status, agent_core::schema::SessionStatus::Idle);
    rt.finish_session(session.id).expect("finish");
    let err = rt
        .send_text(session.id, "again")
        .expect_err("done session rejects send");
    assert!(matches!(
        err,
        agent_core::error::CoreError::SessionClosed(_)
    ));
}

#[test]
fn config_get_and_set_roundtrip() {
    let rt = Runtime::builder()
        .workdir(workdir("cfg"))
        .provider(Arc::new(EchoProvider))
        .build()
        .expect("runtime");
    let before = rt.config_get();
    assert_eq!(before.approval_timeout_ms, 120_000);
    assert_eq!(before.rpc_timeout_ms, 30_000);
    let patched = rt
        .config_set(&json!({ "approvalTimeoutMs": 5000, "defaultMode": "craft" }))
        .expect("set");
    assert_eq!(patched.approval_timeout_ms, 5000);
    assert_eq!(patched.default_mode, Mode::Craft);
    let err = rt
        .config_set(&json!({ "approvalTimeoutMs": 0 }))
        .expect_err("zero timeout rejected");
    assert!(matches!(
        err,
        agent_core::error::CoreError::InvalidConfig(_)
    ));
    // 未知字段必须拒绝，不静默忽略
    let err = rt
        .config_set(&json!({ "noSuchField": 1 }))
        .expect_err("unknown field rejected");
    assert!(matches!(
        err,
        agent_core::error::CoreError::InvalidConfig(_)
    ));
    assert_eq!(
        rt.config_get(),
        patched,
        "失败的 set 不得改变配置（基线 = 最近一次成功 set）"
    );
}

#[test]
fn large_tool_result_goes_to_blob_not_content() {
    let dir = workdir("blob");
    let rt = Runtime::builder()
        .workdir(dir.clone())
        .provider(Arc::new(EchoProvider))
        .build()
        .expect("runtime");
    let session = rt
        .create_session(&CreateSession::plain("s", isolation()))
        .expect("create");
    let huge = "x".repeat(64 * 1024);
    rt.record_tool_result(session.id, "fs.read", json!({"path": "/a"}), &huge)
        .expect("record");
    let after = rt.get_session(session.id).expect("get");
    let msg: &Message = after
        .messages
        .iter()
        .find(|m| m.role == Role::ToolResult)
        .expect("tool result message");
    assert!(
        msg.content.len() <= 512,
        "content 必须被收窄，实际 {}",
        msg.content.len()
    );
    let tool = msg.tool.as_ref().expect("tool ref");
    let blob_ref = tool.result_ref.as_ref().expect("result_ref present");
    let store = BlobStore::new(dir.join("blobs"));
    let restored = store.get(blob_ref).expect("blob readable");
    assert_eq!(restored, huge.into_bytes());
}
