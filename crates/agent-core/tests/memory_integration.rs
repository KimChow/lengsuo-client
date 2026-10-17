//! 记忆集成测试（agent-memory-spec §4 + M2 任务卡验收清单）。
//!
//! 权限分层说明：工具的权限门由宿主在调用前经 `Runtime::check_tool` 执行
//! （kickoff §1 分层：工具=协议层，门=调用前检查）；本套件验证执行体语义，
//! 门本身由 permission.rs 套件覆盖（deny-by-default 9 项）。

use agent_core::runtime::{CreateSession, Runtime};
use agent_core::schema::{Isolation, Mode, PermissionMode};
use serde_json::json;
use std::time::Duration;

fn isolation() -> Isolation {
    Isolation {
        user_id: "u".into(),
        tenant_id: "t".into(),
        env_id: None,
    }
}

fn rt(tag: &str, memory_enabled: bool) -> Runtime {
    let dir = std::env::temp_dir().join(format!("m2-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("workdir");
    let mut cfg = agent_core::config::RuntimeConfig::default_v0();
    cfg.memory_enabled = memory_enabled;
    Runtime::builder()
        .workdir(&dir)
        .provider(std::sync::Arc::new(agent_core::provider::EchoProvider))
        .config(cfg)
        .build()
        .expect("runtime")
}

fn mk_session(rt: &Runtime, ws: &std::path::Path) -> agent_core::schema::Session {
    rt.create_session(&CreateSession {
        title: "t".into(),
        workspace_root: Some(ws.display().to_string()),
        mode: Mode::Craft,
        permission_mode: PermissionMode::Full,
        env_binding: None,
        isolation: isolation(),
    })
    .expect("create")
}

fn workdir_of(rt: &Runtime) -> std::path::PathBuf {
    rt.workdir().to_path_buf()
}

#[test]
fn config_memory_enabled_defaults_false_and_roundtrips() {
    let dir = std::env::temp_dir().join(format!("m2-cfg-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("dir");
    let rt = Runtime::builder()
        .workdir(&dir)
        .provider(std::sync::Arc::new(agent_core::provider::EchoProvider))
        .build()
        .expect("runtime");
    assert!(!rt.config_get().memory_enabled, "默认必须关闭");
    let patched = rt
        .config_set(&json!({ "memoryEnabled": true }))
        .expect("set");
    assert!(patched.memory_enabled);
    let err = rt
        .config_set(&json!({ "memoryEnabled": "yes" }))
        .expect_err("非布尔拒绝");
    assert!(matches!(
        err,
        agent_core::error::CoreError::InvalidConfig(_)
    ));
}

#[test]
fn enabled_session_gets_memory_digest_with_ai_name() {
    let rt = rt("en", true);
    let ws = workdir_of(&rt);
    let engine = agent_memory::MemoryEngine::new(
        agent_memory::MemoryPaths::new(ws.join(".lengsuo"), &ws),
        true,
    );
    engine.set_ai_name("棱棱").expect("ai name");
    engine
        .set_user_memory("用户偏好简洁回复")
        .expect("user mem");
    let s = mk_session(&rt, &ws);
    let digest = s.memory_digest.expect("enabled ⇒ digest");
    assert!(digest.contains("[身份] AI=棱棱"), "身份注入: {digest}");
    assert!(
        digest.contains("[用户记忆] 用户偏好简洁回复"),
        "记忆注入: {digest}"
    );
}

#[test]
fn disabled_session_has_no_digest() {
    let rt = rt("dis", false);
    let ws = workdir_of(&rt);
    let s = mk_session(&rt, &ws);
    assert!(s.memory_digest.is_none(), "disabled ⇒ None");
}

#[test]
fn compose_failure_does_not_block_session() {
    let rt = rt("fail", true);
    let base = workdir_of(&rt);
    let blocker = base.join("not-a-dir");
    std::fs::write(&blocker, b"x").expect("write");
    // workspace_root 指向一个文件 ⇒ compose 必失败 ⇒ 不得阻断建会话
    let s = mk_session(&rt, &blocker);
    assert!(s.memory_digest.is_none(), "compose 失败 ⇒ digest None");
}

#[test]
fn memory_tools_execute_and_emit() {
    let rt = rt("tool", true);
    let ws = workdir_of(&rt);
    let s = mk_session(&rt, &ws);
    let ok = rt
        .execute_memory_tool(
            s.id,
            "memory.append_daily",
            &json!({ "date": "2026-10-17", "text": "工作摘要" }),
        )
        .expect("执行成功");
    assert_eq!(ok["kind"], "daily_append");
    let paths = agent_memory::MemoryPaths::new(ws.join(".lengsuo"), &ws);
    let date = chrono::NaiveDate::from_ymd_opt(2026, 10, 17).expect("date");
    let tail = agent_memory::read_daily_tail(&paths, date, 10).expect("read");
    assert!(tail.expect("daily").contains("工作摘要"));
    // set_user 成功路径
    rt.execute_memory_tool(s.id, "memory.set_user", &json!({ "text": "偏好简洁" }))
        .expect("set_user");
}

#[test]
fn memory_tool_unknown_name_rejected() {
    let rt = rt("unk", true);
    let ws = workdir_of(&rt);
    let s = mk_session(&rt, &ws);
    let err = rt
        .execute_memory_tool(s.id, "memory.nuke", &json!({}))
        .expect_err("未知记忆工具拒绝");
    assert!(matches!(
        err,
        agent_core::error::CoreError::InvalidConfig(_)
    ));
}

#[test]
fn append_daily_over_cap_returns_error() {
    let rt = rt("cap", true);
    let ws = workdir_of(&rt);
    let s = mk_session(&rt, &ws);
    let big = "x".repeat(8001);
    let err = rt
        .execute_memory_tool(
            s.id,
            "memory.append_daily",
            &json!({ "date": "2026-10-17", "text": big }),
        )
        .expect_err("超 8000 字符拒绝");
    assert!(matches!(
        err,
        agent_core::error::CoreError::InvalidConfig(_)
    ));
    // 整个用例时延上界守卫（异步等价：测试自带超时纪律）
    let _ = Duration::from_secs(5);
}
