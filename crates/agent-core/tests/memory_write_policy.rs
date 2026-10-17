//! 记忆写路径策略（MEMORY-SPEC §2 + 开工说明 §4）：脱敏先于落盘、开关覆盖全部记忆写。
//!
//! 权限分层同 `memory_integration.rs`：权限门由宿主经 `Runtime::check_tool` 前置执行，
//! 本套件只验执行体自身的策略面（内容净化与开关闸门），不重复门本身。
//! 凭据一律用测试专用假值，禁止真实值进入仓库与日志。

use agent_core::runtime::{CreateSession, Runtime};
use agent_core::schema::{Isolation, Mode, PermissionMode};
use serde_json::json;

const FAKE_SECRET: &str = "sk-fake-test-abcdef123456";

fn rt(tag: &str, memory_enabled: bool) -> Runtime {
    let dir = std::env::temp_dir().join(format!("m2wp-{tag}-{}", uuid::Uuid::new_v4()));
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
        title: "写策略".into(),
        workspace_root: Some(ws.display().to_string()),
        mode: Mode::Craft,
        permission_mode: PermissionMode::Full,
        env_binding: None,
        isolation: Isolation {
            user_id: "u".into(),
            tenant_id: "t".into(),
            env_id: None,
        },
    })
    .expect("create")
}

fn paths_of(rt: &Runtime, ws: &std::path::Path) -> agent_memory::MemoryPaths {
    agent_memory::MemoryPaths::new(rt.workdir().join(".lengsuo"), ws)
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

// ------------------------------------------------------------- §2 脱敏先于落盘

#[test]
fn memory_tool_writes_persist_redacted_text_not_credentials() {
    let rt = rt("redact", true);
    let ws = rt.workdir().to_path_buf();
    let s = mk_session(&rt, &ws);
    let paths = paths_of(&rt, &ws);

    rt.execute_memory_tool(
        s.id,
        "memory.set_user",
        &json!({ "text": format!("用户偏好；api_key={FAKE_SECRET}；简洁回复") }),
    )
    .expect("set_user 成功");
    let on_disk = read(&paths.user_memory_file());
    assert!(
        !on_disk.contains(FAKE_SECRET),
        "凭据值不得落记忆文件（规格 §2：先过脱敏再落盘），实际 {on_disk:?}"
    );
    assert!(on_disk.contains("***"), "脱敏标记应保留：{on_disk:?}");
    assert!(
        on_disk.contains("用户偏好"),
        "非敏感正文不得被改动：{on_disk:?}"
    );

    rt.execute_memory_tool(
        s.id,
        "memory.set_project",
        &json!({ "text": format!("本仓无 unsafe；token: {FAKE_SECRET}") }),
    )
    .expect("set_project 成功");
    let project = read(&paths.project_memory_file());
    assert!(
        !project.contains(FAKE_SECRET),
        "项目记忆不得含凭据值：{project:?}"
    );

    rt.execute_memory_tool(
        s.id,
        "identity.set_soul",
        &json!({ "text": format!("先复现再动手；password={FAKE_SECRET}") }),
    )
    .expect("set_soul 成功");
    let soul = read(&paths.identity_dir().join("SOUL.md"));
    assert!(
        !soul.contains(FAKE_SECRET),
        "身份层同样不得含凭据值：{soul:?}"
    );
}

#[test]
fn daily_append_tool_persists_redacted_text() {
    let rt = rt("redact-daily", true);
    let ws = rt.workdir().to_path_buf();
    let s = mk_session(&rt, &ws);
    let date = chrono::NaiveDate::from_ymd_opt(2026, 10, 18).expect("date");

    rt.execute_memory_tool(
        s.id,
        "memory.append_daily",
        &json!({ "date": "2026-10-18", "text": format!("完成写策略验收；secret={FAKE_SECRET}") }),
    )
    .expect("append 成功");
    let tail = agent_memory::read_daily_tail(&paths_of(&rt, &ws), date, 10)
        .expect("read")
        .expect("daily 存在");
    assert!(
        !tail.contains(FAKE_SECRET),
        "当日日志不得含凭据值：{tail:?}"
    );
    assert!(tail.contains("完成写策略验收"), "正文保留：{tail:?}");
}

#[test]
fn created_digest_does_not_leak_credential_values() {
    // 前置写入含凭据的记忆文件，再建会话：digest 注入面也不得带出值。
    let rt = rt("digest-leak", true);
    let ws = rt.workdir().to_path_buf();
    let engine = agent_memory::MemoryEngine::new(paths_of(&rt, &ws), true);
    engine
        .set_user_memory(&format!("偏好简洁；api_key={FAKE_SECRET}"))
        .expect("seed");

    let s = mk_session(&rt, &ws);
    let digest = s.memory_digest.expect("enabled ⇒ digest");
    assert!(
        !digest.contains(FAKE_SECRET),
        "memory_digest 不得含凭据值：{digest:?}"
    );
    assert!(digest.contains("[用户记忆]"), "记忆层应注入：{digest:?}");
}

// --------------------------------------------------------- §2 开关覆盖全部记忆写

#[test]
fn daily_append_tool_is_refused_when_memory_disabled() {
    // 规格 §2：enabled=false ⇒ 所有记忆写返回 Disabled；不得绕开开关落盘。
    let rt = rt("dis-append", false);
    let ws = rt.workdir().to_path_buf();
    let s = mk_session(&rt, &ws);

    let err = rt
        .execute_memory_tool(
            s.id,
            "memory.append_daily",
            &json!({ "date": "2026-10-19", "text": "关闭状态下的日志写" }),
        )
        .expect_err("开关关闭时 append 必须拒绝");
    assert!(
        err.to_string().contains("未开启"),
        "错误须表达开关语义，实际 {err}"
    );
    let paths = paths_of(&rt, &ws);
    let date = chrono::NaiveDate::from_ymd_opt(2026, 10, 19).expect("date");
    assert!(
        !paths.daily_file(date).exists(),
        "拒绝不得产生部分写入：{}",
        paths.daily_file(date).display()
    );
    assert!(
        !agent_memory::MemoryPaths::new(rt.workdir().join(".lengsuo"), &ws)
            .project_memory_dir()
            .exists(),
        "开关关闭时不得创建项目记忆目录"
    );
}

#[test]
fn identity_tool_still_writes_when_memory_disabled() {
    // 反向护栏：身份层是产品人格，规格 §2 明确不受开关限制——收紧记忆写时不得误伤。
    let rt = rt("dis-identity", false);
    let ws = rt.workdir().to_path_buf();
    let s = mk_session(&rt, &ws);

    rt.execute_memory_tool(s.id, "identity.set_soul", &json!({ "text": "冷静、克制" }))
        .expect("身份写不受开关限制");
    let soul = read(&paths_of(&rt, &ws).identity_dir().join("SOUL.md"));
    assert_eq!(soul, "冷静、克制");
    // 记忆三层仍被压制：compose 不含记忆段。
    let s2 = mk_session(&rt, &std::path::PathBuf::from(&ws));
    let digest = s2.memory_digest;
    assert!(
        digest.is_none(),
        "disabled ⇒ 会话不注入 digest，实际 {digest:?}"
    );
    assert!(!s.id.is_nil());
}
