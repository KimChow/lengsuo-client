//! 记忆摘要新鲜度（memory-freshness 卡）：会话内显式记忆更新必须进后续回合。
//!
//! 缺陷对象是**真实 Runtime 回合链**上的 `turn_memory_digest`：建会话时生成的
//! `session.memory_digest` 快照不得让本会话之后的记忆写入永远不进模型上下文。
//! 凭据一律测试专用假值。

use std::sync::{Arc, Mutex};

use agent_core::config::RuntimeConfig;
use agent_core::error::CoreError;
use agent_core::provider::{Provider, ProviderStep, TurnContext};
use agent_core::runtime::{CreateSession, Runtime};
use agent_core::schema::{Isolation, Mode, PermissionMode};
use serde_json::json;

const FAKE_SECRET: &str = "sk-fake-test-abcdef123456";

/// 捕获型 provider：只接受带上下文的新接口。
struct Capturing {
    seen: Mutex<Vec<TurnContext>>,
}

impl Capturing {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
        })
    }

    fn take(&self) -> Vec<TurnContext> {
        std::mem::take(&mut *self.seen.lock().expect("捕获锁"))
    }
}

impl Provider for Capturing {
    fn next_steps(
        &self,
        _session_id: uuid::Uuid,
        _user_text: &str,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        Err(CoreError::Unsupported("必须走带上下文的回合接口"))
    }

    fn next_steps_with_context(
        &self,
        context: &TurnContext,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        self.seen.lock().expect("捕获锁").push(context.clone());
        Ok(vec![ProviderStep::Finished])
    }
}

/// 起真实 Runtime（记忆开关可控）+ 独立工作区 + 捕获器。
fn runtime_with_capture(
    tag: &str,
    memory_enabled: bool,
) -> (Runtime, std::path::PathBuf, Arc<Capturing>) {
    let dir = std::env::temp_dir().join(format!("fresh-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("workdir");
    let ws = dir.join("ws");
    std::fs::create_dir_all(&ws).expect("workspace");
    let mut config = RuntimeConfig::default_v0();
    config.memory_enabled = memory_enabled;
    let capture = Capturing::new();
    let runtime = Runtime::builder()
        .workdir(&dir)
        .provider(capture.clone())
        .config(config)
        .build()
        .expect("runtime");
    (runtime, ws, capture)
}

fn mk_session(rt: &Runtime, ws: &std::path::Path) -> agent_core::schema::Session {
    rt.create_session(&CreateSession {
        title: "新鲜度".into(),
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

// ------------------------------------------------------ 会话内记忆更新必须进下一回合

#[test]
fn memory_update_midsession_reaches_next_turn_digest() {
    let (rt, ws, capture) = runtime_with_capture("mid", true);
    let s = mk_session(&rt, &ws);
    // 缺陷前提：建会话时已生成快照（此刻记忆三层皆空）。
    let snapshot = rt.get_session(s.id).expect("session").memory_digest;
    assert!(
        snapshot.is_some(),
        "enabled 建会话应留快照（缺陷前提成立）: {snapshot:?}"
    );

    // 会话内既有记忆写工具更新用户记忆 + 项目记忆。
    rt.execute_memory_tool(
        s.id,
        "memory.set_user",
        &json!({ "text": "更新后的用户偏好：中文回复" }),
    )
    .expect("set_user");
    rt.execute_memory_tool(
        s.id,
        "memory.set_project",
        &json!({ "text": "更新后的项目约定：crate=agent-core" }),
    )
    .expect("set_project");

    rt.send_text(s.id, "按最新偏好回复").expect("turn");
    let ctx = capture.take().remove(0);
    let digest = ctx
        .memory_digest
        .clone()
        .expect("memory.enabled ⇒ 本轮必须带摘要");
    assert!(
        digest.contains("更新后的用户偏好：中文回复"),
        "本会话内用户记忆更新必须进下一回合摘要: {digest}"
    );
    assert!(
        digest.contains("更新后的项目约定：crate=agent-core"),
        "本会话内项目记忆更新必须进下一回合摘要: {digest}"
    );
    // 摘要同步进 system prompt（Composer 记忆段）
    assert!(ctx.system_prompt.contains("## 记忆摘要"));
    assert!(ctx
        .system_prompt
        .contains("更新后的项目约定：crate=agent-core"));
}

#[test]
fn disabled_after_update_sends_no_memory_layers() {
    let (rt, ws, capture) = runtime_with_capture("off", true);
    let s = mk_session(&rt, &ws);
    rt.execute_memory_tool(
        s.id,
        "memory.set_user",
        &json!({ "text": "用户层机密偏好" }),
    )
    .expect("set_user");
    rt.execute_memory_tool(
        s.id,
        "memory.set_project",
        &json!({ "text": "项目层机密约定" }),
    )
    .expect("set_project");

    rt.send_text(s.id, "开启时回合").expect("turn 1");
    let on = capture.take().remove(0);
    assert!(on.memory_digest.is_some(), "开启时必须有摘要");

    rt.config_set(&json!({ "memoryEnabled": false }))
        .expect("config_set");
    rt.send_text(s.id, "关闭时回合").expect("turn 2");
    let off = capture.take().remove(0);
    assert!(
        off.memory_digest.is_none(),
        "关闭记忆 ⇒ 本轮摘要必须为 None，实际 {:?}",
        off.memory_digest
    );
    assert!(!off.system_prompt.contains("记忆摘要"));
    assert!(!off.system_prompt.contains("用户层机密偏好"));
    assert!(!off.system_prompt.contains("项目层机密约定"));
}

#[test]
fn midsession_credential_update_is_redacted_in_digest() {
    let (rt, ws, capture) = runtime_with_capture("cred", true);
    let s = mk_session(&rt, &ws);
    rt.execute_memory_tool(
        s.id,
        "memory.set_user",
        &json!({ "text": format!("偏好简洁；api_key={FAKE_SECRET}") }),
    )
    .expect("set_user");

    rt.send_text(s.id, "回合").expect("turn");
    let ctx = capture.take().remove(0);
    let digest = ctx.memory_digest.expect("enabled ⇒ digest");
    assert!(
        !digest.contains(FAKE_SECRET) && !ctx.system_prompt.contains(FAKE_SECRET),
        "凭据值不得进模型上下文"
    );
    assert!(digest.contains("***"), "脱敏占位缺失: {digest}");
}

// ------------------------------------------------------------ 读取失败：本回合无摘要但不阻塞

#[test]
fn compose_failure_yields_no_digest_and_warns_without_stale_fallback() {
    let (rt, ws, capture) = runtime_with_capture("fail", true);
    let s = mk_session(&rt, &ws);
    rt.execute_memory_tool(
        s.id,
        "memory.set_user",
        &json!({ "text": "已建快照里的敏感旧记忆" }),
    )
    .expect("set_user");
    rt.send_text(s.id, "第一回合").expect("turn 1");
    let first = capture.take().remove(0);
    assert!(
        first
            .memory_digest
            .as_deref()
            .unwrap_or_default()
            .contains("已建快照里的敏感旧记忆"),
        "第一回合摘要应含刚写入的记忆: {:?}",
        first.memory_digest
    );
    assert!(
        rt.get_session(s.id)
            .expect("session")
            .memory_digest
            .is_some(),
        "会话上应留有快照（缺陷前提）"
    );

    // 注入读取失败：把项目记忆文件路径摆成**目录** ⇒ 读取返回非 NotFound 的 IO 错误
    // ⇒ compose fail-closed 上抛 Err（文件缺失只算「该层无内容」，不能用来注错）。
    let project_file = ws.join(".lengsuo").join("memory").join("MEMORY.md");
    std::fs::create_dir_all(&project_file).expect("block project memory with dir");

    let receipt = rt
        .send_text(s.id, "记忆读取失败时的回合")
        .expect("turn 2 不得被阻塞");
    assert!(receipt.last_seq > 0, "失败回合仍须推进事件序号");
    let second = capture.take().remove(0);
    assert_eq!(second.user_text, "记忆读取失败时的回合");
    assert!(
        second.memory_digest.is_none(),
        "读取失败本回合不得带摘要，更不得回退旧敏感快照，实际 {:?}",
        second.memory_digest
    );
    assert!(
        !second.system_prompt.contains("已建快照里的敏感旧记忆"),
        "旧敏感记忆不得回退进 system prompt:\n{}",
        second.system_prompt
    );
    assert!(!second.system_prompt.contains("记忆摘要"));

    // 告警可观测：事件流里有 memory_compose_failed 的 warning。
    let warnings: Vec<String> = rt
        .event_log()
        .replay(s.id, 0, 500)
        .expect("replay")
        .iter()
        .filter(|e| e.kind == "warning")
        .map(|e| e.payload.to_string())
        .collect();
    assert!(
        warnings.iter().any(|p| p.contains("memory_compose_failed")),
        "读取失败必须留下告警事件，实际: {warnings:?}"
    );
}
