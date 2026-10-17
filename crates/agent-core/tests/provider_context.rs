//! Provider 回合上下文集成测试（provider-context 卡）。
//!
//! 验收对象是**真实 Runtime 回合链**：网关 `session:send` → `Runtime::send_text`
//! → `run_turn` → `Provider::next_steps_with_context`。断言的输入内容来自 Runtime
//! 实际组装的 `TurnContext`（Composer 系统提示词 × 已启用记忆摘要 × 会话历史 ×
//! 本轮用户输入），不是独立调用 Composer 的单元测试。

use std::sync::{Arc, Mutex};

use agent_core::config::RuntimeConfig;
use agent_core::error::CoreError;
use agent_core::provider::{Provider, ProviderStep, TurnContext};
use agent_core::runtime::{CreateSession, Runtime};
use agent_core::schema::{Isolation, Mode, PermissionMode, Role};
use agent_prompts::Composer;

/// 捕获型 provider：只接受带上下文的新接口；旧接口被调用即失败。
struct Capturing {
    seen: Mutex<Vec<TurnContext>>,
}

impl Capturing {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
        })
    }

    /// 取出并清空已捕获上下文。
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
        Err(CoreError::Unsupported(
            "Runtime 必须走带上下文的回合接口，不得回落到旧 next_steps",
        ))
    }

    fn next_steps_with_context(
        &self,
        context: &TurnContext,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        self.seen.lock().expect("捕获锁").push(context.clone());
        Ok(vec![
            ProviderStep::Text(format!("收到：{}", context.user_text)),
            ProviderStep::Finished,
        ])
    }
}

/// 旧式 provider：只实现 `next_steps`（兼容性锚点：默认适配必须仍能跑回合）。
struct LegacyOnly {
    seen: Mutex<Vec<(uuid::Uuid, String)>>,
}

impl Provider for LegacyOnly {
    fn next_steps(
        &self,
        session_id: uuid::Uuid,
        user_text: &str,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        self.seen
            .lock()
            .expect("捕获锁")
            .push((session_id, user_text.to_string()));
        Ok(vec![
            ProviderStep::Text(user_text.to_string()),
            ProviderStep::Finished,
        ])
    }
}

fn isolation() -> Isolation {
    Isolation {
        user_id: "u".into(),
        tenant_id: "t".into(),
        env_id: None,
    }
}

/// 起一个真实 Runtime：memory 开关可控，provider 注入。
fn runtime(provider: Arc<dyn Provider>, memory_enabled: bool) -> Runtime {
    let dir = std::env::temp_dir().join(format!("ctx-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("workdir");
    let mut config = RuntimeConfig::default_v0();
    config.memory_enabled = memory_enabled;
    Runtime::builder()
        .workdir(&dir)
        .provider(provider)
        .config(config)
        .build()
        .expect("runtime")
}

fn session(rt: &Runtime, mode: Mode) -> agent_core::schema::Session {
    rt.create_session(&CreateSession {
        title: "上下文卡".into(),
        // 工作区取 runtime workdir，使记忆 home/workspace 与 Runtime 内部一致
        workspace_root: Some(rt.workdir().display().to_string()),
        mode,
        permission_mode: PermissionMode::ReadOnly,
        env_binding: None,
        isolation: isolation(),
    })
    .expect("create session")
}

/// 写身份层（人格名/用户称呼；不受跨会话记忆开关限制，agent-memory-spec §3）。
fn set_identity(rt: &Runtime) {
    let paths = agent_memory::MemoryPaths::new(rt.workdir().join(".lengsuo"), rt.workdir());
    let engine = agent_memory::MemoryEngine::new(paths, true);
    engine.set_ai_name("棱棱").expect("ai name");
    engine.set_user_name("澜").expect("user name");
}

/// 写用户记忆（直接走 agent-memory 落盘，Runtime 在回合时组装）。
fn set_user_memory(rt: &Runtime, text: &str) {
    let paths = agent_memory::MemoryPaths::new(rt.workdir().join(".lengsuo"), rt.workdir());
    let engine = agent_memory::MemoryEngine::new(paths, true);
    engine.set_user_memory(text).expect("user memory");
}

#[test]
fn turn_sends_composer_prompt_history_and_current_user_once() {
    let capture = Capturing::new();
    let rt = runtime(capture.clone(), false);
    set_identity(&rt);
    let s = session(&rt, Mode::Craft);

    rt.send_text(s.id, "第一轮输入").expect("turn 1");
    let first = {
        let mut seen = capture.take();
        assert_eq!(seen.len(), 1, "一次 session:send 必须恰好一次新接口调用");
        seen.remove(0)
    };
    assert_eq!(first.session_id, s.id);
    assert_eq!(first.mode, Mode::Craft);
    assert_eq!(first.user_text, "第一轮输入");
    assert!(first.history.is_empty(), "首轮历史必须为空: {first:?}");
    // Composer 系统提示词：模式标题行 + 公共尾硬规则
    assert!(
        first.system_prompt.contains("# 系统提示词 · 模式：craft"),
        "system prompt 必须是 Composer craft 模式产物:\n{}",
        first.system_prompt
    );
    assert!(
        first.system_prompt.contains("## 硬规则"),
        "硬规则段必须进入模型输入:\n{}",
        first.system_prompt
    );
    assert!(
        first
            .system_prompt
            .contains("## 工具能力（craft · 全工具）"),
        "craft 能力段缺失:\n{}",
        first.system_prompt
    );
    // 身份变量注入（agent-prompts 的 PromptVars 由记忆身份层提供）
    assert!(first.system_prompt.contains("棱棱"), "ai_name 未注入");
    assert!(
        first.system_prompt.contains("本次服务对象：澜"),
        "user_name 未注入"
    );

    rt.send_text(s.id, "第二轮输入").expect("turn 2");
    let second = {
        let mut seen = capture.take();
        assert_eq!(seen.len(), 1);
        seen.remove(0)
    };
    // 历史按时间序，且本轮 user_text 不在历史里重复出现
    let roles: Vec<Role> = second.history.iter().map(|m| m.role).collect();
    assert_eq!(
        roles,
        vec![Role::User, Role::Assistant],
        "第二轮历史应为用户/助手各一条: {:?}",
        second.history
    );
    assert_eq!(second.history[0].content, "第一轮输入");
    assert_eq!(second.history[1].content, "收到：第一轮输入");
    assert_eq!(second.user_text, "第二轮输入");
    let history_blob: String = second
        .history
        .iter()
        .map(|m| m.content.clone() + "\n")
        .collect();
    assert!(
        !history_blob.contains("第二轮输入"),
        "当前用户输入只能出现在 user_text，不得重复进历史"
    );
}

#[test]
fn enabled_memory_digest_reaches_provider_input_redacted() {
    let capture = Capturing::new();
    let rt = runtime(capture.clone(), true);
    set_user_memory(
        &rt,
        "用户偏好简洁回复；token=supersecretvalue123 是测试凭据",
    );
    let s = session(&rt, Mode::Craft);

    rt.send_text(s.id, "按偏好回复").expect("turn");
    let ctx = capture.take().remove(0);
    let digest = ctx
        .memory_digest
        .clone()
        .expect("memory.enabled 时上下文必须带记忆摘要");
    assert!(
        digest.contains("[用户记忆] 用户偏好简洁回复"),
        "记忆注入: {digest}"
    );
    assert!(
        ctx.system_prompt.contains("## 记忆摘要"),
        "记忆摘要必须进 system prompt:\n{}",
        ctx.system_prompt
    );
    assert!(ctx.system_prompt.contains("[用户记忆] 用户偏好简洁回复"));
    // 凭据不进模型上下文（§6：脱敏后才可注入）
    assert!(
        !ctx.system_prompt.contains("supersecretvalue123"),
        "凭据不得进 system prompt:\n{}",
        ctx.system_prompt
    );
    assert!(!digest.contains("supersecretvalue123"), "凭据不得进 digest");
    assert!(digest.contains("token=***"), "脱敏占位缺失: {digest}");
}

#[test]
fn disabled_memory_sends_no_digest_section() {
    let capture = Capturing::new();
    let rt = runtime(capture.clone(), false);
    set_user_memory(&rt, "不该出现的用户记忆内容");
    let s = session(&rt, Mode::Craft);

    rt.send_text(s.id, "关闭记忆时的输入").expect("turn");
    let ctx = capture.take().remove(0);
    assert!(ctx.memory_digest.is_none(), "关闭记忆 ⇒ 上下文无 digest");
    assert!(
        !ctx.system_prompt.contains("记忆摘要"),
        "关闭记忆时不得留下记忆段（含空标题）:\n{}",
        ctx.system_prompt
    );
    assert!(!ctx.system_prompt.contains("不该出现的用户记忆内容"));
}

#[test]
fn quick_mode_prompt_has_no_tool_surface() {
    let capture = Capturing::new();
    let rt = runtime(capture.clone(), false);
    let s = session(&rt, Mode::Quick);

    rt.send_text(s.id, "只答不操作").expect("turn");
    let ctx = capture.take().remove(0);
    assert_eq!(ctx.mode, Mode::Quick);
    assert!(
        ctx.system_prompt.contains("能力边界（quick · 只答不操作）"),
        "quick 能力段缺失:\n{}",
        ctx.system_prompt
    );
    assert!(ctx.system_prompt.contains("本模式不启用任何工具"));
    for tool in [
        "fs.list",
        "fs.read",
        "fs.write",
        "shell.exec",
        "net.fetch",
        "browser.open",
    ] {
        assert!(
            !ctx.system_prompt.contains(tool),
            "quick 不得带工具说明: {tool}"
        );
    }
    assert!(ctx.system_prompt.contains("## 硬规则"));
}

#[test]
fn ask_mode_prompt_is_readonly_only() {
    let capture = Capturing::new();
    let rt = runtime(capture.clone(), false);
    let s = session(&rt, Mode::Ask);

    rt.send_text(s.id, "只读提问").expect("turn");
    let ctx = capture.take().remove(0);
    assert!(ctx.system_prompt.contains("工具能力（ask · 只读白名单）"));
    assert!(ctx.system_prompt.contains("fs.list、fs.read、fs.search"));
    assert!(!ctx.system_prompt.contains("fs.write"), "ask 不得含写工具");
    assert!(
        !ctx.system_prompt.contains("shell.exec"),
        "ask 不得含执行工具"
    );
    assert!(
        !ctx.system_prompt.contains("browser.open"),
        "ask 不得含浏览器工具"
    );
    assert!(ctx.system_prompt.contains("## 硬规则"));
}

#[test]
fn plan_mode_prompt_carries_plan_gate() {
    let capture = Capturing::new();
    let rt = runtime(capture.clone(), false);
    let s = session(&rt, Mode::Plan);

    rt.send_text(s.id, "先做计划").expect("turn");
    let ctx = capture.take().remove(0);
    assert!(ctx.system_prompt.contains("## 规划门禁（plan）"));
    assert!(
        ctx.system_prompt.contains(Composer::plan_gate()),
        "plan 门禁片段必须原样进入模型输入"
    );
    // plan 复用 craft 能力段与硬规则
    assert!(ctx.system_prompt.contains("## 工具能力（craft · 全工具）"));
    assert!(ctx.system_prompt.contains("## 硬规则"));
}

#[test]
fn repeated_same_text_keeps_both_history_entries() {
    // 历史必须来自真实快照，而不是按文本相同性剔除本轮输入。
    let capture = Capturing::new();
    let rt = runtime(capture.clone(), false);
    let s = session(&rt, Mode::Craft);

    rt.send_text(s.id, "同样的话").expect("turn 1");
    rt.send_text(s.id, "同样的话").expect("turn 2");
    let contexts = capture.take();
    assert_eq!(contexts.len(), 2);
    assert!(contexts[0].history.is_empty());
    let second = &contexts[1];
    assert_eq!(second.user_text, "同样的话");
    assert_eq!(
        second
            .history
            .iter()
            .filter(|m| m.role == Role::User)
            .count(),
        1,
        "第一条 user 必须留在历史里: {:?}",
        second.history
    );
    assert_eq!(second.history[0].content, "同样的话");
}

#[test]
fn legacy_provider_still_runs_through_default_adapter() {
    // 兼容锚点：只实现旧 next_steps 的 provider（如 EchoProvider / 网关 Slow）
    // 经默认实现仍可跑完整回合。
    let legacy = Arc::new(LegacyOnly {
        seen: Mutex::new(Vec::new()),
    });
    let rt = runtime(legacy.clone(), false);
    let s = session(&rt, Mode::Ask);

    let receipt = rt.send_text(s.id, "旧接口输入").expect("legacy turn");
    assert!(receipt.last_seq > 0, "旧接口回合仍须产生事件");
    let seen = legacy.seen.lock().expect("捕获锁").clone();
    assert_eq!(seen, vec![(s.id, "旧接口输入".to_string())]);
    let stored = rt.get_session(s.id).expect("session");
    let last = stored.messages.last().expect("assistant 回复");
    assert_eq!(last.role, Role::Assistant);
    assert_eq!(last.content, "旧接口输入");
}
