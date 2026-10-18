//! 步语义契约测试（docs/step-semantics-spec.md §5 清单）。
//!
//! 铁律：一步 = 一次逻辑 LLM 调用；工具结果落盘后 **reload 历史** 开新步；
//! 禁止 in-memory tool loop（金标：opencode `AGENTS.md:183,186`，
//! `packages/core/src/session/runner/llm.ts:191-198` + `step.ts:107,281`）。
//!
//! 现状 `Runtime::run_turn`（`src/runtime/turns.rs:22-69`）是一次调用返回
//! `Vec<ProviderStep>` 的内存批消费——凡断言"reload 开新步"的契约在现实现上
//! **注定失败**，按约定标 `#[ignore]` 并在规格 §2 差距表登记；实现落地后去掉
//! ignore 即成为验收。`[激活]` 项锚定现状必须守住的下限，不得回退。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use agent_core::config::RuntimeConfig;
use agent_core::error::CoreError;
use agent_core::provider::{Provider, ProviderStep, TurnContext};
use agent_core::runtime::{CreateSession, Runtime, TurnReceipt};
use agent_core::schema::{Isolation, Mode, PermissionMode, Role};

/// 共享脚本化 Mock（`ChatProvider`/`ToolExecutor` 面，供 C5 熔断契约使用）。
mod agent_support;

// ---------------- 脚本化 provider（Runtime 面 harness） ----------------

/// 按队列出步的脚本化 provider：每次 `next_steps_with_context` 调用弹出一步的
/// 产出，并记录收到的完整 `TurnContext`（供断言"第 n 次调用的历史里有什么"）。
struct ScriptedProvider {
    steps: Mutex<VecDeque<Vec<ProviderStep>>>,
    seen: Mutex<Vec<TurnContext>>,
}

impl ScriptedProvider {
    fn new(steps: Vec<Vec<ProviderStep>>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into()),
            seen: Mutex::new(Vec::new()),
        })
    }

    /// provider 被调用次数 = 已消耗的 LLM 调用数（= 步数的现状代理）。
    fn calls(&self) -> usize {
        self.seen.lock().expect("锁").len()
    }

    /// 第 n 次调用（0 起）收到的上下文副本。
    fn ctx_at(&self, n: usize) -> TurnContext {
        self.seen.lock().expect("锁")[n].clone()
    }
}

impl Provider for ScriptedProvider {
    fn next_steps(
        &self,
        _session_id: uuid::Uuid,
        _user_text: &str,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        Err(CoreError::Unsupported(
            "契约测试只走带上下文接口（provider_context 卡约束）",
        ))
    }

    fn next_steps_with_context(
        &self,
        context: &TurnContext,
    ) -> Result<Vec<ProviderStep>, CoreError> {
        self.seen.lock().expect("锁").push(context.clone());
        self.steps
            .lock()
            .expect("锁")
            .pop_front()
            .ok_or(CoreError::Unsupported(
                "脚本已耗尽：出现计划外的第 n+1 次调用",
            ))
    }
}

/// 无工具、单步收敛的脚本（text + done）。
fn text_step(text: &str) -> Vec<ProviderStep> {
    vec![ProviderStep::Text(text.to_string()), ProviderStep::Finished]
}

/// 一步以工具调用终结（无文本、无 Finished）。
fn tool_step(name: &str, args: Value) -> Vec<ProviderStep> {
    vec![ProviderStep::ToolCall {
        name: name.to_string(),
        args,
    }]
}

fn runtime(provider: Arc<dyn Provider>) -> Runtime {
    let dir = std::env::temp_dir().join(format!("step-ctx-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("workdir");
    Runtime::builder()
        .workdir(&dir)
        .provider(provider)
        .config(RuntimeConfig::default_v0())
        .build()
        .expect("runtime")
}

fn craft_session(rt: &Runtime) -> agent_core::schema::Session {
    rt.create_session(&CreateSession {
        title: "步语义契约".into(),
        workspace_root: Some(rt.workdir().display().to_string()),
        mode: Mode::Craft,
        permission_mode: PermissionMode::Full,
        env_binding: None,
        isolation: Isolation {
            user_id: "u".into(),
            tenant_id: "t".into(),
            env_id: None,
        },
    })
    .expect("create session")
}

/// receipt 事件 kind 序列。
fn receipt_kinds(receipt: &TurnReceipt) -> Vec<String> {
    receipt.events.iter().map(|e| e.kind.clone()).collect()
}

// ---------------- [激活] 锚点：现状必须守住的下限 ----------------

/// C1a：一次 `send_text` 恰好一次 provider 调用，事件以 `done` 收口。
/// （"一步一调用"的下界：今天不得出现一次输入调多次模型；续步实现后此
/// 不变式升级为"每个新步恰好一次调用"，由 C2 接管。）
#[test]
fn one_send_text_makes_exactly_one_provider_call() {
    let p = ScriptedProvider::new(vec![text_step("收到，收工")]);
    let rt = runtime(p.clone());
    let s = craft_session(&rt);

    let receipt = rt.send_text(s.id, "开工").expect("turn");
    assert_eq!(p.calls(), 1, "一次 send_text 必须恰好一次 LLM 调用");
    assert_eq!(
        receipt_kinds(&receipt).last().map(String::as_str),
        Some("done"),
        "回合事件必须以 done 收口: {:?}",
        receipt_kinds(&receipt)
    );
}

/// C1b：receipt 事件与持久 JSONL 回放逐项一致（durable record 单队列锚点）。
#[test]
fn events_durable_and_replay_matches_receipt() {
    let p = ScriptedProvider::new(vec![text_step("落盘校验")]);
    let rt = runtime(p.clone());
    let s = craft_session(&rt);

    // 建会话本身会先发一条 session_update（回合之前）；契约只比对回合区段。
    let pre_turn_seq = rt.get_session(s.id).expect("session").last_seq;
    let receipt = rt.send_text(s.id, "落盘").expect("turn");
    let replayed = rt
        .event_log()
        .replay(s.id, pre_turn_seq, 500)
        .expect("replay");
    let receipt_seq: Vec<u64> = receipt.events.iter().map(|e| e.seq).collect();
    let replay_seq: Vec<u64> = replayed.iter().map(|e| e.seq).collect();
    assert_eq!(receipt_seq, replay_seq, "receipt 即持久日志，不得旁路");
    let replay_kinds: Vec<&str> = replayed.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        replay_kinds,
        vec!["text", "done"],
        "回放 kind 序列必须与 receipt 一致"
    );
    assert_eq!(receipt.last_seq, *replay_seq.last().expect("有事件"));
}

/// C1c：工具调用/结果经宿主落盘后，下一次 provider 调用的历史必须**重读**到
/// `ToolCall` + `ToolResult` 两类消息（reload-from-durable-history 的现状下限：
/// 今天靠"下一次 send_text"体现；R3 落地后同一断言须在无新输入时由续步满足）。
#[test]
fn tool_result_reloaded_into_next_provider_history() {
    let p = ScriptedProvider::new(vec![
        tool_step("fs.write", json!({"path": "a.txt"})),
        text_step("写完了"),
    ]);
    let rt = runtime(p.clone());
    let s = craft_session(&rt);

    let first = rt.send_text(s.id, "写 a.txt").expect("turn 1");
    assert!(
        receipt_kinds(&first).contains(&"tool_use".to_string()),
        "工具步必须发 tool_use: {:?}",
        receipt_kinds(&first)
    );
    rt.record_tool_call(s.id, "fs.write", &json!({"path": "a.txt"}))
        .expect("记录调用");
    rt.record_tool_result(s.id, "fs.write", json!({"path": "a.txt"}), "ok")
        .expect("记录结果");

    rt.send_text(s.id, "继续").expect("turn 2");
    let ctx = p.ctx_at(1);
    let roles: Vec<Role> = ctx.history.iter().map(|m| m.role).collect();
    assert!(
        roles.contains(&Role::ToolCall),
        "第 2 次调用的历史必须含 ToolCall 消息: {roles:?}"
    );
    assert!(
        roles.contains(&Role::ToolResult),
        "第 2 次调用的历史必须含 ToolResult 消息: {roles:?}"
    );
    let tr = ctx
        .history
        .iter()
        .find(|m| m.role == Role::ToolResult)
        .expect("ToolResult 在历史里");
    assert_eq!(tr.tool.as_ref().expect("带 tool 信息").name, "fs.write");
}

// ---------------- #[ignore]：目标契约（实现后去掉 ignore） ----------------

/// C2（差距 R1/R3，规格 §5）：含工具步终结后，运行时必须 **reload 历史自动开新步**
/// ——一次 `send_text` 在脚本 `[工具步, 文本步]` 下应看到 2 次调用，且第 2 次的
/// 历史已含本步 `ToolResult`。现状 run_turn 单次调用摊批、工具后不再调模型 ⇒ 失败。
#[test]
#[ignore = "run_turn 尚为 in-memory batch（§2 R1/R3）：工具后 reload 开新步未实现"]
fn tool_call_ends_step_and_reloads_for_new_step() {
    let p = ScriptedProvider::new(vec![
        tool_step("fs.read", json!({"path": "a.txt"})),
        text_step("读完了"),
    ]);
    let rt = runtime(p.clone());
    let s = craft_session(&rt);

    rt.send_text(s.id, "读 a.txt").expect("turn");
    assert_eq!(
        p.calls(),
        2,
        "工具步终结后必须由 reload 的历史开新步（金标 llm.ts:194 `continuing → runStep(step+1)`）"
    );
    let second = p.ctx_at(1);
    assert!(
        second.history.iter().any(|m| m.role == Role::ToolResult),
        "第 2 步的历史必须含第 1 步的 ToolResult"
    );
}

/// C3（差距 R1，规格 §5）：禁止 in-memory tool loop——provider 一次调用返回
/// `[ToolCall, Text, Finished]` 时，`text` 事件必须出现在**下一次** LLM 调用之后
/// （即本步在工具处终结），而不是同批在内存里消费完。现状同批发出 ⇒ 失败。
#[test]
#[ignore = "next_steps 批量返回被内存 for 逐条消费（§2 R1）：步内禁止续批未实现"]
fn no_in_memory_text_after_tool_call() {
    let p = ScriptedProvider::new(vec![
        vec![
            ProviderStep::ToolCall {
                name: "fs.read".into(),
                args: json!({"path": "b.txt"}),
            },
            ProviderStep::Text("不该出现的同批文本".into()),
            ProviderStep::Finished,
        ],
        text_step("新步文本"),
    ]);
    let rt = runtime(p.clone());
    let s = craft_session(&rt);

    rt.send_text(s.id, "读 b.txt").expect("turn");
    assert_eq!(
        p.calls(),
        2,
        "本步必须在 tool_use 处终结；批内尾随文本不得被内存消费，须由 reload 后的新步（第 2 次调用）产出"
    );
    let assistant_texts: Vec<String> = rt
        .get_session(s.id)
        .expect("session")
        .messages
        .iter()
        .filter(|m| m.role == Role::Assistant)
        .map(|m| m.content.clone())
        .collect();
    assert_eq!(
        assistant_texts,
        vec!["新步文本".to_string()],
        "同批尾随文本不得落进持久历史（金标 step.ts:122-134：本步止于工具结算）"
    );
}

/// C4（差距 R4，规格 §3）：步边界事件——含工具回合应发
/// `step_start → tool_use → step_end → step_start → text → step_end → done{steps}`；
/// `done` 只属于回合收敛，不冒充步末。现状无 `step_start/step_end` kind ⇒ 失败。
#[test]
#[ignore = "EventKind 无 step_start/step_end（§2 R4）：步边界事件词汇未落地"]
fn step_boundary_events_present() {
    let p = ScriptedProvider::new(vec![
        tool_step("fs.read", json!({"path": "c.txt"})),
        text_step("齐了"),
    ]);
    let rt = runtime(p.clone());
    let s = craft_session(&rt);

    let receipt = rt.send_text(s.id, "读 c.txt").expect("turn");
    let kinds = receipt_kinds(&receipt);
    let count = |want: &str| kinds.iter().filter(|k| k.as_str() == want).count();
    assert_eq!(count("step_start"), 2, "每步恰一条 step_start: {kinds:?}");
    assert_eq!(count("step_end"), 2, "每步恰一条 step_end: {kinds:?}");
    assert_eq!(count("done"), 1, "done 只属于回合收敛: {kinds:?}");
    let tool_idx = kinds
        .iter()
        .position(|k| k == "tool_use")
        .expect("tool_use");
    let end_idx = kinds
        .iter()
        .position(|k| k == "step_end")
        .expect("step_end");
    assert!(
        end_idx > tool_idx && tool_idx < kinds.iter().position(|k| k == "step_start").unwrap() + 2,
        "tool_use 必须落在第一个 step_start 与 step_end 之间: {kinds:?}"
    );
    let done = receipt
        .events
        .iter()
        .find(|e| e.kind == "done")
        .expect("done");
    assert_eq!(done.payload["steps"], 2, "done 载荷须报步数");
}

/// C5（差距 R5/R7，规格 §4）：maxSteps 熔断末步语义——到限不是硬停，而是**再走
/// 一步缴械的纯文本步**（金标 `llm.ts:226,240-244` + `max-steps.ts`）。用 AgentLoop
/// 的 `MockProvider`（`agent_support`，可观测每回合 `tool_names()`）断言：max_steps=2
/// 且脚本全带工具时，存在第 3 次调用且其工具面为空、无第 3 次执行、final_text 非空。
/// 现状 loop.rs:218-233 到限直接 break ⇒ 失败。
#[test]
#[ignore = "熔断为硬停非末步缴械（§2 R5/R7）：MAX_STEPS 末步提示词未实现"]
fn max_steps_final_step_disables_tools() {
    use agent_core::schema::Event;
    use agent_core::{AgentLoop, LoopLimits, LoopStatus, PlanGate};
    use agent_support::{call, turn, MockExecutor, MockProvider, Recorder};
    use uuid::Uuid;

    let scripted = (0..4)
        .map(|i| turn("还在跑。", call("task.list", json!({"page": i}))))
        .collect();
    let provider = MockProvider::new(scripted);
    let executor = MockExecutor::default();
    let rec = Recorder::default();
    let emit = |ev: Event| rec.push(ev);
    let mut agent = AgentLoop::new(
        &provider,
        &executor,
        Mode::Ask,
        LoopLimits { max_steps: 2 },
        PlanGate::default(),
        &emit,
    )
    .session_id(Uuid::nil())
    .seq_base(0);

    let outcome = agent.run("列任务").expect("熔断应正常返回");
    assert_eq!(outcome.status, LoopStatus::MaxStepsReached);
    assert_eq!(
        provider.chat_calls(),
        3,
        "到限后必须追加一次末步调用（金标 toolChoice:none 的总结步），而非硬停"
    );
    assert!(
        provider.tool_names()[2].is_empty(),
        "末步可见工具面必须为空: {:?}",
        provider.tool_names()
    );
    assert_eq!(executor.executed().len(), 2, "末步不得执行工具");
    assert!(!outcome.final_text.is_empty(), "熔断末步必须产出总结文本");
}
