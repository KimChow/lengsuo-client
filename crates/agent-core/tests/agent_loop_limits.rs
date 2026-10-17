//! Agent loop 测试（maxSteps 熔断、交付物提醒轮、事件顺序、错误上抛）。共享 Mock 见 `agent_support`。

mod agent_support;

use agent_support::{
    call, default_limits, kinds, raw_calls, run_loop, turn, MockExecutor, MockProvider, Recorder,
};
use serde_json::{json, Value};
use uuid::Uuid;

use agent_core::schema::{Event, EventKind, Mode};
use agent_core::{AgentLoop, ChatProvider, ChatTurn, LoopLimits, LoopStatus, PlanGate};

// ---------------- maxSteps 熔断 ----------------

#[test]
fn max_steps_breaks_the_loop() {
    let turns = (0..LoopLimits::default().max_steps)
        .map(|i| turn("还在跑。", call("task.list", json!({"page": i}))))
        .collect();
    let provider = MockProvider::new(turns);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Ask,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "列任务",
    )
    .expect("熔断应正常返回");
    assert_eq!(outcome.status, LoopStatus::MaxStepsReached);
    assert_eq!(outcome.steps, 30, "默认 30 回合熔断");
    assert_eq!(provider.chat_calls(), 30, "provider 不被超调");
    assert_eq!(executor.executed().len(), 30, "每回合一个合法只读工具");
    assert_eq!(events.last().expect("有事件").0, EventKind::Done.as_str());
    assert_eq!(events.last().expect("有事件").1["maxSteps"], 30);
}

#[test]
fn custom_limits_break_earlier() {
    let turns = (0..5)
        .map(|_| turn("还在跑。", call("task.list", json!({"page": 1}))))
        .collect();
    let provider = MockProvider::new(turns);
    let executor = MockExecutor::default();
    let (outcome, _, _) = run_loop(
        Mode::Ask,
        &provider,
        &executor,
        LoopLimits { max_steps: 2 },
        PlanGate::default(),
        "列任务",
    )
    .expect("自定义熔断");
    assert_eq!(outcome.status, LoopStatus::MaxStepsReached);
    assert_eq!(outcome.steps, 2);
    assert_eq!(outcome.final_text, "还在跑。");
}

#[test]
fn default_max_steps_is_thirty() {
    assert_eq!(default_limits().max_steps, 30);
}

// ---------------- ⑦ 交付物提醒轮 ----------------

#[test]
fn craft_write_intent_without_write_tool_gets_one_reminder() {
    let provider = MockProvider::new(vec![
        turn("我说创建好了。", vec![]),
        turn("其实还没创建任何文件（如实说明）。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "创建一个文件",
    )
    .expect("提醒回合跑完");
    assert_eq!(outcome.status, LoopStatus::Completed);
    assert_eq!(outcome.steps, 2, "提醒追加一次回合");
    assert_eq!(provider.chat_calls(), 2);
    // 提醒以 thinking 事件上报，并作为 user 注记进历史。
    let thinking: Vec<&Value> = events
        .iter()
        .filter(|(k, _)| k == EventKind::Thinking.as_str())
        .map(|(_, p)| p)
        .collect();
    assert_eq!(thinking.len(), 1, "只提醒一次");
    assert!(thinking[0]["reminder"]
        .as_str()
        .unwrap_or_default()
        .contains("交付物"));
    let second = provider.msgs_at(1);
    let note = second.last().expect("有注记")["content"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(note.contains("请实际执行"), "提醒进历史: {note}");
    assert_eq!(outcome.final_text, "其实还没创建任何文件（如实说明）。");
}

#[test]
fn reminder_is_never_repeated() {
    let provider = MockProvider::new(vec![
        turn("说写好了。", vec![]),
        turn("还是没写。", vec![]),
        turn("收尾。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, _, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "修改配置",
    )
    .expect("提醒最多一次");
    assert_eq!(outcome.steps, 2, "第二次不再提醒，直接完成");
    assert_eq!(provider.chat_calls(), 2);
}

#[test]
fn no_reminder_when_write_tool_actually_called() {
    let provider = MockProvider::new(vec![
        turn("写入。", call("fs.write", json!({"path": "/a"}))),
        turn("已创建。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "创建一个文件",
    )
    .expect("有交付物");
    assert_eq!(outcome.steps, 2, "工具回合 + 收尾回合，无提醒");
    assert_eq!(provider.chat_calls(), 2);
    assert_eq!(
        events
            .iter()
            .filter(|(k, _)| k == EventKind::Thinking.as_str())
            .count(),
        0,
        "不发提醒"
    );
}

#[test]
fn no_reminder_without_write_intent_or_in_readonly_modes() {
    // 无写意图。
    let provider = MockProvider::new(vec![turn("答完。", vec![])]);
    let executor = MockExecutor::default();
    let (outcome, _, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "解释一下这段代码",
    )
    .expect("单回合");
    assert_eq!(outcome.steps, 1);

    // Ask 模式即使文本含写意图也不提醒（本就不能写）。
    let provider = MockProvider::new(vec![turn("只能说明缺口。", vec![])]);
    let executor = MockExecutor::default();
    let (outcome, _, _) = run_loop(
        Mode::Ask,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "创建文件",
    )
    .expect("单回合");
    assert_eq!(outcome.steps, 1);
    assert_eq!(provider.chat_calls(), 1);
}

#[test]
fn expert_mode_also_gets_reminder() {
    let provider = MockProvider::new(vec![
        turn("声称改好了。", vec![]),
        turn("未实际修改。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, _, _) = run_loop(
        Mode::Expert,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "写入结果",
    )
    .expect("expert 提醒");
    assert_eq!(outcome.steps, 2);
}

// ---------------- 事件顺序 ----------------

#[test]
fn event_order_is_text_tool_use_tool_result_then_done() {
    let provider = MockProvider::new(vec![
        turn("先读。", call("fs.read", json!({"path": "/a"}))),
        turn("读完了。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (_, events, seqs) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "读 /a",
    )
    .expect("事件有序");
    assert_eq!(
        kinds(&events),
        vec![
            EventKind::Text.as_str(),
            EventKind::ToolUse.as_str(),
            EventKind::ToolResult.as_str(),
            EventKind::Text.as_str(),
            EventKind::Done.as_str(),
        ]
    );
    assert_eq!(seqs, (1..=seqs.len() as u64).collect::<Vec<u64>>());
    let ids: Vec<&str> = events
        .iter()
        .filter(|(k, _)| k == EventKind::ToolUse.as_str() || k == EventKind::ToolResult.as_str())
        .map(|(_, p)| p["id"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(ids, vec!["c0", "c0"], "tool_use 与 tool_result 以 id 对应");
}

#[test]
fn events_carry_session_id_and_start_seq() {
    let provider = MockProvider::new(vec![turn("好。", vec![])]);
    let executor = MockExecutor::default();
    let sid = Uuid::new_v4();
    let rec = Recorder::default();
    let emit = |ev: Event| rec.push(ev);
    let mut agent = AgentLoop::new(
        &provider,
        &executor,
        Mode::Quick,
        default_limits(),
        PlanGate::default(),
        &emit,
    )
    .session_id(sid)
    .seq_base(41);
    agent.run("hi").expect("跑完");
    let events = rec.events();
    assert!(events.iter().all(|e| e.session_id == sid));
    assert_eq!(events[0].seq, 42, "seq 从锚点续接");
    assert!(events.iter().all(|e| e.ts_ms > 0));
}

#[test]
fn empty_text_turn_emits_no_text_event() {
    let provider = MockProvider::new(vec![
        ChatTurn {
            text: String::new(),
            tool_calls: raw_calls("fs.read", json!({})),
        },
        turn("结束。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "读",
    )
    .expect("空文本回合");
    assert_eq!(outcome.final_text, "结束。");
    assert_eq!(
        events
            .iter()
            .filter(|(k, _)| k == EventKind::Text.as_str())
            .count(),
        1,
        "空文本不产生 text 事件"
    );
}

// ---------------- provider 错误上抛 ----------------

#[test]
fn provider_error_is_returned_as_err() {
    struct FailingProvider;
    impl ChatProvider for FailingProvider {
        fn chat(&self, _msgs: &[Value], _tools: &[Value]) -> Result<ChatTurn, String> {
            Err("上游模型不可用".to_string())
        }
    }
    let executor = MockExecutor::default();
    let rec = Recorder::default();
    let emit = |ev: Event| rec.push(ev);
    let mut agent = AgentLoop::new(
        &FailingProvider,
        &executor,
        Mode::Craft,
        default_limits(),
        PlanGate::default(),
        &emit,
    );
    let err = agent.run("任务").expect_err("应上抛");
    assert_eq!(err, "上游模型不可用");
    assert_eq!(
        rec.len(),
        0,
        "provider 首调即失败 ⇒ 无已完成轮次事件可上报（规格：事件=实际发生的步骤）"
    );
}
