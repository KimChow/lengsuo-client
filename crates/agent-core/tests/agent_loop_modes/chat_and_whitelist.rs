//! ① 理解 + ② chat + ⑧ 最终回复走查与 ③ 模式白名单过滤（自原 agent_loop_modes.rs L14-217 原样搬移）。

use crate::agent_support::{
    call, default_limits, kinds, run_loop, turn, MockExecutor, MockProvider,
};
use serde_json::json;
use std::collections::BTreeSet;

use agent_core::schema::{EventKind, Mode};
use agent_core::{mode_policy, LoopStatus, PlanGate};

// ---------------- ① 理解 + ② chat + ⑧ 最终回复 ----------------

#[test]
fn quick_mode_completes_with_chat_only_and_empty_tool_face() {
    let provider = MockProvider::new(vec![turn("答案如下。", vec![])]);
    let executor = MockExecutor::default();
    let (outcome, events, seqs) = run_loop(
        Mode::Quick,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "随便聊聊",
    )
    .expect("quick 回合应跑完");

    assert_eq!(outcome.status, LoopStatus::Completed);
    assert_eq!(outcome.steps, 1);
    assert_eq!(outcome.final_text, "答案如下。");
    // Quick 空工具面：provider 看不到任何工具定义。
    assert_eq!(provider.tool_names(), vec![Vec::<String>::new()]);
    assert_eq!(executor.executed().len(), 0, "quick 不执行任何工具");
    // 事件顺序：text → done。
    assert_eq!(
        kinds(&events),
        vec![EventKind::Text.as_str(), EventKind::Done.as_str()]
    );
    assert_eq!(seqs, vec![1, 2], "seq 会话内单调递增");
    assert_eq!(events[1].1["status"], "completed");
}

#[test]
fn system_message_carries_mode_template_and_hard_rules() {
    let provider = MockProvider::new(vec![turn("好。", vec![])]);
    let executor = MockExecutor::default();
    run_loop(
        Mode::Ask,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "看看代码",
    )
    .expect("单回合完成");
    let msgs = provider.msgs_at(0);
    let system = msgs[0]["content"].as_str().expect("系统消息为文本");
    assert!(system.contains("ask · 只读白名单"), "含模式模板: {system}");
    assert!(
        system.contains("不得声称读过/写过/搜过未实际发生的操作"),
        "全模式追加硬规则"
    );
    assert_eq!(msgs[1]["role"], "user");
    assert_eq!(msgs[1]["content"], "看看代码");
}

// ---------------- ③ 模式白名单过滤 ----------------

#[test]
fn each_mode_exposes_its_whitelist_to_provider() {
    let expected: Vec<(Mode, BTreeSet<String>)> = Mode::ALL
        .iter()
        .map(|m| (*m, mode_policy(*m).tools))
        .collect();
    for (mode, want) in expected {
        let provider = MockProvider::new(vec![turn("完成。", vec![])]);
        let executor = MockExecutor::default();
        run_loop(
            mode,
            &provider,
            &executor,
            default_limits(),
            PlanGate::default(),
            "任务",
        )
        .expect("单回合完成");
        let got: BTreeSet<String> = provider.tool_names()[0].iter().cloned().collect();
        assert_eq!(got, want, "{mode:?} 可见工具面应等于白名单");
    }
}

#[test]
fn ask_mode_denies_write_tool_without_executing_it() {
    let provider = MockProvider::new(vec![
        turn("先写一下。", call("fs.write", json!({"path": "/a"}))),
        turn("改为说明缺口。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Ask,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "改文件",
    )
    .expect("拒绝不中断回合");

    assert_eq!(
        outcome.status,
        LoopStatus::Completed,
        "白名单外只回填不中断"
    );
    assert!(executor.executed().is_empty(), "被拒工具不得执行");
    let tool_result = events
        .iter()
        .find(|(k, _)| k == EventKind::ToolResult.as_str())
        .expect("有 tool_result 事件");
    assert_eq!(tool_result.1["result"]["status"], "denied");
    assert_eq!(tool_result.1["isError"], true);
    assert!(
        tool_result.1["result"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("不在 ask 模式白名单"),
        "拒绝说明含模式名: {:?}",
        tool_result.1
    );
    // ⑥ 观察回传：denied 结果进入下一回合消息历史。
    let next = provider.msgs_at(1);
    assert_eq!(next.last().expect("回填结果")["role"], "tool_result");
    assert_eq!(next[next.len() - 1]["tool"]["name"], "fs.write");
}

#[test]
fn craft_mode_executes_write_tools() {
    let provider = MockProvider::new(vec![
        turn("写入。", call("fs.write", json!({"path": "/a"}))),
        turn("已写入 /a。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "写入 /a",
    )
    .expect("craft 回合跑完");
    assert_eq!(outcome.status, LoopStatus::Completed);
    assert_eq!(executor.executed(), vec!["fs.write".to_string()]);
    let result = &events
        .iter()
        .find(|(k, _)| k == EventKind::ToolResult.as_str())
        .expect("有结果事件")
        .1;
    assert_eq!(result["result"]["bytes"], 12);
    assert_eq!(result["isError"], false);
    assert_eq!(outcome.final_text, "已写入 /a。");
}

#[test]
fn tool_error_is_backfilled_and_loop_continues() {
    let provider = MockProvider::new(vec![
        turn("执行。", call("shell.exec", json!({"command": "boom"}))),
        turn("失败已说明。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "跑个命令",
    )
    .expect("执行失败不中断");
    assert_eq!(outcome.status, LoopStatus::Completed);
    let result = &events
        .iter()
        .find(|(k, _)| k == EventKind::ToolResult.as_str())
        .expect("有结果事件")
        .1;
    assert_eq!(result["result"]["status"], "error");
    assert_eq!(result["isError"], true);
}

#[test]
fn repeated_denied_tool_terminates_with_denied_status() {
    let provider = MockProvider::new(vec![
        turn("写。", call("fs.write", json!({"path": "/a"}))),
        turn("再写。", call("fs.write", json!({"path": "/a"}))),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Ask,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "改文件",
    )
    .expect("拒绝状态可查询");
    assert_eq!(
        outcome.status,
        LoopStatus::Denied {
            tool: "fs.write".into()
        },
        "同一工具重复被拒 ⇒ 终止，防空转"
    );
    assert_eq!(outcome.steps, 2);
    assert_eq!(events.last().expect("有事件").0, EventKind::Done.as_str());
    assert_eq!(events.last().expect("有事件").1["status"], "denied");
}
