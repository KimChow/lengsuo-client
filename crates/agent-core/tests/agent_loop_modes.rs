//! Agent loop 测试（模式白名单 + Plan 门禁）。共享 Mock 见 `agent_support`。

mod agent_support;

use agent_support::{
    call, default_limits, kinds, kinds_of, run_loop, turn, MockExecutor, MockProvider,
};
use serde_json::{json, Value};
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

// ---------------- Plan 门禁两分支 ----------------

#[test]
fn plan_gate_denies_writes_then_approved_exit_switches_to_craft() {
    let provider = MockProvider::new(vec![
        // 规划态：写工具被拒，plan.exit 可执行。
        turn("写入。", call("fs.write", json!({"path": "/a"}))),
        turn("批准吧。", call("plan.exit", json!({"approved": true}))),
        turn("已落地。", call("fs.write", json!({"path": "/a"}))),
        turn("收尾。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Plan,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "写入 /a",
    )
    .expect("plan 回合跑完");

    assert_eq!(outcome.status, LoopStatus::Completed);
    // 拒绝回填在前：fs.write 第一次未执行，批准后才执行一次。
    // 拒绝回填在前：fs.write 第一次未执行，批准后才执行一次（门禁工具本身不走 executor）。
    assert_eq!(executor.executed(), vec!["fs.write"]);
    let approved = events
        .iter()
        .find(|(k, p)| k == EventKind::ToolResult.as_str() && p["name"] == "plan.exit")
        .expect("plan.exit 有结果回填");
    assert_eq!(approved.1["result"]["status"], "approved");
    assert_eq!(approved.1["result"]["mode"], "craft");
    let denied = events
        .iter()
        .find(|(k, p)| k == EventKind::ToolResult.as_str() && p["result"]["status"] == "denied")
        .expect("有拒绝回填");
    assert_eq!(denied.1["name"], "fs.write");
    assert!(
        denied.1["result"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("不在 plan 模式白名单"),
        "plan 模式写工具已被白名单剔除: {:?}",
        denied.1
    );
    // 批准后切 Craft：发 session_update 且后续回合可见写工具。
    let updates: Vec<&Value> = events
        .iter()
        .filter(|(k, _)| k == EventKind::SessionUpdate.as_str())
        .map(|(_, p)| p)
        .collect();
    assert_eq!(updates.len(), 1, "仅一次模式切换事件");
    assert_eq!(updates[0]["mode"], "craft");
    assert_eq!(updates[0]["planActive"], false);
    assert_eq!(updates[0]["planApproved"], true);
    assert!(
        provider.tool_names()[2].contains(&"fs.write".to_string()),
        "批准后 craft 白名单必须可见写工具"
    );
}

#[test]
fn external_plan_gate_blocks_writes_that_the_whitelist_allows() {
    // 宿主带入 PlanGate{active:true} 而模式仍是 craft：白名单含写工具，由门禁层拒绝。
    let provider = MockProvider::new(vec![
        turn("写入。", call("fs.write", json!({"path": "/a"}))),
        // 未实际写入且任务含写意图 ⇒ 追加一次提醒回合。
        turn("还没写。", vec![]),
        turn("改为说明缺口。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Craft,
        &provider,
        &executor,
        default_limits(),
        PlanGate {
            active: true,
            approved: false,
        },
        "写入 /a",
    )
    .expect("门禁拒绝不中断");
    assert_eq!(outcome.status, LoopStatus::Completed);
    assert_eq!(outcome.steps, 3, "含一次提醒回合");
    assert!(executor.executed().is_empty(), "门禁下不执行写工具");
    let denied = events
        .iter()
        .find(|(k, _)| k == EventKind::ToolResult.as_str())
        .expect("有拒绝回填");
    assert!(
        denied.1["result"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("规划态拒绝"),
        "第二层门禁说明: {:?}",
        denied.1
    );
    // craft 白名单里可读工具仍可用（门禁只挡写/执行）。
    assert!(provider.tool_names()[0].contains(&"fs.write".to_string()));
}

#[test]
fn plan_exit_without_approval_aborts_the_run() {
    let provider = MockProvider::new(vec![turn(
        "未批准。",
        call("plan.exit", json!({"approved": false})),
    )]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Plan,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "先规划",
    )
    .expect("未批准应正常返回");

    assert_eq!(outcome.status, LoopStatus::Aborted);
    assert_eq!(outcome.steps, 1);
    assert_eq!(executor.executed().len(), 0, "门禁工具自身不执行");
    assert_eq!(
        kinds(&events),
        kinds_of(&[
            EventKind::Text,
            EventKind::ToolUse,
            EventKind::ToolResult,
            EventKind::Done,
        ])
    );
    assert_eq!(events.last().expect("有事件").1["status"], "aborted");
}

#[test]
fn plan_mode_readonly_tools_still_run() {
    let provider = MockProvider::new(vec![
        turn("读一下。", call("fs.read", json!({"path": "/a"}))),
        turn("读完了。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, _, _) = run_loop(
        Mode::Plan,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "看看现状",
    )
    .expect("plan 允许只读");
    assert_eq!(outcome.status, LoopStatus::Completed);
    assert_eq!(executor.executed(), vec!["fs.read".to_string()]);
}

#[test]
fn expert_mode_plan_enter_then_approved_exit_keeps_running() {
    let provider = MockProvider::new(vec![
        turn("先规划。", call("plan.enter", json!({}))),
        turn("删掉它。", call("fs.delete", json!({"path": "/a"}))),
        turn("批准。", call("plan.exit", json!({"approved": true}))),
        turn("执行。", call("fs.delete", json!({"path": "/a"}))),
        turn("已删除。", vec![]),
    ]);
    let executor = MockExecutor::default();
    let (outcome, events, _) = run_loop(
        Mode::Expert,
        &provider,
        &executor,
        default_limits(),
        PlanGate::default(),
        "修改并删除",
    )
    .expect("expert 门禁回合跑完");
    assert_eq!(outcome.status, LoopStatus::Completed);
    assert_eq!(
        executor.executed(),
        vec!["fs.delete"],
        "门禁工具不走 executor"
    );
    let modes: Vec<&str> = events
        .iter()
        .filter(|(k, _)| k == EventKind::SessionUpdate.as_str())
        .map(|(_, p)| p["mode"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        modes,
        vec!["plan", "craft"],
        "enter 切规划态，exit 批准切 craft"
    );
}
