//! Plan 门禁各分支：plan 白名单×门禁组合、外部门禁拦截、未批准终止、只读放行、expert 进出切换
//! （自原 agent_loop_modes.rs L219-408 原样搬移）。

use crate::agent_support::{
    call, default_limits, kinds, kinds_of, run_loop, turn, MockExecutor, MockProvider,
};
use serde_json::{json, Value};

use agent_core::schema::{EventKind, Mode};
use agent_core::{LoopStatus, PlanGate};

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
