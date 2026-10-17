//! 被拒绝事件的原子性测试。行为来源：PC19（历史/实时事件按 seq 有序）、PC26（终态保护）。
//!
//! 唯一锁定行为：任何被 [`SessionStreamState::apply_event`] 拒绝的事件，
//! **既不得消费序号（`next_seq` 不前移），也不得留下任何状态痕迹**
//! （不追加/合并消息、不改变相位或模式、不增删审批条目、不解除终态保护）。
//!
//! 配套不变式：同一 `seq` 被拒绝后，紧随其后的**合法**事件仍可成功应用——
//! 证明无效事件没有占用该序号资源。合法重复事件（`seq != last + 1`）与断序冻结规则
//! 本身不在本卡改动范围，这里只锁定「拒绝 = 零副作用」。
//!
//! 覆盖的无效事件形态：
//! - Quick 模式下的 `tool_use` / `tool_result`（与模式矛盾）；
//! - 缺 `approval_id` 的 `approval_request`；
//! - 已有挂起审批时的第二个 `approval_request`（v0 串行审批违规）；
//! - 未知 `mode` 取值的 `session_update`；
//! - 终态（`done` / `fail`）之后的事件；
//! - 断序（跳跃/重复）事件。

use lengsuo_shell::state::{
    ApprovalDecision, MessageRole, SessionMode, SessionStreamState, StreamPhase,
};
use lengsuo_shell::{EventKind, GatewayEvent, StateError};
use serde_json::json;

/// 构造一条归属 `s1` 的网关事件。
fn event(kind: EventKind, seq: u64, payload: serde_json::Value) -> GatewayEvent {
    GatewayEvent {
        seq,
        session_id: "s1".to_string(),
        kind,
        payload,
        ts_ms: 1_700_000_000_000 + seq,
    }
}

/// 快照：本卡关心「状态是否被触动」的全部可观测维度。
/// 序号只以 `next_seq` 暴露（等价于 `last_seq + 1`），因此「消费 last_seq」
/// 与「`next_seq` 前移」在这里是同一件事。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    next_seq: u64,
    phase: StreamPhase,
    mode: SessionMode,
    messages: Vec<(MessageRole, String)>,
    pending_id: Option<String>,
    approvals_len: usize,
}

fn snapshot(state: &SessionStreamState) -> Snapshot {
    Snapshot {
        next_seq: state.next_seq(),
        phase: state.phase(),
        mode: state.mode(),
        messages: state
            .messages()
            .iter()
            .map(|m| (m.role, m.content.clone()))
            .collect(),
        pending_id: state.approvals().pending().map(|p| p.id.clone()),
        approvals_len: state.approvals().len(),
    }
}

/// 起一个会话流并落一条合法文本事件（seq=1）。
fn seeded(mode: SessionMode) -> SessionStreamState {
    let mut state = SessionStreamState::new("s1", mode);
    state
        .apply_event(event(EventKind::Text, 1, json!({ "text": "开始处理" })))
        .expect("seq=1 的合法文本事件应被接受");
    state
}

/// Quick 模式拒绝 `tool_use`：零副作用，同 seq 的合法事件仍可成功。
#[test]
fn quick_mode_rejects_tool_use_without_consuming_seq_or_state() {
    let mut state = seeded(SessionMode::Quick);
    let before = snapshot(&state);
    assert_eq!(before.next_seq, 2, "已应用 seq=1，下一条期望 2");

    let err = state
        .apply_event(event(
            EventKind::ToolUse,
            2,
            json!({ "name": "shell.exec", "arguments": {} }),
        ))
        .expect_err("Quick 模式必须拒绝 tool_use");
    assert!(
        matches!(err, StateError::InvalidTransition { .. }),
        "拒绝原因应为模式/相位不允许，实际 {err:?}"
    );
    assert_eq!(snapshot(&state), before, "被拒绝事件不得修改任何状态");

    // 同 seq 的合法事件仍可成功：序号资源未被无效事件占用。
    state
        .apply_event(event(EventKind::Text, 2, json!({ "text": "合法续写" })))
        .expect("被拒绝后同 seq 的合法事件应可应用");
    assert_eq!(state.next_seq(), 3);
    assert!(state
        .messages()
        .iter()
        .any(|m| m.content.contains("合法续写")));
}

/// Quick 模式连续拒绝 `tool_result`：仍然零副作用。
#[test]
fn quick_mode_rejects_tool_result_without_consuming_seq() {
    let mut state = seeded(SessionMode::Quick);
    let before = snapshot(&state);
    let payload = json!({ "name": "shell.exec", "chars": 4usize, "resultRef": "r" });

    for _ in 0..2 {
        let err = state
            .apply_event(event(EventKind::ToolResult, 2, payload.clone()))
            .expect_err("Quick 模式必须拒绝 tool_result");
        assert!(
            matches!(err, StateError::InvalidTransition { .. }),
            "实际 {err:?}"
        );
        assert_eq!(snapshot(&state), before, "连续拒绝仍须零副作用");
    }

    state
        .apply_event(event(EventKind::Text, 2, json!({ "text": "合法续写" })))
        .expect("同 seq 的合法事件应可应用");
    assert_eq!(state.next_seq(), 3);
}

/// 缺 `approval_id` 的审批请求被拒绝：不得建立挂起审批、不得改相位。
#[test]
fn approval_request_without_id_is_rejected_atomically() {
    let mut state = seeded(SessionMode::Craft);
    let before = snapshot(&state);

    let err = state
        .apply_event(event(
            EventKind::ApprovalRequest,
            2,
            json!({ "name": "shell.exec" }),
        ))
        .expect_err("缺 approval_id 必须被拒绝");
    assert!(
        matches!(err, StateError::InvalidTransition { .. }),
        "实际 {err:?}"
    );
    assert_eq!(snapshot(&state), before);
    assert!(state.approvals().pending().is_none());

    state
        .apply_event(event(
            EventKind::ApprovalRequest,
            2,
            json!({ "approval_id": "req-1", "name": "shell.exec" }),
        ))
        .expect("同 seq 的合法审批请求应可应用");
    assert_eq!(
        state.approvals().pending().map(|p| p.id.clone()),
        Some("req-1".to_string())
    );
    assert_eq!(state.phase(), StreamPhase::AwaitingApproval);
    assert_eq!(state.next_seq(), 3);
}

/// 已有挂起审批时的第二个 `approval_request` 被拒绝：
/// 不得覆盖既有挂起条目、不得消费 seq；原审批仍可正常应答。
#[test]
fn second_pending_approval_is_rejected_and_does_not_clobber_first() {
    let mut state = seeded(SessionMode::Craft);
    state
        .apply_event(event(
            EventKind::ApprovalRequest,
            2,
            json!({ "approval_id": "req-1", "name": "shell.exec" }),
        ))
        .expect("首次审批请求应被接受");
    let before = snapshot(&state);
    assert_eq!(before.next_seq, 3);
    assert_eq!(before.pending_id.as_deref(), Some("req-1"));

    let err = state
        .apply_event(event(
            EventKind::ApprovalRequest,
            3,
            json!({ "approval_id": "req-2", "name": "fs.write" }),
        ))
        .expect_err("重复的待决审批必须被拒绝（v0 串行审批）");
    assert!(
        matches!(err, StateError::InvalidTransition { .. }),
        "实际 {err:?}"
    );
    assert_eq!(snapshot(&state), before, "被拒绝的第二个审批须零副作用");

    // 原始挂起条目未被覆盖，仍可应答（应答本身不消费事件序号）。
    state
        .respond_approval("req-1", ApprovalDecision::Allow, 1_700_000_000_500)
        .expect("原审批钩子不应被重复请求破坏");
    assert_eq!(state.next_seq(), 3, "应答不改变序号锚点");

    state
        .apply_event(event(EventKind::Text, 3, json!({ "text": "合法续写" })))
        .expect("同 seq 的合法事件应可应用");
    assert_eq!(state.next_seq(), 4);
}

/// 未知 `mode` 取值的 `session_update` 被拒绝：模式不变、不消费 seq。
#[test]
fn unknown_mode_in_session_update_is_rejected_atomically() {
    let mut state = seeded(SessionMode::Craft);
    let before = snapshot(&state);

    let err = state
        .apply_event(event(
            EventKind::SessionUpdate,
            2,
            json!({ "mode": "sandbox" }),
        ))
        .expect_err("未知 mode 取值必须被拒绝，不猜测");
    assert!(
        matches!(err, StateError::InvalidTransition { .. }),
        "实际 {err:?}"
    );
    assert_eq!(
        snapshot(&state),
        before,
        "解析失败的事件不得消费序号或改模式"
    );

    state
        .apply_event(event(
            EventKind::SessionUpdate,
            2,
            json!({ "mode": "quick" }),
        ))
        .expect("同 seq 的合法 mode_update 应可应用");
    assert_eq!(state.mode(), SessionMode::Quick);
    assert_eq!(state.next_seq(), 3);
}

/// 终态之后的事件被拒绝：不得追加消息、不得消费 seq、不得解除终态保护。
#[test]
fn event_after_done_is_rejected_atomically() {
    let mut state = seeded(SessionMode::Craft);
    state
        .apply_event(event(EventKind::Done, 2, json!({})))
        .expect("done 应被接受并进入终态");
    assert_eq!(state.phase(), StreamPhase::Finished);
    let before = snapshot(&state);
    assert_eq!(before.next_seq, 3);

    let err = state
        .apply_event(event(EventKind::Text, 3, json!({ "text": "迟到" })))
        .expect_err("终态后必须拒绝事件");
    assert!(matches!(err, StateError::Sealed(_)), "实际 {err:?}");
    assert_eq!(snapshot(&state), before, "终态拒绝须零副作用");
    assert_eq!(state.phase(), StreamPhase::Finished, "终态保护不得被解除");
}

/// `fail` 之后的事件同样零副作用，序号锚点保持不动。
#[test]
fn event_after_fail_is_rejected_atomically() {
    let mut state = seeded(SessionMode::Craft);
    state.fail();
    let before = snapshot(&state);

    let err = state
        .apply_event(event(EventKind::Text, 2, json!({ "text": "迟到" })))
        .expect_err("失败终态后必须拒绝");
    assert!(matches!(err, StateError::Sealed(_)), "实际 {err:?}");
    assert_eq!(snapshot(&state), before);
}

/// 断序拒绝不得推进锚点或留下痕迹；补齐断裂点后恢复正常。
#[test]
fn seq_gap_rejection_is_atomic_and_still_recovers() {
    let mut state = seeded(SessionMode::Craft);

    // seq=5 跳跃：必须拒绝且不消费任何序号。
    let err = state
        .apply_event(event(EventKind::Text, 5, json!({ "text": "跳跃" })))
        .expect_err("断序必须被拒绝");
    assert!(matches!(err, StateError::SeqGap { .. }), "实际 {err:?}");
    let before = snapshot(&state);
    assert_eq!(before.next_seq, 2, "断序拒绝不得推进锚点");

    // 断序期间的其它无效事件同样零副作用，冻结语义保持。
    let err = state
        .apply_event(event(EventKind::ToolUse, 6, json!({ "name": "x" })))
        .expect_err("断序期间事件仍被拒绝");
    assert!(matches!(err, StateError::SeqGap { .. }), "实际 {err:?}");
    assert_eq!(snapshot(&state), before);

    // 重复序号（seq=1）仍按既有断序规则拒绝，本卡未改该规则。
    let err = state
        .apply_event(event(EventKind::Text, 1, json!({ "text": "重复" })))
        .expect_err("重复序号必须按断序处理");
    assert!(matches!(err, StateError::SeqGap { .. }), "实际 {err:?}");
    assert_eq!(snapshot(&state), before);

    // 补齐断裂点（seq=2）后恢复正常。
    state
        .apply_event(event(EventKind::Text, 2, json!({ "text": "补齐" })))
        .expect("补齐序号后应恢复");
    assert_eq!(state.next_seq(), 3);
}

/// 「合法-拒绝-合法」交错后，序号严格等于已接受事件数：
/// 拒绝事件一次都没有消费序号。
#[test]
fn interleaved_rejections_keep_seq_matching_only_accepted_events() {
    let mut state = seeded(SessionMode::Quick);
    let mut accepted = 1u64;

    for i in 0..6u64 {
        let seq = accepted + 1;
        let rejected = if i % 2 == 0 {
            // 无效：Quick 模式下的 tool_use。
            state.apply_event(event(EventKind::ToolUse, seq, json!({ "name": "t" })))
        } else {
            // 无效：缺 approval_id 的审批请求。
            state.apply_event(event(
                EventKind::ApprovalRequest,
                seq,
                json!({ "name": "t" }),
            ))
        };
        assert!(rejected.is_err(), "第 {i} 轮构造的无效事件必须被拒绝");
        assert_eq!(
            state.next_seq(),
            seq,
            "第 {i} 轮：拒绝不得把期望序号推过 seq={seq}"
        );

        // 同 seq 的合法文本事件总能成功。
        state
            .apply_event(event(
                EventKind::Text,
                seq,
                json!({ "text": format!("m{seq}") }),
            ))
            .expect("合法事件应可应用");
        accepted += 1;
        assert_eq!(
            state.next_seq(),
            accepted + 1,
            "第 {i} 轮：序号只应随合法事件前移"
        );
    }
    // 所有文本增量按既有合并规则并入同一条助手消息，内容含全部合法序号。
    let merged: String = state
        .messages()
        .iter()
        .filter(|m| m.content.contains('m'))
        .map(|m| m.content.as_str())
        .collect();
    for seq in 2..=accepted {
        assert!(merged.contains(&format!("m{seq}")), "缺少 m{seq}");
    }
    // 只有被应用的事件才留下内容：Quick 模式下被拒的 tool_use / 无 id 审批
    // 不得产生任何工具角色消息。
    assert!(
        state
            .messages()
            .iter()
            .all(|m| m.role == MessageRole::Assistant),
        "被拒事件不得产生其它角色的消息"
    );
    assert!(state
        .messages()
        .iter()
        .all(|m| m.role == MessageRole::Assistant));
}
