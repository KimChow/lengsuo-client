//! 挂起审批的过期语义（开工说明 §5 / PC19）：
//! `request_approval` 宣告 `expiresAt` 后，晚于过期时刻的 `respond(true)` 不得批准；
//! `wait` 的上限取「调用方 timeout」与「创建时 deadline」的较短值，过期后立即 deny。
//! 全部用例使用 `with_approval_timeout(Duration::ZERO)`，无 sleep，确定性红灯。

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use agent_core::error::CoreError;
use agent_core::permission::PermissionGate;
use agent_core::schema::{ApprovalOutcome, Mode};
use agent_core::tool::{ToolKind, ToolRegistry, ToolSpec};
use serde_json::json;

fn registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(ToolSpec {
        name: "shell.exec".into(),
        description: "测试用".into(),
        kind: ToolKind::Exec,
        sensitive_arguments: true,
        timeout_ms: 5_000,
    });
    r
}

fn gate(approval_timeout: Duration) -> PermissionGate {
    PermissionGate::new(registry())
        .with_whitelist(Mode::Craft, BTreeSet::from(["shell.exec".to_string()]))
        .with_approval_timeout(approval_timeout)
}

/// 过期后 `respond(true)` 必须落为 deny + timed_out，且不得返回批准。
#[test]
fn expired_approval_cannot_be_approved() {
    let g = gate(Duration::ZERO);
    let req = g.request_approval("sess", "shell.exec", &json!({"command": "ls"}));
    let result = g.respond(req.id, true);
    match result {
        Ok(outcome) => {
            let outcome: ApprovalOutcome = outcome;
            assert!(!outcome.approved, "已过期审批不得批准：{outcome:?}");
            assert!(outcome.timed_out, "已过期应答必须标记 timed_out");
        }
        Err(err) => {
            // 允许以现有错误回绝，但不得是批准。
            assert!(
                matches!(
                    err,
                    CoreError::ApprovalAnswered(_) | CoreError::ApprovalNotFound(_)
                ),
                "过期应答应返回既有审批错误，实际 {err:?}"
            );
        }
    }
}

/// 过期后 `wait` 必须能正常结束（deny），不因调用方较长 timeout 而挂住。
#[test]
fn expired_approval_wait_ends_immediately_with_deny() {
    let g = gate(Duration::ZERO);
    let req = g.request_approval("sess", "shell.exec", &json!({"command": "ls"}));
    let started = Instant::now();
    let outcome = g
        .wait(req.id, Duration::from_secs(600))
        .expect("wait 必须返回结果");
    let elapsed = started.elapsed();
    assert!(!outcome.approved, "过期审批默认 deny：{outcome:?}");
    assert!(outcome.timed_out, "过期审批应标记 timed_out");
    assert!(
        elapsed < Duration::from_secs(5),
        "wait 上限应取创建 deadline（已过期）而非调用方 600s，实际等 {elapsed:?}"
    );
    assert!(g.list_pending("sess").is_empty(), "过期后必须清理挂起项");
    assert_eq!(g.pending_count(), 0, "过期后挂起总数应为 0");
}

/// 过期与重复应答竞争仍是一次性：第二次不得静默批准，也不得成功改写结果。
#[test]
fn expired_then_repeat_respond_stays_one_shot() {
    let g = gate(Duration::ZERO);
    let req = g.request_approval("sess", "shell.exec", &json!({"command": "ls"}));
    let first = g.respond(req.id, true);
    if let Ok(outcome) = first {
        assert!(!outcome.approved, "过期首次应答不得批准");
        let second = g.respond(req.id, true);
        assert!(
            matches!(second, Err(CoreError::ApprovalAnswered(_))),
            "重复应答必须失败，实际 {second:?}"
        );
    } else {
        // 首次已回绝：第二次也必须失败（未知或已应答）。
        assert!(g.respond(req.id, true).is_err(), "过期回绝后不得再批准");
    }
}

/// 未过期路径不变：正常 approve / deny 与既有语义一致。
#[test]
fn live_approval_approve_and_deny_unchanged() {
    let g = gate(Duration::from_secs(120));
    let approved = g.request_approval("sess", "shell.exec", &json!({"command": "ls"}));
    let outcome = g.respond(approved.id, true).expect("未过期可批准");
    assert!(outcome.approved, "正常批准不变");
    assert!(!outcome.timed_out);
    let wait_out = g
        .wait(approved.id, Duration::from_secs(5))
        .expect("wait 取回已应答结果");
    assert!(wait_out.approved, "wait 应看到已批准结果");

    let denied = g.request_approval("sess", "shell.exec", &json!({"command": "ls"}));
    let outcome = g.respond(denied.id, false).expect("未过期可拒绝");
    assert!(!outcome.approved, "正常拒绝不变");
    assert!(!outcome.timed_out);
    assert!(g.respond(denied.id, true).is_err(), "重复应答仍失败");
    assert!(g.wait(denied.id, Duration::from_secs(5)).is_ok());
}

/// 调用方 timeout 更短时仍按调用方超时 deny（无过期干扰，行为回归）。
#[test]
fn caller_timeout_still_bounds_wait() {
    let g = gate(Duration::from_secs(120));
    let req = g.request_approval("sess", "shell.exec", &json!({"command": "ls"}));
    let outcome = g
        .wait(req.id, Duration::from_millis(10))
        .expect("调用方超时路径");
    assert!(!outcome.approved, "调用方超时按 deny 语义");
    assert!(outcome.timed_out);
    assert!(g.list_pending("sess").is_empty());
}
