//! 时钟回拨验收：`updated_at_ms` 只前进不回退（参考 PC26 advanceActivity 原则）。
//!
//! 覆盖合法状态迁移与文本迁移两条写时间戳的路径，并确认幂等请求不刷新时间。

use std::cell::Cell;

use agent_tasks::{NowMs, TaskBoard, TaskStatus};
use uuid::Uuid;

const BASE_MS: u64 = 1_700_000_500_000;

thread_local! {
    static CLOCK: Cell<u64> = const { Cell::new(BASE_MS) };
}

/// 手动摆位的注入时钟：由测试显式设置当前毫秒，可前可后。
fn set_now(ms: u64) {
    CLOCK.with(|c| c.set(ms));
}

fn settable_clock() -> NowMs {
    fn read() -> u64 {
        CLOCK.with(|c| c.get())
    }
    read
}

fn board_at(ms: u64) -> TaskBoard {
    set_now(ms);
    TaskBoard::with_clock(settable_clock())
}

// ---- 状态迁移路径 ----

#[test]
fn status_update_does_not_regress_updated_at_on_clock_skew_back() {
    let mut b = board_at(BASE_MS);
    let t = b.create(Uuid::new_v4(), "回拨-状态", "d").unwrap();
    assert_eq!(t.updated_at_ms, BASE_MS);

    // 时钟回拨 1 小时后做合法迁移：时间戳不得倒退。
    set_now(BASE_MS - 3_600_000);
    let moved = b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert_eq!(moved.status, TaskStatus::InProgress, "合法迁移仍然生效");
    assert_eq!(
        moved.updated_at_ms, BASE_MS,
        "回拨时钟不得把 updated_at_ms 拉回"
    );
    assert_eq!(b.get(t.id).unwrap().updated_at_ms, BASE_MS);

    // 再回拨更深一层做 in_progress -> done，仍不回退。
    set_now(BASE_MS - 7_200_000);
    let done = b.update_status(t.id, TaskStatus::Done).unwrap();
    assert_eq!(done.status, TaskStatus::Done);
    assert_eq!(done.updated_at_ms, BASE_MS);
}

#[test]
fn status_update_still_advances_when_clock_moves_forward() {
    let mut b = board_at(BASE_MS);
    let t = b.create(Uuid::new_v4(), "前进-状态", "d").unwrap();
    set_now(BASE_MS + 5_000);
    let moved = b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert_eq!(
        moved.updated_at_ms,
        BASE_MS + 5_000,
        "时钟正常前进时照常刷新"
    );

    // 回拨之后再用一个介于两者之间的时间：仍取历史最大值。
    set_now(BASE_MS + 2_000);
    let done = b.update_status(t.id, TaskStatus::Done).unwrap();
    assert_eq!(done.updated_at_ms, BASE_MS + 5_000);
}

#[test]
fn idempotent_status_update_does_not_refresh_time() {
    let mut b = board_at(BASE_MS);
    let t = b.create(Uuid::new_v4(), "幂等-状态", "d").unwrap();
    set_now(BASE_MS + 1_000);
    b.update_status(t.id, TaskStatus::InProgress).unwrap();

    // 同状态幂等：即便时钟前进，也不刷新时间。
    set_now(BASE_MS + 9_000);
    let again = b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert_eq!(again.updated_at_ms, BASE_MS + 1_000, "幂等请求不刷新时间戳");

    // 幂等请求在时钟回拨时同样不动时间戳，也不得倒退。
    set_now(BASE_MS - 500);
    let third = b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert_eq!(third.updated_at_ms, BASE_MS + 1_000);
}

// ---- 文本更新路径 ----

#[test]
fn text_update_does_not_regress_updated_at_on_clock_skew_back() {
    let mut b = board_at(BASE_MS);
    let t = b.create(Uuid::new_v4(), "回拨-文本", "d0").unwrap();

    set_now(BASE_MS - 3_600_000);
    let renamed = b.update_text(t.id, Some("新标题"), None).unwrap();
    assert_eq!(renamed.subject, "新标题", "文本更新仍然生效");
    assert_eq!(
        renamed.updated_at_ms, BASE_MS,
        "回拨时钟不得把 updated_at_ms 拉回"
    );
    assert_eq!(
        renamed.created_at_ms, BASE_MS,
        "created_at_ms 不受文本更新影响"
    );

    // 描述单独更新，仍在更深的回拨下保持不回退。
    set_now(BASE_MS - 7_200_000);
    let described = b.update_text(t.id, None, Some("d1")).unwrap();
    assert_eq!(described.description, "d1");
    assert_eq!(described.updated_at_ms, BASE_MS);
}

#[test]
fn text_update_still_advances_and_skips_unchanged_fields() {
    let mut b = board_at(BASE_MS);
    let t = b.create(Uuid::new_v4(), "s0", "d0").unwrap();

    set_now(BASE_MS + 4_000);
    let same = b.update_text(t.id, Some("s0"), Some("d0")).unwrap();
    assert_eq!(same.updated_at_ms, BASE_MS, "字段无变化不刷新");

    set_now(BASE_MS + 6_000);
    let changed = b.update_text(t.id, Some("s1"), Some("d0")).unwrap();
    assert_eq!(
        changed.updated_at_ms,
        BASE_MS + 6_000,
        "有变化且时钟前进时照常刷新"
    );

    // 无变化的写入即使时钟前进也不刷新；有变化但时钟回拨则取历史最大值。
    set_now(BASE_MS + 8_000);
    let noop = b.update_text(t.id, Some("s1"), None).unwrap();
    assert_eq!(noop.updated_at_ms, BASE_MS + 6_000);

    set_now(BASE_MS + 1_000);
    let skewed = b.update_text(t.id, Some("s2"), None).unwrap();
    assert_eq!(skewed.subject, "s2");
    assert_eq!(skewed.updated_at_ms, BASE_MS + 6_000);
}

#[test]
fn rejected_writes_leave_timestamp_untouched() {
    let mut b = board_at(BASE_MS);
    let t = b.create(Uuid::new_v4(), "拒绝-写入", "d").unwrap();
    set_now(BASE_MS + 2_000);
    b.update_status(t.id, TaskStatus::InProgress).unwrap();

    // 非法迁移与空白 subject 均不改状态、不改时间戳。
    set_now(BASE_MS - 1_000);
    assert!(b.update_status(t.id, TaskStatus::Pending).is_err());
    assert!(b.update_text(t.id, Some("  "), None).is_err());
    let kept = b.get(t.id).unwrap();
    assert_eq!(kept.status, TaskStatus::InProgress);
    assert_eq!(kept.updated_at_ms, BASE_MS + 2_000);
}

#[test]
fn mixed_updates_keep_updated_at_monotonic_under_backwards_clock() {
    let mut b = board_at(BASE_MS);
    let sid = Uuid::new_v4();
    let mut seen = Vec::new();
    let mut prev = b.create(sid, "m1", "d").unwrap();
    seen.push(prev.updated_at_ms);

    let steps: [(u64, bool); 6] = [
        (BASE_MS + 10, true),
        (BASE_MS - 4_000, false),
        (BASE_MS + 3_000, true),
        (BASE_MS - 9_000, false),
        (BASE_MS + 1_000, true),
        (BASE_MS + 20_000, true),
    ];
    for (i, (ms, advance_status)) in steps.into_iter().enumerate() {
        set_now(ms);
        prev = if advance_status {
            let to = match prev.status {
                TaskStatus::Pending => TaskStatus::InProgress,
                _ => TaskStatus::Done,
            };
            b.update_status(prev.id, to).unwrap()
        } else {
            b.update_text(prev.id, Some(&format!("m1-{}", i)), None)
                .unwrap()
        };
        seen.push(prev.updated_at_ms);
    }
    assert!(
        seen.windows(2).all(|w| w[0] <= w[1]),
        "updated_at_ms 必须非递减: {seen:?}"
    );
}
