//! 测试共享辅助：注入时钟、看板构造与状态摆位（各 tests/*.rs 以 `mod support;` 引入）。

#![allow(dead_code)]

use agent_tasks::{NowMs, Task, TaskBoard, TaskError, TaskStatus};
use uuid::Uuid;

/// 冻结时钟的时间戳：用于「无变化不刷新 updated_at」断言。
pub const FROZEN_MS: u64 = 1_700_000_100_000;

// 可重定位移时钟：thread_local 保证每个测试线程独立，每次调用 +1ms，
// 使 created/updated 时间戳确定且可断言顺序。
thread_local! {
    static CLOCK: std::cell::Cell<u64> = const { std::cell::Cell::new(1_700_000_000_000) };
}

pub fn ticking_clock() -> NowMs {
    fn tick() -> u64 {
        CLOCK.with(|c| {
            let v = c.get();
            c.set(v + 1);
            v
        })
    }
    tick
}

/// 冻结时钟：时间戳恒定。
pub fn frozen_clock() -> NowMs {
    fn frozen() -> u64 {
        FROZEN_MS
    }
    frozen
}

/// 使用自增注入时钟的看板。
pub fn board() -> TaskBoard {
    TaskBoard::with_clock(ticking_clock())
}

/// 使用冻结时钟的看板。
pub fn frozen_board() -> TaskBoard {
    TaskBoard::with_clock(frozen_clock())
}

/// 在独立会话中创建一个任务（标题唯一，便于区分）。
pub fn create(b: &mut TaskBoard, subject: &str) -> Task {
    b.create(Uuid::new_v4(), subject, "描述")
        .expect("create ok")
}

/// 沿合法路径把任务摆到目标状态（Pending 无需移动）。
pub fn park(b: &mut TaskBoard, id: Uuid, want: TaskStatus) {
    if want == TaskStatus::Pending {
        return;
    }
    b.update_status(id, TaskStatus::InProgress)
        .expect("摆位: pending->in_progress");
    if want != TaskStatus::InProgress {
        b.update_status(id, want).expect("摆位: in_progress->终态");
    }
}

/// 断言错误为指定方向的 InvalidTransition。
pub fn is_invalid_transition(err: &TaskError, from: TaskStatus, to: TaskStatus) -> bool {
    matches!(err, TaskError::InvalidTransition { from: f, to: t } if *f == from && *t == to)
}
