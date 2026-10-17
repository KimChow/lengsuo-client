//! append 原子提交：落盘/校验失败不得发布内存幽灵事件（开工说明 §5 修复卡）。
//!
//! 行为来源：我方 N9 事件日志；PC08/PC26 恢复语义只作参考，不复制实现。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use agent_core::error::CoreError;
use agent_core::event_log::{EventLog, JsonlEventLog, MAX_LINE_BYTES};

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agent-core-atomic-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create workdir");
    dir
}

/// 把会话文件路径占成目录：任何追加写都以 EISDIR 失败，可重复复现写失败路径。
fn block_session_file(dir: &Path, session: uuid::Uuid) {
    fs::create_dir_all(dir.join(format!("events-{session}.jsonl"))).expect("占位目录");
}

fn unblock_session_file(dir: &Path, session: uuid::Uuid) {
    fs::remove_dir(dir.join(format!("events-{session}.jsonl"))).expect("移除占位目录");
}

fn seqs_of(events: &[agent_core::schema::Event]) -> Vec<u64> {
    events.iter().map(|e| e.seq).collect()
}

#[test]
fn failed_append_publishes_no_ghost_event() {
    let dir = workdir("ghost");
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let s = uuid::Uuid::new_v4();
    block_session_file(&dir, s);

    let err = log
        .append(s, "text", serde_json::json!({"a": 1}))
        .expect_err("写失败必须报错");
    assert!(
        matches!(err, CoreError::Io { .. }),
        "期望 IO 错误，实际 {err:?}"
    );

    // 核心不变量：写失败后 last_seq/replay/sessions 都不认识这条事件。
    assert_eq!(log.last_seq(s), None, "last_seq 不得出现幽灵 seq");
    assert!(
        log.replay(s, 0, 10).expect("replay").is_empty(),
        "replay 不得返回未落盘的事件"
    );
    assert!(!log.sessions().contains(&s), "失败的会话不得进入索引");

    // 磁盘与内存必须一致：障碍解除后重新打开得到同样的空视图（无半行残留）。
    unblock_session_file(&dir, s);
    let reopened = JsonlEventLog::open(dir.clone()).expect("reopen");
    assert_eq!(reopened.last_seq(s), None);
    assert!(reopened.replay(s, 0, 10).expect("replay").is_empty());
    // 障碍解除后同一条事件正常提交，seq 仍从 1 开始，不跳号。
    let ok = reopened
        .append(s, "text", serde_json::json!({"a": 1}))
        .expect("append after recovery");
    assert_eq!(ok.seq, 1);
}

#[test]
fn failed_append_never_retreats_or_skips_seq() {
    let dir = workdir("gap");
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let s = uuid::Uuid::new_v4();

    let first = log
        .append(s, "text", serde_json::json!({"n": 1}))
        .expect("first");
    assert_eq!(first.seq, 1);

    // 超大行：提交前校验拦住，不占用 seq、不落盘、不回退计数器。
    let huge = serde_json::json!({"blob": "x".repeat(MAX_LINE_BYTES)});
    let err = log
        .append(s, "tool_result", huge)
        .expect_err("超大行必须拒绝");
    assert!(
        matches!(err, CoreError::LineTooLarge { .. }),
        "期望行长错误，实际 {err:?}"
    );
    assert_eq!(log.last_seq(s), Some(1), "超大行失败后 last_seq 不变");

    // 落盘写失败（目录占位）：同样不推进 seq。
    let blocked = uuid::Uuid::new_v4();
    block_session_file(&dir, blocked);
    assert!(log.append(blocked, "text", serde_json::json!({})).is_err());
    assert_eq!(log.last_seq(blocked), None);
    assert!(!log.sessions().contains(&blocked));

    let second = log
        .append(s, "text", serde_json::json!({"n": 2}))
        .expect("second");
    assert_eq!(second.seq, 2, "失败不得让 seq 倒退或跳号");
    assert_eq!(seqs_of(&log.replay(s, 0, 10).expect("replay")), vec![1, 2]);

    unblock_session_file(&dir, blocked);
    let reopened = JsonlEventLog::open(dir.clone()).expect("reopen");
    assert_eq!(reopened.last_seq(s), Some(2));
    assert_eq!(reopened.last_seq(blocked), None, "未落盘会话不得被回放出来");
    assert_eq!(
        seqs_of(&reopened.replay(s, 0, 10).expect("replay")),
        vec![1, 2],
        "磁盘回放与内存索引必须一致"
    );
    // 被阻塞过的会话解除障碍后从头开始编号。
    assert_eq!(
        reopened
            .append(blocked, "text", serde_json::json!({}))
            .expect("blocked recovered")
            .seq,
        1
    );
}

#[test]
fn concurrent_oversized_failure_never_regases_committed_seq() {
    let dir = workdir("concurrent");
    let log = Arc::new(JsonlEventLog::open(dir.clone()).expect("open"));
    let s = uuid::Uuid::new_v4();
    let barrier = Arc::new(Barrier::new(2));

    // A：反复尝试超大行，失败后不得回退别人已提交的 seq。
    let a_log = Arc::clone(&log);
    let a_bar = Arc::clone(&barrier);
    let a = thread::spawn(move || {
        a_bar.wait();
        let huge = serde_json::json!({"blob": "y".repeat(MAX_LINE_BYTES)});
        for _ in 0..8 {
            assert!(matches!(
                a_log.append(s, "tool_result", huge.clone()),
                Err(CoreError::LineTooLarge { .. })
            ));
        }
    });

    // B：正常追加，seq 必须严格递增，last_seq 不得倒退。
    let b_log = Arc::clone(&log);
    let b_bar = Arc::clone(&barrier);
    let b = thread::spawn(move || {
        b_bar.wait();
        let mut prev = 0u64;
        for i in 0..24u64 {
            let seen = b_log.last_seq(s).unwrap_or(0);
            assert!(seen >= prev, "last_seq 倒退: {seen} < {prev}");
            let e = b_log
                .append(s, "text", serde_json::json!({"i": i}))
                .expect("append");
            assert!(
                e.seq > seen,
                "新事件 seq 必须大于已提交 seq: {} <= {seen}",
                e.seq
            );
            prev = e.seq;
        }
    });

    a.join().expect("A");
    b.join().expect("B");

    let events = log.replay(s, 0, 100).expect("replay");
    let seqs = seqs_of(&events);
    assert_eq!(seqs, (1..=24u64).collect::<Vec<u64>>(), "seq 连续且无覆盖");
    assert_eq!(log.last_seq(s), Some(24));

    let reopened = JsonlEventLog::open(dir).expect("reopen");
    assert_eq!(
        seqs_of(&reopened.replay(s, 0, 100).expect("replay")),
        seqs,
        "并发后磁盘与内存仍一致"
    );
}
