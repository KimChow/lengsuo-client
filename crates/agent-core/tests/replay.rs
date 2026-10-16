//! EventLog：JSONL 追加、seq 单调、启动回放、断行/乱序容错（开工说明 §5、§6）。

use std::path::{Path, PathBuf};

use agent_core::event_log::{EventLog, JsonlEventLog};

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agent-core-replay-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create workdir");
    dir
}

fn write_head(dir: &Path, session: &str, lines: &[&str]) -> PathBuf {
    let path = dir.join(format!("events-{session}.jsonl"));
    let mut body = vec![format!(
        r#"{{"schemaVersion":1,"kind":"header","sessionId":"{session}"}}"#
    )];
    body.extend(lines.iter().map(|s| s.to_string()));
    std::fs::write(&path, body.join("\n") + "\n").expect("write jsonl");
    path
}

fn line(seq: u64, session: &str, kind: &str) -> String {
    let ts_ms = seq * 10;
    format!(
        r#"{{"seq":{seq},"sessionId":"{session}","kind":"{kind}","payload":{{}},"tsMs":{ts_ms}}}"#
    )
}

#[test]
fn append_assigns_monotonic_seq_within_session() {
    let dir = workdir("seq");
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let s = uuid::Uuid::new_v4();
    let a = log
        .append(s, "text", serde_json::json!({"a":1}))
        .expect("append a");
    let b = log
        .append(s, "tool_result", serde_json::json!({"b":2}))
        .expect("append b");
    let c = log
        .append(s, "done", serde_json::json!({}))
        .expect("append c");
    assert_eq!((a.seq, b.seq, c.seq), (1, 2, 3));
    let other = uuid::Uuid::new_v4();
    let d = log
        .append(other, "text", serde_json::json!({}))
        .expect("append other");
    assert_eq!(d.seq, 1, "seq 是会话内单调，不是全局");
    assert_eq!(a.session_id, s);
    assert!(a.ts_ms > 0);
}

#[test]
fn header_carries_schema_version_from_day_one() {
    let dir = workdir("hdr");
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let s = uuid::Uuid::new_v4();
    log.append(s, "text", serde_json::json!({"i":1}))
        .expect("append");
    log.append(s, "text", serde_json::json!({"i":2}))
        .expect("append");
    let raw = std::fs::read_to_string(dir.join(format!("events-{s}.jsonl"))).expect("read");
    let mut iter = raw.lines();
    let head: serde_json::Value =
        serde_json::from_str(iter.next().expect("header line")).expect("header json");
    assert_eq!(head["schemaVersion"], 1);
    assert_eq!(head["kind"], "header");
    assert_eq!(head["sessionId"].as_str().expect("sid"), s.to_string());
    assert_eq!(iter.count(), 2, "两条事件行");
}

#[test]
fn replay_matches_appended_events() {
    let dir = workdir("same");
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let s = uuid::Uuid::new_v4();
    let mut written = Vec::new();
    for i in 0..5 {
        written.push(
            log.append(s, "text", serde_json::json!({"i": i}))
                .expect("append"),
        );
    }
    let reloaded = JsonlEventLog::open(dir.clone()).expect("reopen replays seq");
    let events = reloaded.replay(s, 0, 100).expect("replay");
    assert_eq!(events.len(), 5);
    for (got, want) in events.iter().zip(written.iter()) {
        assert_eq!(got.seq, want.seq);
        assert_eq!(got.kind, want.kind);
        assert_eq!(got.payload, want.payload);
        assert_eq!(got.ts_ms, want.ts_ms);
    }
    let next = reloaded
        .append(s, "text", serde_json::json!({"i": 5}))
        .expect("append after replay");
    assert_eq!(next.seq, 6, "重启后 seq 必须接续，不得重置");
    assert_eq!(reloaded.last_seq(s), Some(6));
}

#[test]
fn replay_after_restart_restores_session_index() {
    let dir = workdir("idx");
    let s = uuid::Uuid::new_v4();
    {
        let log = JsonlEventLog::open(dir.clone()).expect("open");
        log.append(s, "text", serde_json::json!({"i": 1}))
            .expect("append");
    }
    let log = JsonlEventLog::open(dir.clone()).expect("reopen");
    assert_eq!(log.sessions(), vec![s], "启动回放必须恢复会话索引");
    assert_eq!(log.last_seq(s), Some(1));
    assert_eq!(log.last_seq(uuid::Uuid::new_v4()), None);
}

#[test]
fn replay_is_paginated_by_seq() {
    let dir = workdir("page");
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let s = uuid::Uuid::new_v4();
    for i in 0..10 {
        log.append(s, "text", serde_json::json!({"i": i}))
            .expect("append");
    }
    let page = log.replay(s, 3, 4).expect("page after seq 3");
    let seqs: Vec<u64> = page.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![4, 5, 6, 7]);
    assert!(log.replay(s, 10, 5).expect("beyond tail").is_empty());
}

#[test]
fn truncated_last_line_is_dropped_not_fatal() {
    let dir = workdir("trunc");
    let s = uuid::Uuid::new_v4();
    let path = write_head(
        &dir,
        &s.to_string(),
        &[&line(1, &s.to_string(), "text"), r#"{"seq":2,"sessio"#],
    );
    let log = JsonlEventLog::open(dir.clone()).expect("open tolerates broken tail");
    let events = log.replay(s, 0, 10).expect("replay");
    assert_eq!(events.len(), 1, "断行只丢最后一行");
    assert_eq!(log.last_seq(s), Some(1));
    let next = log
        .append(s, "text", serde_json::json!({}))
        .expect("append after broken tail");
    assert_eq!(next.seq, 2, "断裂行不得占用 seq");
    let raw = std::fs::read_to_string(&path).expect("read back");
    // 半行垃圾不得残留；逐行必须是完整 JSON（合法追加行与垃圾片段共享前缀，不能用 contains 判定）
    for l in raw.lines() {
        serde_json::from_str::<serde_json::Value>(l).expect("修复后不得再保留半行垃圾");
    }
    assert!(raw.ends_with('\n'));
}

#[test]
fn out_of_order_and_duplicate_seq_are_repaired() {
    let dir = workdir("ooo");
    let sid = uuid::Uuid::new_v4();
    let s = sid.to_string();
    write_head(
        &dir,
        &s,
        &[
            &line(3, &s, "text"),
            &line(1, &s, "text"),
            &line(1, &s, "dup"),
            &line(2, &s, "text"),
        ],
    );
    let log = JsonlEventLog::open(dir.clone()).expect("open repairs ordering");
    let events = log.replay(sid, 0, 10).expect("replay");
    let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3], "乱序必须按 seq 排序");
    assert_eq!(
        events.iter().filter(|e| e.kind == "dup").count(),
        0,
        "重复 seq 只留先出现的"
    );
    assert_eq!(log.last_seq(sid), Some(3));
    let next = log
        .append(sid, "text", serde_json::json!({}))
        .expect("append");
    assert_eq!(next.seq, 4);
}

#[test]
fn seq_gap_is_tolerated_and_continues() {
    let dir = workdir("gap");
    let sid = uuid::Uuid::new_v4();
    let s = sid.to_string();
    write_head(&dir, &s, &[&line(1, &s, "text"), &line(7, &s, "text")]);
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let events = log.replay(sid, 0, 10).expect("replay");
    assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 7]);
    assert_eq!(log.last_seq(sid), Some(7), "空洞后从最大 seq 继续");
}

#[test]
fn header_seq_mismatch_and_bad_json_lines_are_skipped() {
    let dir = workdir("bad");
    let sid = uuid::Uuid::new_v4();
    let s = sid.to_string();
    write_head(
        &dir,
        &s,
        &[
            "not json at all",
            r#"{"schemaVersion":1,"kind":"header","sessionId":"x"}"#,
            &line(1, &s, "text"),
            r#"{"kind":"text"}"#,
            &line(2, &s, "text"),
        ],
    );
    let log = JsonlEventLog::open(dir.clone()).expect("open");
    let events = log.replay(sid, 0, 10).expect("replay");
    assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn unknown_schema_version_fails_closed() {
    let dir = workdir("ver");
    let s = uuid::Uuid::new_v4().to_string();
    let path = dir.join(format!("events-{s}.jsonl"));
    std::fs::write(
        &path,
        format!(
            "{}\n",
            r#"{{"schemaVersion":99,"kind":"header","sessionId":"{s}"}}"#
        ),
    )
    .expect("write");
    let err = JsonlEventLog::open(dir)
        .err()
        .expect("future schema version must fail closed");
    assert!(
        matches!(err, agent_core::error::CoreError::SchemaVersion { .. }),
        "{err:?}"
    );
}

#[test]
fn append_rejects_too_large_line() {
    let dir = workdir("big");
    let log = JsonlEventLog::open(dir).expect("open");
    let s = uuid::Uuid::new_v4();
    let huge = serde_json::json!({"pad": "y".repeat(3 * 1024 * 1024)});
    let err = log
        .append(s, "text", huge)
        .expect_err("oversized line rejected");
    assert!(
        matches!(err, agent_core::error::CoreError::LineTooLarge { .. }),
        "{err:?}"
    );
}
