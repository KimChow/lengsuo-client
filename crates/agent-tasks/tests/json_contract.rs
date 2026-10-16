//! JSON 契约测试：to_json 字段名冻结、status 小写词、Task 结构往返。

mod support;

use agent_tasks::{Task, TaskStatus};
use serde_json::json;
use support::{board, frozen_board};
use uuid::Uuid;

/// 冻结字段名（多一个少一个都是契约破坏）。
const FROZEN_FIELDS: [&str; 7] = [
    "created_at_ms",
    "description",
    "id",
    "session_id",
    "status",
    "subject",
    "updated_at_ms",
];

#[test]
fn json_field_names_are_frozen() {
    let mut b = frozen_board();
    let sid = Uuid::new_v4();
    let t = b.create(sid, "标题", "描述").unwrap();
    let value = b.to_json(t.id).expect("to_json");
    let obj = value.as_object().expect("JSON object");

    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    let expected: Vec<&str> = FROZEN_FIELDS.to_vec();
    assert_eq!(keys, expected, "字段名冻结，不得增减");
    assert_eq!(obj["id"], json!(t.id.to_string()), "id 为字符串形式 uuid");
    assert_eq!(obj["session_id"], json!(sid.to_string()));
    assert_eq!(obj["subject"], json!("标题"));
    assert_eq!(obj["description"], json!("描述"));
    assert_eq!(obj["status"], json!("pending"));
    assert_eq!(
        obj["created_at_ms"],
        json!(t.created_at_ms),
        "时间为整数毫秒"
    );
    assert_eq!(obj["updated_at_ms"], json!(t.updated_at_ms));
    assert!(obj["created_at_ms"].is_u64(), "时间戳为非负整数");
}

#[test]
fn json_status_is_lowercase_word_for_every_state() {
    let mut b = board();
    let t = b.create(Uuid::new_v4(), "s", "d").unwrap();
    assert_eq!(b.to_json(t.id).unwrap()["status"], json!("pending"));
    b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert_eq!(
        b.to_json(t.id).unwrap()["status"],
        json!("in_progress"),
        "snake_case 小写词"
    );
    b.update_status(t.id, TaskStatus::Done).unwrap();
    assert_eq!(b.to_json(t.id).unwrap()["status"], json!("done"));

    let mut b2 = board();
    let c = b2.create(Uuid::new_v4(), "s", "d").unwrap();
    b2.update_status(c.id, TaskStatus::InProgress).unwrap();
    b2.update_status(c.id, TaskStatus::Cancelled).unwrap();
    assert_eq!(b2.to_json(c.id).unwrap()["status"], json!("cancelled"));
}

#[test]
fn json_reflects_latest_text() {
    let mut b = board();
    let t = b.create(Uuid::new_v4(), "旧", "旧描述").unwrap();
    b.update_text(t.id, Some("新"), Some("新描述")).unwrap();
    let value = b.to_json(t.id).unwrap();
    assert_eq!(value["subject"], json!("新"));
    assert_eq!(value["description"], json!("新描述"));
}

#[test]
fn status_serde_roundtrip_uses_frozen_words() {
    for status in TaskStatus::ALL {
        let text = serde_json::to_string(&status).unwrap();
        assert_eq!(text, format!("\"{}\"", status.as_str()));
        let parsed: TaskStatus = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, status);
    }
    // 大写/未知词不接受。
    assert!(serde_json::from_str::<TaskStatus>("\"PENDING\"").is_err());
    assert!(serde_json::from_str::<TaskStatus>("\"blocked\"").is_err());
}

#[test]
fn task_struct_serde_roundtrip() {
    let mut b = board();
    let t = b.create(Uuid::new_v4(), "s", "d").unwrap();
    let text = serde_json::to_string(&t).unwrap();
    let back: Task = serde_json::from_str(&text).unwrap();
    assert_eq!(back, t, "Task 自身序列化与 to_json 字段一致");
    // 顶层字段名同样是冻结集合。
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut keys: Vec<&String> = value.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, FROZEN_FIELDS.to_vec());
}
