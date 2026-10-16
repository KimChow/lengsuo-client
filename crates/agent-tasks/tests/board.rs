//! 看板行为测试：create/get/update_text/list 排序与会话隔离、NotFound。

mod support;

use agent_tasks::{Task, TaskBoard, TaskError, TaskStatus};
use support::{board, create, frozen_board};
use uuid::Uuid;

// ---- subject 校验 ----

#[test]
fn empty_subject_is_rejected_on_create() {
    let mut b = board();
    let sid = Uuid::new_v4();
    for bad in ["", " ", "\t", "\n", "\u{00a0}"] {
        assert_eq!(
            b.create(sid, bad, "描述"),
            Err(TaskError::EmptySubject),
            "空白 subject 应被拒: {bad:?}"
        );
    }
    assert_eq!(b.list_by_session(sid).len(), 0, "被拒的创建不留痕迹");
}

#[test]
fn non_empty_subject_is_kept_verbatim() {
    let mut b = board();
    let sid = Uuid::new_v4();
    let t = b
        .create(sid, "  带空格的标题  ", "d")
        .expect("非空 subject 应通过");
    assert_eq!(t.subject, "  带空格的标题  ", "只校验非空，不裁剪存储值");
    assert_eq!(t.session_id, sid);
    assert_eq!(t.status, TaskStatus::Pending, "初始状态 pending");
    assert_eq!(t.description, "d");
    assert_eq!(t.created_at_ms, t.updated_at_ms, "创建时两个时间戳相同");
    assert!(b.get(t.id).is_ok());
}

// ---- update_text ----

#[test]
fn update_text_rejects_empty_subject_but_keeps_old() {
    let mut b = board();
    let sid = Uuid::new_v4();
    let t = b.create(sid, "原标题", "原描述").unwrap();
    assert_eq!(
        b.update_text(t.id, Some(""), Some("新描述")),
        Err(TaskError::EmptySubject)
    );
    assert_eq!(
        b.update_text(t.id, Some("   "), None),
        Err(TaskError::EmptySubject)
    );
    let kept = b.get(t.id).unwrap();
    assert_eq!(kept.subject, "原标题");
    assert_eq!(kept.description, "原描述", "校验先于写入，不得部分更新");
}

#[test]
fn update_text_applies_either_or_both_fields() {
    let mut b = board();
    let t = b.create(Uuid::new_v4(), "s0", "d0").unwrap();

    let only_desc = b.update_text(t.id, None, Some("d1")).unwrap();
    assert_eq!(only_desc.subject, "s0");
    assert_eq!(only_desc.description, "d1");

    let only_subj = b.update_text(t.id, Some("s2"), None).unwrap();
    assert_eq!(only_subj.subject, "s2");
    assert_eq!(only_subj.description, "d1");

    let both = b.update_text(t.id, Some("s3"), Some("d3")).unwrap();
    assert_eq!(both.subject, "s3");
    assert_eq!(both.description, "d3");

    // None/None 是空操作：内容不变。
    let noop = b.update_text(t.id, None, None).unwrap();
    assert_eq!(noop, both);
}

#[test]
fn update_text_does_not_touch_status_or_created_at() {
    let mut b = frozen_board();
    let t = b.create(Uuid::new_v4(), "s", "d").unwrap();
    b.update_status(t.id, TaskStatus::InProgress).unwrap();
    let after = b.update_text(t.id, Some("s2"), None).unwrap();
    assert_eq!(after.status, TaskStatus::InProgress, "改文本不改状态");
    assert_eq!(after.created_at_ms, t.created_at_ms);

    // 同值写入不刷新 updated_at。
    let before_ms = after.updated_at_ms;
    let same = b.update_text(t.id, Some("s2"), None).unwrap();
    assert_eq!(same.updated_at_ms, before_ms, "无变化不刷新");
}

// ---- NotFound ----

#[test]
fn unknown_id_is_not_found_on_every_entry_point() {
    let mut b = board();
    let ghost = Uuid::new_v4();
    assert_eq!(b.get(ghost).err(), Some(TaskError::NotFound));
    assert_eq!(
        b.update_status(ghost, TaskStatus::InProgress).err(),
        Some(TaskError::NotFound)
    );
    assert_eq!(
        b.update_text(ghost, Some("x"), None).err(),
        Some(TaskError::NotFound)
    );
    assert_eq!(b.to_json(ghost).err(), Some(TaskError::NotFound));
    assert!(b.list_by_session(ghost).is_empty());
}

// ---- list 排序与会话隔离 ----

#[test]
fn list_by_session_is_sorted_by_created_at() {
    let mut b = board();
    let sid = Uuid::new_v4();
    // 注入时钟每调用一次 +1ms，因此创建顺序即时序顺序。
    let first = b.create(sid, "1", "").unwrap();
    let second = b.create(sid, "2", "").unwrap();
    let third = b.create(sid, "3", "").unwrap();

    let listed = b.list_by_session(sid);
    let ids: Vec<Uuid> = listed.iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![first.id, second.id, third.id]);
    let times: Vec<u64> = listed.iter().map(|t| t.created_at_ms).collect();
    assert!(
        times.windows(2).all(|w| w[0] < w[1]),
        "created_at_ms 严格升序: {times:?}"
    );
}

#[test]
fn list_is_isolated_per_session() {
    let mut b = board();
    let s1 = Uuid::new_v4();
    let s2 = Uuid::new_v4();
    let a = b.create(s1, "会话1-A", "").unwrap();
    let x = b.create(s2, "会话2-X", "").unwrap();
    let c = b.create(s1, "会话1-C", "").unwrap();

    let l1: Vec<Uuid> = b.list_by_session(s1).iter().map(|t| t.id).collect();
    let l2: Vec<Uuid> = b.list_by_session(s2).iter().map(|t| t.id).collect();
    assert_eq!(l1, vec![a.id, c.id], "会话 1 按创建顺序含两个任务");
    assert_eq!(l2, vec![x.id], "会话 2 只看得到自己的任务");
    assert!(
        b.list_by_session(Uuid::new_v4()).is_empty(),
        "未知会话为空列表"
    );
}

#[test]
fn list_is_stable_when_created_at_ties() {
    // 同一毫秒创建的任务：顺序按 id 升序，且多次调用一致（不随 HashMap 抖动）。
    let mut b = frozen_board();
    let sid = Uuid::new_v4();
    let ids_in: Vec<Uuid> = ["a", "b", "c"]
        .iter()
        .map(|s| b.create(sid, s, "").unwrap().id)
        .collect();
    let mut expected = ids_in.clone();
    expected.sort();

    let listed: Vec<Uuid> = b.list_by_session(sid).iter().map(|t| t.id).collect();
    assert_eq!(listed, expected, "同毫秒按 id 升序");
    let again: Vec<Uuid> = b.list_by_session(sid).iter().map(|t| t.id).collect();
    assert_eq!(listed, again, "重复调用顺序一致");
}

#[test]
fn task_is_immutable_snapshot_from_board() {
    // create/update 返回快照：改快照不影响看板内状态。
    let mut b = board();
    let sid = Uuid::new_v4();
    let mut t = b.create(sid, "s", "d").unwrap();
    t.subject = "改了副本".into();
    let Task { id, .. } = t;
    assert_eq!(b.get(id).unwrap().subject, "s");
}

#[test]
fn default_board_is_empty_and_usable() {
    let mut b = TaskBoard::default();
    assert!(b.list_by_session(Uuid::new_v4()).is_empty());
    let t = create(&mut b, "首个");
    assert_eq!(b.get(t.id).unwrap().subject, "首个");
}

#[test]
fn new_board_uses_system_clock() {
    // 生产入口走系统时钟：时间戳为合理 Unix 毫秒，id 为 uuid v4。
    let mut b = TaskBoard::new();
    let t = b.create(Uuid::new_v4(), "s", "d").unwrap();
    assert!(t.created_at_ms > 1_600_000_000_000, "应为合理 Unix 毫秒");
    assert_eq!(t.created_at_ms, t.updated_at_ms);
    assert_eq!(t.id.get_version_num(), 4, "id 为 uuid v4");
    b.update_status(t.id, TaskStatus::InProgress).unwrap();
    assert!(b.get(t.id).unwrap().updated_at_ms >= t.created_at_ms);
}
