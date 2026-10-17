//! 会话列表隔离：`list_sessions` / `list_session_summaries` 必须按完整
//! `Isolation`（用户/租户/环境）匹配，不得按 `key()` 拼接串比较。
//!
//! 背景：`Isolation::key()` 为 `user_id-tenant_id` 拼接且不含 env，
//! 分段歧义会让不同隔离主体共用会话列表。本套件只覆盖列表过滤；
//! 事件流订阅与审批门仍按 `key()` 分线，不在本卡范围内。

use std::sync::Arc;

use agent_core::provider::EchoProvider;
use agent_core::runtime::{CreateSession, Runtime};
use agent_core::schema::{Isolation, Session};

fn iso(user_id: &str, tenant_id: &str, env_id: Option<&str>) -> Isolation {
    Isolation {
        user_id: user_id.into(),
        tenant_id: tenant_id.into(),
        env_id: env_id.map(Into::into),
    }
}

fn rt(tag: &str) -> Runtime {
    let dir = std::env::temp_dir().join(format!("session-list-iso-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("workdir");
    Runtime::builder()
        .workdir(&dir)
        .provider(Arc::new(EchoProvider))
        .build()
        .expect("runtime")
}

/// 建一个属于该隔离主体的会话，返回会话 id。
fn mk(rt: &Runtime, title: &str, isolation: &Isolation) -> uuid::Uuid {
    rt.create_session(&CreateSession::plain(title, isolation.clone()))
        .expect("create")
        .id
}

/// 排序后的 id 集合（热态是 `BTreeMap<Uuid, _>`，断言不依赖建会话顺序）。
fn sorted_ids(sessions: &[Session]) -> Vec<uuid::Uuid> {
    let mut ids: Vec<uuid::Uuid> = sessions.iter().map(|s| s.id).collect();
    ids.sort();
    ids
}

fn sorted(mut ids: Vec<uuid::Uuid>) -> Vec<uuid::Uuid> {
    ids.sort();
    ids
}

fn listed(rt: &Runtime, isolation: &Isolation) -> Vec<uuid::Uuid> {
    sorted_ids(&rt.list_sessions(isolation))
}

#[test]
fn key_ambiguity_across_segments_does_not_share_list() {
    // 两者的 key() 都是 "a-b-c"，但隔离主体不同。
    let rt = rt("segments");
    let a = mk(&rt, "A", &iso("a-b", "c", None));
    let b = mk(&rt, "B", &iso("a", "b-c", None));

    assert_eq!(
        listed(&rt, &iso("a-b", "c", None)),
        vec![a],
        "分段歧义不得把另一主体的会话列进来"
    );
    assert_eq!(listed(&rt, &iso("a", "b-c", None)), vec![b]);
}

#[test]
fn different_env_id_same_user_tenant_are_separate() {
    let rt = rt("env");
    let one = mk(&rt, "E1", &iso("u", "t", Some("env-1")));
    let two = mk(&rt, "E2", &iso("u", "t", Some("env-2")));
    let none = mk(&rt, "E0", &iso("u", "t", None));

    assert_eq!(listed(&rt, &iso("u", "t", Some("env-1"))), vec![one]);
    assert_eq!(listed(&rt, &iso("u", "t", Some("env-2"))), vec![two]);
    assert_eq!(listed(&rt, &iso("u", "t", None)), vec![none]);
}

#[test]
fn none_env_id_is_not_equal_to_empty_env_id() {
    let rt = rt("empty-env");
    let none = mk(&rt, "N", &iso("u", "t", None));
    let empty = mk(&rt, "E", &iso("u", "t", Some("")));

    assert_eq!(listed(&rt, &iso("u", "t", None)), vec![none]);
    assert_eq!(
        listed(&rt, &iso("u", "t", Some(""))),
        vec![empty],
        "`None` 与 `Some(\"\")` 是不同隔离主体，不得互相列出"
    );
}

#[test]
fn summaries_do_not_leak_across_isolation() {
    let rt = rt("summaries");
    let mine = mk(&rt, "Mine", &iso("a-b", "c", None));
    let theirs = mk(&rt, "Theirs", &iso("a", "b-c", None));

    let summaries = rt.list_session_summaries(&iso("a-b", "c", None));
    assert_eq!(summaries.len(), 1, "摘要列表同样不得跨隔离泄露");
    assert_eq!(summaries[0]["id"].as_str().unwrap(), mine.to_string());
    assert_eq!(summaries[0]["title"].as_str().unwrap(), "Mine");

    let other = rt.list_session_summaries(&iso("a", "b-c", None));
    assert_eq!(other.len(), 1);
    assert_eq!(other[0]["id"].as_str().unwrap(), theirs.to_string());
    assert_eq!(other[0]["title"].as_str().unwrap(), "Theirs");
}

#[test]
fn same_isolation_keeps_all_sessions_visible() {
    // 兼容既有行为：同一隔离主体的多个会话必须全部可见。
    let rt = rt("same");
    let isolation = iso("u", "t", Some("env-1"));
    let first = mk(&rt, "S1", &isolation);
    let second = mk(&rt, "S2", &isolation);
    let third = mk(&rt, "S3", &isolation);

    assert_eq!(listed(&rt, &isolation), sorted(vec![first, second, third]));
    assert_eq!(rt.list_session_summaries(&isolation).len(), 3);
}
