//! catalog 注册与失败闭合语义：畸形技能令 list 显式失败、未知/缺失名报
//! NotFound、授权根缺失显式报错、多根注册后注册者优先。

use std::collections::BTreeSet;

use agent_skills::{InvocationSource, SkillCatalog, SkillsError};
use tempfile::TempDir;

use crate::{catalog_for, host_tools, make_skill, names_of, plain};

#[test]
fn malformed_skill_stays_fail_closed_through_catalog() {
    let tmp = TempDir::new().unwrap();
    make_skill(tmp.path(), "good", &plain("good"));
    make_skill(tmp.path(), "BadName", "非法目录名且无 front-matter\n");
    let catalog = catalog_for(tmp.path(), &[]);
    let err = catalog.list().unwrap_err();
    match err {
        agent_skills::AccessError::Skills(SkillsError::Malformed { path, .. }) => {
            assert!(path.ends_with("BadName/SKILL.md"), "实得 {path:?}");
        }
        other => panic!("期望底层 Malformed，实得 {other:?}"),
    }
    // 干净根不受影响。
    let other = TempDir::new().unwrap();
    make_skill(other.path(), "good", &plain("good"));
    assert_eq!(names_of(&catalog_for(other.path(), &[])), vec!["good"]);
}

#[test]
fn unknown_and_missing_name_loads_not_found() {
    let tmp = TempDir::new().unwrap();
    make_skill(tmp.path(), "only", &plain("only"));
    let catalog = catalog_for(tmp.path(), &[]);
    assert!(matches!(
        catalog.load("absent", InvocationSource::User, &host_tools(&["Read"])),
        Err(agent_skills::AccessError::NotFound)
    ));
    // 大小写敏感沿用既有语义。
    assert!(matches!(
        catalog.load("ONLY", InvocationSource::User, &host_tools(&["Read"])),
        Err(agent_skills::AccessError::NotFound)
    ));
}

#[test]
fn missing_authorized_root_is_reported_not_silently_empty() {
    let tmp = TempDir::new().unwrap();
    let err = SkillCatalog::new(vec![tmp.path().join("nope")], Vec::new()).unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::Boundary { .. }),
        "授权根缺失必须显式失败，实得 {err:?}"
    );
    // 空根列表是合法的空 catalog（宿主可显式选择「无授权目录」）。
    let empty = SkillCatalog::new(Vec::new(), Vec::new()).expect("构造空 catalog");
    assert!(empty.list().unwrap().is_empty());
    assert!(matches!(
        empty.load("anything", InvocationSource::User, &BTreeSet::new()),
        Err(agent_skills::AccessError::NotFound)
    ));
}

#[test]
fn later_root_wins_same_priority_as_registry() {
    // 与 SkillRegistry 一致的覆盖次序：后注册者优先，catalog 不改语义。
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    make_skill(a.path(), "shared", "---\nname: shared\n---\nA 正文\n");
    make_skill(b.path(), "shared", "---\nname: shared\n---\nB 正文\n");
    let catalog = SkillCatalog::new(
        vec![a.path().to_path_buf(), b.path().to_path_buf()],
        Vec::new(),
    )
    .expect("构造 catalog");
    let listed = catalog.list().unwrap();
    assert_eq!(listed.len(), 1);
    let loaded = catalog
        .load("shared", InvocationSource::User, &host_tools(&["Read"]))
        .expect("加载");
    assert_eq!(loaded.body, "B 正文");
}
