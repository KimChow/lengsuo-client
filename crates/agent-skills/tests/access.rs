//! `SkillCatalog` 按需加载结果面测试：调用来源门、生效工具集只与宿主授权求交集。
//!
//! 授权边界与禁用可见性见 `tests/loader.rs`；限制字段的解析面见 `tests/policy.rs`。
//! 假数据：技能与工具名均为测试专用虚构名。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agent_skills::{AccessError, InvocationSource, SkillCatalog};
use tempfile::TempDir;

/// 宿主授权的工具全集（顺序无关，生效集一��升序）。
const HOST_ALL: &[&str] = &["Bash", "Grep", "Read", "Write"];

fn make_skill(root: &Path, dir_name: &str, content: &str) -> PathBuf {
    let dir = root.join(dir_name);
    fs::create_dir_all(&dir).expect("创建技能目录");
    fs::write(dir.join("SKILL.md"), content).expect("写入 SKILL.md");
    dir
}

fn host_tools(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn catalog_for(root: &Path) -> SkillCatalog {
    SkillCatalog::new(vec![root.to_path_buf()], Vec::new()).expect("构造 catalog")
}

#[test]
fn model_invocation_is_refused_when_disable_model_invocation() {
    let tmp = TempDir::new().unwrap();
    make_skill(
        tmp.path(),
        "user-only",
        "---\nname: user-only\ndisable-model-invocation: true\n---\n正文\n",
    );
    let catalog = catalog_for(tmp.path());
    // 可见性不因来源收窄：常驻目录仍列出（宿主按来源过滤是上层职责）。
    assert_eq!(catalog.list().unwrap().len(), 1);
    let err = catalog
        .load("user-only", InvocationSource::Model, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, AccessError::NotInvocable { .. }),
        "模型自助调用必须被拒，实得 {err:?}"
    );
    // 用户显式触发仍可行。
    assert!(catalog
        .load("user-only", InvocationSource::User, &host_tools(&["Read"]))
        .is_ok());
}

#[test]
fn user_invocation_is_refused_when_user_invocable_false() {
    let tmp = TempDir::new().unwrap();
    make_skill(
        tmp.path(),
        "internal",
        "---\nname: internal\nuser-invocable: false\n---\n正文\n",
    );
    let catalog = catalog_for(tmp.path());
    let err = catalog
        .load("internal", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, AccessError::NotInvocable { .. }),
        "用户菜单显式触发必须被拒，实得 {err:?}"
    );
    assert!(catalog
        .load("internal", InvocationSource::Model, &host_tools(&["Read"]))
        .is_ok());
}

#[test]
fn load_returns_intersected_tools_only() {
    let tmp = TempDir::new().unwrap();
    make_skill(
        tmp.path(),
        "narrow",
        "---\nname: narrow\nallowed-tools: Grep, Read, Bash\n---\n正文\n",
    );
    let catalog = catalog_for(tmp.path());
    let loaded = catalog
        .load(
            "narrow",
            InvocationSource::User,
            &host_tools(&["Grep", "Read"]),
        )
        .expect("加载");
    assert_eq!(
        loaded.effective_tools,
        vec!["Grep", "Read"],
        "生效工具集只能是宿主授权的子集"
    );
    assert!(!loaded.effective_tools.contains(&"Bash".to_string()));
    // 宿主完全不给工具 ⇒ 生效集为空（技能声明不产生授权）。
    let none = catalog
        .load("narrow", InvocationSource::User, &BTreeSet::new())
        .expect("加载");
    assert!(none.effective_tools.is_empty());
}

#[test]
fn unparsable_allowed_tools_loads_with_zero_tools() {
    let tmp = TempDir::new().unwrap();
    // 无法可靠解析的限制声明：正文可加载，但工具集降级为空，绝不当作无限工具。
    make_skill(
        tmp.path(),
        "risky",
        "---\nname: risky\nallowed-tools: Bash(git status:*)\n---\n正文\n",
    );
    let catalog = catalog_for(tmp.path());
    let loaded = catalog
        .load("risky", InvocationSource::User, &host_tools(HOST_ALL))
        .expect("加载");
    assert!(
        loaded.effective_tools.is_empty(),
        "实得 {:?}",
        loaded.effective_tools
    );
    assert!(loaded
        .summary
        .policy
        .fail_closed_fields
        .contains(&"allowed-tools".to_string()));
}
