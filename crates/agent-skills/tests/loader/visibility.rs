//! 常驻目录可见性与禁用语义：目录不携带正文、宿主禁用名单、
//! front-matter 禁用位、不可靠禁用值失败闭合为禁用。

use agent_skills::InvocationSource;
use tempfile::TempDir;

use crate::{catalog_for, host_tools, make_skill, names_of, plain, FAKE_SECRET};

#[test]
fn resident_catalog_carries_no_body_text() {
    let tmp = TempDir::new().unwrap();
    make_skill(tmp.path(), "pdf-forms", &plain("pdf-forms"));
    let catalog = catalog_for(tmp.path(), &[]);
    let listed = catalog.list().unwrap();
    assert_eq!(listed.len(), 1);
    // 常驻目录只有 name/description/path 标识：把整个目录 Debug 出来也不该有正文。
    let dump = format!("{listed:?}");
    assert!(
        !dump.contains(FAKE_SECRET),
        "常驻目录不得携带正文全文: {dump}"
    );
    assert_eq!(listed[0].name, "pdf-forms");
    assert_eq!(listed[0].description, "pdf-forms 描述");
    // path 是标识（canonical 后的 SKILL.md 路径），供诊断定位。
    assert!(
        listed[0].path.ends_with("SKILL.md"),
        "实得 {:?}",
        listed[0].path
    );

    // 正文只在显式 load 时返回，且仍是全文（不裁剪）。
    let loaded = catalog
        .load("pdf-forms", InvocationSource::User, &host_tools(&["Read"]))
        .expect("显式加载");
    assert_eq!(loaded.body, format!("正文含 {FAKE_SECRET}"));
    assert_eq!(loaded.name, "pdf-forms");
}

#[test]
fn disabled_skill_is_invisible_and_not_loadable() {
    let tmp = TempDir::new().unwrap();
    make_skill(tmp.path(), "alpha", &plain("alpha"));
    make_skill(tmp.path(), "beta", &plain("beta"));
    let catalog = catalog_for(tmp.path(), &["beta"]);

    assert_eq!(
        names_of(&catalog),
        vec!["alpha"],
        "禁用技能不出现在常驻目录"
    );
    // 不可见之外仍必须不可加载：不能靠直接给名字绕过。
    let err = catalog
        .load("beta", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::Disabled { ref name } if name == "beta"),
        "禁用技能加载应报 Disabled，实得 {err:?}"
    );
    // 未禁用的仍可加载。
    assert!(catalog
        .load("alpha", InvocationSource::User, &host_tools(&["Read"]))
        .is_ok());
    // 空禁用集时可见（对照，证明上一条不是恒假）。
    let open = catalog_for(tmp.path(), &[]);
    assert_eq!(names_of(&open), vec!["alpha", "beta"]);
    assert!(open
        .load("beta", InvocationSource::User, &host_tools(&["Read"]))
        .is_ok());
}

#[test]
fn front_matter_disabled_flag_is_invisible_and_not_loadable() {
    let tmp = TempDir::new().unwrap();
    make_skill(
        tmp.path(),
        "off",
        "---\nname: off\ndisabled: true\n---\n正文\n",
    );
    make_skill(tmp.path(), "on", &plain("on"));
    // 宿主没写禁用名单，仅凭 front-matter 的 disabled 也必须禁用。
    let catalog = catalog_for(tmp.path(), &[]);
    assert_eq!(names_of(&catalog), vec!["on"], "disabled: true 应不可见");
    let err = catalog
        .load("off", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::Disabled { .. }),
        "实得 {err:?}"
    );
}

#[test]
fn unparsable_disabled_flag_fails_closed_to_disabled() {
    let tmp = TempDir::new().unwrap();
    make_skill(
        tmp.path(),
        "maybe",
        "---\nname: maybe\ndisabled: maybe\n---\n正文\n",
    );
    let catalog = catalog_for(tmp.path(), &[]);
    assert!(names_of(&catalog).is_empty(), "不可靠值应视为禁用");
    let err = catalog
        .load("maybe", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::Disabled { .. }),
        "实得 {err:?}"
    );
}
