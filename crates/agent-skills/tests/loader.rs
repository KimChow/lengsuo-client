//! `SkillCatalog` 安全入口测试：授权目录边界（canonicalize 防 symlink 越界）、
//! 禁用不可见不可加载、调用来源门、常驻目录只含元数据、正文只在显式 load 返回。
//!
//! 假数据：技能正文里的字符串是测试专用假凭据标记，非任何真实秘密。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agent_skills::{InvocationSource, SkillCatalog, SkillsError};
use tempfile::TempDir;

/// 假凭据标记：只用来断言它不离开 body、不进常驻目录。
const FAKE_SECRET: &str = "FAKE-CREDENTIAL-do-not-leak";

/// 宿主授权的工具全集（顺序无关，生效集一律升序）。
const HOST_ALL: &[&str] = &["Bash", "Grep", "Read", "Write"];

fn make_skill(root: &Path, dir_name: &str, content: &str) -> PathBuf {
    let dir = root.join(dir_name);
    fs::create_dir_all(&dir).expect("创建技能目录");
    fs::write(dir.join("SKILL.md"), content).expect("写入 SKILL.md");
    dir
}

fn plain(dir_name: &str) -> String {
    format!("---\nname: {dir_name}\ndescription: {dir_name} 描述\n---\n正文含 {FAKE_SECRET}\n")
}

fn host_tools(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn catalog_for(root: &Path, disabled: &[&str]) -> SkillCatalog {
    SkillCatalog::new(
        vec![root.to_path_buf()],
        disabled.iter().map(|d| (*d).to_string()).collect(),
    )
    .expect("构造 catalog")
}

fn names_of(catalog: &SkillCatalog) -> Vec<String> {
    catalog
        .list()
        .expect("列出目录")
        .into_iter()
        .map(|s| s.name)
        .collect()
}

/// 越界用例的公共骨架：授权根内一个真技能 + 根外一个真技能。
fn two_roots() -> (TempDir, TempDir) {
    let inside = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    make_skill(inside.path(), "ok", &plain("ok"));
    make_skill(outside.path(), "escaped", &plain("escaped"));
    (inside, outside)
}

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

#[cfg(unix)]
#[test]
fn symlinked_skill_dir_cannot_escape_authorized_root() {
    let (inside, outside) = two_roots();
    // 授权根内放一个指向根外的符号链接目录，其下有合法 SKILL.md。
    std::os::unix::fs::symlink(
        outside.path().join("escaped"),
        inside.path().join("link-out"),
    )
    .expect("创建 symlink");
    let catalog = catalog_for(inside.path(), &[]);
    let err = catalog.list().unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::OutsideAuthorizedRoot { .. }),
        "越界符号链接必须 fail-closed，实得 {err:?}"
    );
    // 绕过目录列表直接点名加载同样不可行。
    let err2 = catalog
        .load("escaped", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(
            err2,
            agent_skills::AccessError::OutsideAuthorizedRoot { .. }
        ),
        "实得 {err2:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_skill_file_cannot_escape_authorized_root() {
    let (inside, outside) = two_roots();
    let fake = inside.path().join("inner");
    fs::create_dir_all(&fake).expect("创建技能目录");
    std::os::unix::fs::symlink(
        outside.path().join("escaped").join("SKILL.md"),
        fake.join("SKILL.md"),
    )
    .expect("创建 symlink 文件");
    let catalog = catalog_for(inside.path(), &[]);
    let err = catalog
        .load("escaped", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::OutsideAuthorizedRoot { .. }),
        "实得 {err:?}"
    );
    assert!(catalog.list().unwrap_err().to_string().contains("SKILL.md"));
}

#[cfg(unix)]
#[test]
fn symlink_back_inside_same_root_is_still_authorized() {
    let tmp = TempDir::new().unwrap();
    make_skill(tmp.path(), "real", &plain("real"));
    // 根内互链（不逃出授权根）不应误伤：canonical 后仍在根内。
    std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("alias-dir"))
        .expect("创建 symlink");
    let catalog = catalog_for(tmp.path(), &[]);
    // 同一份 SKILL.md 经两条路径扫到，canonical 路径一致 ⇒ 去重成一条。
    assert_eq!(names_of(&catalog), vec!["real"]);
    assert!(catalog
        .load("real", InvocationSource::User, &host_tools(&["Read"]))
        .is_ok());
}

#[test]
fn dot_dot_components_cannot_escape_authorized_root() {
    // 注册路径里带 `..`：canonical 化后仍按真实边界判定，不凭字符串前缀放行。
    let (inside, outside) = two_roots();
    let indirect = inside.path().join("sub").join("..");
    fs::create_dir_all(inside.path().join("sub")).unwrap();
    let catalog = SkillCatalog::new(vec![indirect], Vec::new()).expect("构造 catalog");
    assert_eq!(names_of(&catalog), vec!["ok"], "应只看到授权根内的技能");
    // 授权边界按 canonical 后的真实路径判定；越界技能不在其中。
    let roots = catalog.authorized_roots();
    assert_eq!(roots.len(), 1);
    assert!(roots[0].starts_with(inside.path().canonicalize().unwrap()));
    assert!(!outside.path().join("escaped").starts_with(&roots[0]));
    assert!(matches!(
        catalog.load("escaped", InvocationSource::User, &host_tools(&["Read"])),
        Err(agent_skills::AccessError::NotFound)
    ));
}

#[test]
fn skills_outside_authorized_roots_are_not_loadable() {
    let (inside, outside) = two_roots();
    let catalog = catalog_for(inside.path(), &[]);
    assert_eq!(names_of(&catalog), vec!["ok"]);
    let err = catalog
        .load("escaped", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::NotFound),
        "未授权目录里的技能应视为不存在，实得 {err:?}"
    );
    // 证明它确实存在于磁盘且能被直接解析（即上面不是假阳性）。
    assert!(agent_skills::parse_skill_md(&outside.path().join("escaped")).is_ok());
}

#[test]
fn model_invocation_is_refused_when_disable_model_invocation() {
    let tmp = TempDir::new().unwrap();
    make_skill(
        tmp.path(),
        "user-only",
        "---\nname: user-only\ndisable-model-invocation: true\n---\n正文\n",
    );
    let catalog = catalog_for(tmp.path(), &[]);
    // 可见性不因来源收窄：常驻目录仍列出（宿主按来源过滤是上层职责）。
    assert_eq!(names_of(&catalog), vec!["user-only"]);
    let err = catalog
        .load("user-only", InvocationSource::Model, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::NotInvocable { .. }),
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
    let catalog = catalog_for(tmp.path(), &[]);
    let err = catalog
        .load("internal", InvocationSource::User, &host_tools(&["Read"]))
        .unwrap_err();
    assert!(
        matches!(err, agent_skills::AccessError::NotInvocable { .. }),
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
    let catalog = catalog_for(tmp.path(), &[]);
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
    let catalog = catalog_for(tmp.path(), &[]);
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
