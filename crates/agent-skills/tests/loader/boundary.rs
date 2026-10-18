//! symlink 与授权根边界：目录/文件软链越界 fail-closed、根内互链不误伤、
//! `..` 组件按 canonical 真实边界判定、根外技能不可加载。

use std::fs;

use agent_skills::{InvocationSource, SkillCatalog};

use crate::{catalog_for, host_tools, names_of, two_roots};

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
