//! `SkillRegistry` 行为测试：多目录覆盖优先级、load 扫描、find 大小写敏感、NotFound。

use std::fs;
use std::path::{Path, PathBuf};

use agent_skills::{Skill, SkillRegistry, SkillsError};
use tempfile::TempDir;

fn write_skill(root: &Path, dir_name: &str, content: &str) -> PathBuf {
    let dir = root.join(dir_name);
    fs::create_dir_all(&dir).expect("创建技能目录");
    fs::write(dir.join("SKILL.md"), content).expect("写入 SKILL.md");
    dir
}

/// 建一个含单个技能的目录，返回该技能正文全文（用于断言注入即返回全文）。
#[test]
fn load_scans_first_level_skill_md_and_sorts_by_name() {
    let tmp = TempDir::new().unwrap();
    write_skill(
        tmp.path(),
        "beta",
        "---\nname: beta\ndescription: B\n---\nB 正文\n",
    );
    write_skill(tmp.path(), "alpha", "alpha 没有 front-matter\n正文\n");
    // 非技能子目录（无 SKILL.md）与隐藏目录应被忽略。
    fs::create_dir_all(tmp.path().join("not-a-skill")).unwrap();
    fs::write(tmp.path().join("not-a-skill").join("README.md"), "x").unwrap();
    write_skill(tmp.path(), ".hidden", "隐藏技能\n");
    // 顶层散落文件也应忽略。
    fs::write(tmp.path().join("SKILL.md"), "顶层不该算技能\n").unwrap();

    let reg = SkillRegistry::with_dirs(vec![tmp.path().to_path_buf()]);
    let skills = reg.load().unwrap();
    let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta"]);
    assert_eq!(skills[0].description, "");
    assert_eq!(skills[1].description, "B");
}

#[test]
fn later_dir_overrides_same_name() {
    let user = TempDir::new().unwrap();
    let site = TempDir::new().unwrap();
    write_skill(
        user.path(),
        "commit",
        "---\nname: commit\n---\n用户版正文\n",
    );
    write_skill(
        site.path(),
        "commit",
        "---\nname: commit\ndescription: 站点级\n---\n站点版正文\n",
    );

    // 后注册者优先：site 在 user 之后 ⇒ site 覆盖。
    let reg = SkillRegistry::with_dirs(vec![user.path().to_path_buf(), site.path().to_path_buf()]);
    let skills = reg.load().unwrap();
    assert_eq!(skills.len(), 1, "同名应去重: {skills:?}");
    assert_eq!(skills[0].body, "站点版正文");
    assert_eq!(skills[0].description, "站点级");
    assert_eq!(skills[0].path, site.path().join("commit").join("SKILL.md"));

    // 反向注册顺序 ⇒ user 覆盖 site。
    let reg2 = SkillRegistry::with_dirs(vec![site.path().to_path_buf(), user.path().to_path_buf()]);
    let s2 = reg2.load().unwrap();
    assert_eq!(s2.len(), 1);
    assert_eq!(s2[0].body, "用户版正文");

    // find 同样遵循覆盖优先级。
    let found = reg.find("commit").unwrap().expect("应命中");
    assert_eq!(found.body, "站点版正文");
}

#[test]
fn find_is_case_sensitive() {
    let tmp = TempDir::new().unwrap();
    write_skill(tmp.path(), "pdf-forms", "---\nname: pdf-forms\n---\n正文\n");
    let reg = SkillRegistry::with_dirs(vec![tmp.path().to_path_buf()]);
    assert!(reg.find("pdf-forms").unwrap().is_some());
    assert!(reg.find("PDF-Forms").unwrap().is_none());
    assert!(reg.find("Pdf-forms").unwrap().is_none());
    assert!(reg.find("pdf").unwrap().is_none());
}

#[test]
fn find_missing_name_returns_ok_none() {
    let tmp = TempDir::new().unwrap();
    write_skill(tmp.path(), "only", "正文\n");
    let reg = SkillRegistry::with_dirs(vec![tmp.path().to_path_buf()]);
    let out = reg.find("absent").unwrap();
    assert!(out.is_none(), "NotFound 由调用方处理，find 返回 None");
}

#[test]
fn missing_root_dir_reports_not_found() {
    // 注册了不存在的根目录 ⇒ 显式 NotFound（配置写错不静默当作空目录）。
    let tmp = TempDir::new().unwrap();
    let reg = SkillRegistry::with_dirs(vec![tmp.path().join("does-not-exist")]);
    let err = reg.load().unwrap_err();
    assert!(matches!(err, SkillsError::NotFound), "实得 {err:?}");
    let err2 = reg.find("anything").unwrap_err();
    assert!(matches!(err2, SkillsError::NotFound), "实得 {err2:?}");
    // 上层若要容错，注册前自行判断即可。
    let tolerant = SkillRegistry::with_dirs(
        vec![tmp.path().join("does-not-exist")]
            .into_iter()
            .filter(|p| p.is_dir())
            .collect(),
    );
    assert!(tolerant.load().unwrap().is_empty());
}

#[test]
fn registry_with_no_dirs_loads_empty() {
    let reg = SkillRegistry::with_dirs(vec![]);
    assert!(reg.load().unwrap().is_empty());
    assert!(reg.find("anything").unwrap().is_none());
}

#[test]
fn injected_body_is_the_full_text() {
    let tmp = TempDir::new().unwrap();
    let full = "---\nname: reviewer\ndescription: 代码审查\n---\n# 审查步骤\n\n1. 读 diff\n2. 找风险\n\n末行\n";
    write_skill(tmp.path(), "reviewer", full);
    let reg = SkillRegistry::with_dirs(vec![tmp.path().to_path_buf()]);
    let skill: Skill = reg.find("reviewer").unwrap().expect("应命中");
    // 注入即返回全文：正文逐字一致，仅去掉 front-matter。
    assert_eq!(skill.body, "# 审查步骤\n\n1. 读 diff\n2. 找风险\n\n末行");
    assert!(skill.body.contains("找风险"));
}

#[test]
fn malformed_skill_in_load_is_fail_closed() {
    let tmp = TempDir::new().unwrap();
    write_skill(tmp.path(), "good", "好技能\n");
    write_skill(tmp.path(), "BadName", "非法目录名且不写 front-matter\n");
    let reg = SkillRegistry::with_dirs(vec![tmp.path().to_path_buf()]);
    let err = reg.load().unwrap_err();
    // fail-closed：坏技能让整次 load 失败，且错误里带出坏文件路径。
    assert!(matches!(err, SkillsError::Malformed { .. }), "实得 {err:?}");
    match err {
        SkillsError::Malformed { path, .. } => assert!(path.ends_with("BadName/SKILL.md")),
        _ => unreachable!(),
    }
    // 干净目录不受影响。
    let other = TempDir::new().unwrap();
    write_skill(other.path(), "good", "另一个好技能\n");
    let ok = SkillRegistry::with_dirs(vec![other.path().to_path_buf()]);
    assert!(ok.find("good").unwrap().is_some());
}

#[test]
fn same_name_inside_one_dir_uses_later_scan_order() {
    // front-matter name 与所在目录名不同，且另一子目录以该 front-matter 名命名 ⇒
    // 合并后按扫描次序的后来者为准，不产生两条同名技能。
    let tmp = TempDir::new().unwrap();
    write_skill(
        tmp.path(),
        "alias-dir",
        "---\nname: shared\ndescription: A\n---\n别名正文\n",
    );
    write_skill(
        tmp.path(),
        "shared",
        "---\nname: shared\ndescription: B\n---\n规范正文\n",
    );
    let reg = SkillRegistry::with_dirs(vec![tmp.path().to_path_buf()]);
    let skills = reg.load().unwrap();
    assert_eq!(skills.len(), 1);
    // 目录名按字典序扫描：shared 在 alias-dir 之后，故后者生效。
    assert_eq!(skills[0].body, "规范正文");
    assert_eq!(skills[0].description, "B");
    assert_eq!(skills[0].path, tmp.path().join("shared").join("SKILL.md"));
}
