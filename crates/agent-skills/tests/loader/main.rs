//! `SkillCatalog` 安全入口测试：授权目录边界（canonicalize 防 symlink 越界）、
//! 禁用不可见不可加载、调用来源门、常驻目录只含元数据、正文只在显式 load 返回。
//!
//! 假数据：技能正文里的字符串是测试专用假凭据标记，非任何真实秘密。
//!
//! 按主题拆分：visibility（可见性与禁用）、boundary（symlink 与授权根边界）、
//! invocation（调用来源门与工具交集）、registry（注册与失败闭合语义）。

mod boundary;
mod invocation;
mod registry;
mod visibility;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agent_skills::SkillCatalog;
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
