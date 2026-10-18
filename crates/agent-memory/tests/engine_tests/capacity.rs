//! §5.3 容量：字符计数、边界含等号、拒绝时不落半盘。

use agent_memory::{CAP_PROJECT_MEMORY, CAP_USER_MEMORY};

use crate::{assert_cap_err, text_of_chars, TempDir};

#[test]
fn user_memory_accepts_exact_cap_and_rejects_over_cap_without_partial_write() {
    let dir = TempDir::new("user-cap");
    let engine = dir.engine(true);
    let file = dir.user_memory();

    // 恰好等于上限 ⇒ 通过（边界含等号，规格 §1）。
    let exact = text_of_chars(CAP_USER_MEMORY);
    engine
        .set_user_memory(&exact)
        .expect("恰好等于上限必须通过");
    assert_eq!(dir.read(&file).chars().count(), CAP_USER_MEMORY);

    // 已有内容在先，再试超限 ⇒ Err 且旧正文分毫未变（禁止部分写入）。
    let err = engine
        .set_user_memory(&text_of_chars(CAP_USER_MEMORY + 1))
        .expect_err("超限必须拒绝");
    assert_cap_err(err, CAP_USER_MEMORY, CAP_USER_MEMORY + 1);
    assert_eq!(dir.read(&file), exact, "超限时已有文件被部分写入");
}

#[test]
fn project_memory_accepts_exact_cap_and_rejects_one_char_over() {
    let dir = TempDir::new("project-cap");
    let engine = dir.engine(true);
    let file = dir.project_memory();
    let exact = text_of_chars(CAP_PROJECT_MEMORY);

    engine
        .set_project_memory(&exact)
        .expect("恰好等于上限必须通过");
    assert_eq!(dir.read(&file).chars().count(), CAP_PROJECT_MEMORY);

    let err = engine
        .set_project_memory(&text_of_chars(CAP_PROJECT_MEMORY + 1))
        .expect_err("超限必须拒绝");
    assert_cap_err(err, CAP_PROJECT_MEMORY, CAP_PROJECT_MEMORY + 1);
    // 容量校验先于落盘：正文仍是上一次的全量写入。
    assert_eq!(dir.read(&file), exact);
}

#[test]
fn rejected_write_on_fresh_path_leaves_no_file_at_all() {
    // 全新路径 + 超限 ⇒ 连父目录都不该出现（校验先于 create_dir_all）。
    let dir = TempDir::new("no-partial-file");
    let engine = dir.engine(true);
    assert!(engine
        .set_user_memory(&text_of_chars(CAP_USER_MEMORY + 1))
        .is_err());
    assert!(!dir.exists(&dir.user_memory()));
    assert!(!dir.exists(&dir.paths().home.join("memory")));
    assert!(engine
        .set_project_memory(&text_of_chars(CAP_PROJECT_MEMORY + 1))
        .is_err());
    assert!(!dir.exists(&dir.project_memory()));
}

#[test]
fn capacity_counts_characters_not_bytes() {
    // 规格 §3：字符计数按 chars().count()。3 字节/字符的中文在字节数远超上限时仍应通过。
    let dir = TempDir::new("chars-not-bytes");
    let engine = dir.engine(true);
    let exact = text_of_chars(CAP_USER_MEMORY);
    assert!(
        exact.len() > CAP_USER_MEMORY,
        "前置条件：字节数应超过字符上限"
    );
    engine.set_user_memory(&exact).expect("按字符计数必须通过");
}
