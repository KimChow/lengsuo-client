//! `parse_skill_md` 行为测试：有/无 front-matter、超限、坏 name、body 非空。

use std::fs;
use std::path::Path;

use agent_skills::{parse_skill_md, SkillsError};
use tempfile::TempDir;

/// 在临时目录下建一个技能子目录并写入 SKILL.md 内容。
fn make_skill(root: &Path, dir_name: &str, content: &str) -> std::path::PathBuf {
    let dir = root.join(dir_name);
    fs::create_dir_all(&dir).expect("创建技能目录");
    fs::write(dir.join("SKILL.md"), content).expect("写入 SKILL.md");
    dir
}

fn malformed_reason(err: SkillsError) -> String {
    match err {
        SkillsError::Malformed { reason, .. } => reason,
        other => panic!("期望 Malformed，实得 {other:?}"),
    }
}

#[test]
fn parses_front_matter_name_and_description() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "pdf-forms",
        "---\nname: pdf-forms\ndescription: 填写 PDF 表单\n---\n先打开文件。\n再保存。\n",
    );
    let skill = parse_skill_md(&dir).unwrap();
    assert_eq!(skill.name, "pdf-forms");
    assert_eq!(skill.description, "填写 PDF 表单");
    assert_eq!(skill.body, "先打开文件。\n再保存。");
    assert_eq!(skill.path, dir.join("SKILL.md"));
}

#[test]
fn front_matter_name_wins_over_dir_name() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "01-legacy-dir",
        "---\nname: commit-style\ndescription: 提交规范\n---\n正文\n",
    );
    let skill = parse_skill_md(&dir).unwrap();
    // 目录名非法也不影响：front-matter 为准。
    assert_eq!(skill.name, "commit-style");
    assert_eq!(skill.description, "提交规范");
    assert_eq!(skill.body, "正文");
}

#[test]
fn quoted_front_matter_values_are_unquoted() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "quoted",
        "---\nname: \"quoted\"\ndescription: '带 冒号: 的描述'\n---\n正文\n",
    );
    let skill = parse_skill_md(&dir).unwrap();
    assert_eq!(skill.name, "quoted");
    assert_eq!(skill.description, "带 冒号: 的描述");
}

#[test]
fn no_front_matter_falls_back_to_dir_name() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(tmp.path(), "plain-skill", "# 标题\n直接就是正文\n");
    let skill = parse_skill_md(&dir).unwrap();
    assert_eq!(skill.name, "plain-skill");
    assert_eq!(skill.description, "");
    assert_eq!(skill.body, "# 标题\n直接就是正文");
}

#[test]
fn front_matter_missing_name_is_malformed() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "no-name",
        "---\ndescription: 只有描述\n---\n正文\n",
    );
    let reason = malformed_reason(parse_skill_md(&dir).unwrap_err());
    assert!(reason.contains("name"), "原因应说明 name 缺失: {reason}");
}

#[test]
fn front_matter_missing_closing_delimiter_is_malformed() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(tmp.path(), "unclosed", "---\nname: unclosed\n没有收尾\n");
    let reason = malformed_reason(parse_skill_md(&dir).unwrap_err());
    assert!(
        reason.contains("front-matter"),
        "原因应指向 front-matter: {reason}"
    );
}

#[test]
fn bad_names_are_rejected() {
    let tmp = TempDir::new().unwrap();
    let cases: Vec<(String, String)> = [
        ("大写", "PDF-Forms".to_string()),
        ("下划线", "pdf_forms".to_string()),
        ("空", String::new()),
        ("点号", "pdf.forms".to_string()),
        ("斜杠", "a/b".to_string()),
        ("过长", "a".repeat(65)),
    ]
    .into_iter()
    .map(|(c, n)| (c.to_string(), n))
    .collect();
    for (case, name) in cases {
        let dir = make_skill(
            tmp.path(),
            "bad-name",
            &format!("---\nname: {name}\n---\n正文\n"),
        );
        let err = parse_skill_md(&dir).unwrap_err();
        assert!(
            matches!(err, SkillsError::Malformed { .. }),
            "{case} 应拒绝，实得 {err:?}"
        );
    }
}

#[test]
fn valid_name_charset_and_length_accepted() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(tmp.path(), "x", "---\nname: abc-x9-01z\n---\n正文\n");
    assert_eq!(parse_skill_md(&dir).unwrap().name, "abc-x9-01z");
    // 不做隐式小写归一：非法字符一律拒绝（见 bad_names_are_rejected）。

    let long = "a".repeat(64);
    let dir2 = make_skill(
        tmp.path(),
        "y",
        &format!("---\nname: {long}\ndescription: d\n---\n正文\n"),
    );
    assert_eq!(parse_skill_md(&dir2).unwrap().name, long);
}

#[test]
fn dir_name_is_not_normalized_and_invalid_dir_name_fails() {
    let tmp = TempDir::new().unwrap();
    // 目录名含大写：无 front-matter 时回退目录名，仍受 name 规则约束。
    let dir = make_skill(tmp.path(), "BadDir", "正文而已\n");
    let reason = malformed_reason(parse_skill_md(&dir).unwrap_err());
    assert!(reason.contains("name"), "原因应说明 name 非法: {reason}");
}

#[test]
fn empty_body_is_malformed() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "empty-body",
        "---\nname: empty-body\n---\n\n   \n",
    );
    let reason = malformed_reason(parse_skill_md(&dir).unwrap_err());
    assert!(reason.contains("正文"), "原因应说明正文为空: {reason}");

    let dir2 = make_skill(tmp.path(), "empty-plain", "");
    let reason2 = malformed_reason(parse_skill_md(&dir2).unwrap_err());
    assert!(reason2.contains("正文"), "原因应说明正文为空: {reason2}");
}

#[test]
fn size_limit_32kb_is_enforced() {
    let tmp = TempDir::new().unwrap();
    // 恰好 32 KiB（含 front-matter）允许。
    let front = "---\nname: big\n---\n";
    let pad_at_limit = 32 * 1024 - front.len();
    let dir = make_skill(
        tmp.path(),
        "big",
        &format!("{front}{}", "x".repeat(pad_at_limit)),
    );
    assert!(parse_skill_md(&dir).is_ok(), "恰好 32 KiB 应通过");

    let dir2 = make_skill(
        tmp.path(),
        "toobig",
        &format!("{front}{}", "x".repeat(pad_at_limit + 1)),
    );
    let reason = malformed_reason(parse_skill_md(&dir2).unwrap_err());
    assert!(reason.contains("32"), "原因应提到上限: {reason}");
}

#[test]
fn missing_file_is_not_found() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("absent");
    fs::create_dir_all(&dir).unwrap();
    let err = parse_skill_md(&dir).unwrap_err();
    assert!(matches!(err, SkillsError::NotFound), "实得 {err:?}");

    // 整个目录也不存在时同样是 NotFound。
    let err2 = parse_skill_md(&tmp.path().join("nope")).unwrap_err();
    assert!(matches!(err2, SkillsError::NotFound), "实得 {err2:?}");
}

#[test]
fn non_utf8_content_is_malformed_not_panic() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("binary");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("SKILL.md"), [0xff_u8, 0xfe, 0x00, 0x01]).unwrap();
    let reason = malformed_reason(parse_skill_md(&dir).unwrap_err());
    assert!(reason.contains("UTF-8"), "原因应说明编码: {reason}");
}

#[test]
fn unknown_front_matter_keys_and_comments_ignored() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "extra",
        "---\n# 注释行\nname: extra\nmodel: sonnet\ndescription: d\n---\n正文\n",
    );
    let skill = parse_skill_md(&dir).unwrap();
    assert_eq!(skill.name, "extra");
    assert_eq!(skill.description, "d");
}

#[test]
fn error_display_and_path_are_useful() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(tmp.path(), "bad", "正文\n");
    fs::write(dir.join("SKILL.md"), "---\nname: BAD NAME\n---\nx\n").unwrap();
    let err = parse_skill_md(&dir).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("SKILL.md"), "显示信息应含路径: {text}");
}

#[test]
fn crlf_line_endings_are_handled() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "crlf",
        "---\r\nname: crlf\r\ndescription: 跨平台\r\n---\r\n第一行\r\n第二行\r\n",
    );
    let skill = parse_skill_md(&dir).unwrap();
    assert_eq!(skill.name, "crlf");
    assert_eq!(skill.description, "跨平台");
    assert_eq!(skill.body, "第一行\r\n第二行");
}
