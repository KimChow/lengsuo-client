//! §5.5 身份：缺省名、空名拒绝、SOUL 容量位。

use agent_memory::{MemoryError, CAP_SOUL};

use crate::{default_identity, text_of_chars, TempDir};

#[test]
fn identity_defaults_apply_when_files_absent_and_read_back_after_write() {
    let dir = TempDir::new("identity-defaults");
    let engine = dir.engine(true);

    assert_eq!(engine.read_identity().unwrap(), default_identity());

    engine.set_user_name("阿澜").unwrap();
    engine.set_ai_name("小索").unwrap();
    let read = engine.read_identity().unwrap();
    assert_eq!(
        (read.user_name.as_str(), read.ai_name.as_str()),
        ("阿澜", "小索")
    );
    assert_eq!(read.soul, "", "未写 SOUL 时不得凭空填充");

    // 覆写语义：再次 set 生效，不追加、不残留旧值。
    engine.set_ai_name("小澜").unwrap();
    assert_eq!(engine.read_identity().unwrap().ai_name, "小澜");
}

#[test]
fn empty_and_whitespace_only_names_are_rejected_and_not_written() {
    let dir = TempDir::new("empty-name");
    let engine = dir.engine(true);

    assert!(matches!(
        engine.set_user_name("   "),
        Err(MemoryError::EmptyName)
    ));
    assert!(matches!(
        engine.set_ai_name(""),
        Err(MemoryError::EmptyName)
    ));
    assert!(
        !dir.exists(&dir.identity_dir().join("USER.md")),
        "被拒绝的空名仍落了盘"
    );
    assert!(
        !dir.exists(&dir.identity_dir().join("AI_NAME")),
        "被拒绝的空名仍落了盘"
    );
    // 被拒后仍回落缺省名，不产生半写入的身份文件。
    assert_eq!(engine.read_identity().unwrap(), default_identity());
}

#[test]
fn oversized_soul_is_rejected_with_cap_numbers() {
    // §5.5「超长拒绝」走已冻结的 SOUL 容量位（规格 §1：SOUL ≤8000 字符）。
    let dir = TempDir::new("soul-cap");
    let engine = dir.engine(true);
    let soul = dir.identity_dir().join("SOUL.md");

    engine
        .set_soul(&text_of_chars(CAP_SOUL))
        .expect("恰好等于上限必须通过");
    let err = engine
        .set_soul(&text_of_chars(CAP_SOUL + 1))
        .expect_err("超限必须拒绝");
    assert!(
        matches!(err, MemoryError::CapExceeded { cap, len } if cap == CAP_SOUL && len == CAP_SOUL + 1),
        "错误变体/数值不符：{err:?}"
    );
    assert_eq!(dir.read(&soul).chars().count(), CAP_SOUL);
}
