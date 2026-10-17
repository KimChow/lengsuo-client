//! 越界防护验收：记忆三层的 symlink / 真实路径边界（MEMORY-SPEC §2）。
//!
//! 对齐 `daily_tests.rs` 已确立的语义：当日日志三条路径先词法、再按真实路径复核，
//! 逃逸即 `PathEscape` 且**不触盘**。本文件把同一边界核到用户记忆层、项目记忆层与
//! 身份层的写/删/读上（`engine.rs` / `paths.rs`），并确认「根目录自身是 symlink」这一
//! 合法摆放不被误拦（daily.rs 已记录的局限：根的真实路径即为授权根）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use agent_memory::{Identity, MemoryEngine, MemoryError, MemoryPaths, CAP_SOUL};

/// 测试专用假凭据（非真实值；用于确认拒绝发生在落盘前）。
const SOUL_TEXT: &str = "先复现，再动手。";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lengsuo-agent-memory-guard-{pid}-{id}-{tag}",
            pid = std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("临时目录可创建");
        Self { path }
    }

    fn paths(&self) -> MemoryPaths {
        MemoryPaths::new(self.path.join("home"), self.path.join("ws"))
    }

    fn engine(&self, enabled: bool) -> MemoryEngine {
        MemoryEngine::new(self.paths(), enabled)
    }

    fn outside(&self) -> PathBuf {
        self.path.join("outside")
    }

    /// `dir` 内实体名（排序后），用于断言「外部目录未被写入任何东西」。
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn assert_escape(res: Result<(), MemoryError>, scene: &str) {
    assert!(
        matches!(res, Err(MemoryError::PathEscape)),
        "{scene}：必须 PathEscape，实际 {res:?}"
    );
}

// ------------------------------------------------------------------ 正常摆放回归

#[test]
fn guarded_layers_still_write_at_canonical_layout() {
    // 加固不得改变正常摆放：三层 + 身份都能写、能读回。
    let dir = TempDir::new("canonical-layout");
    let engine = dir.engine(true);
    engine.set_user_memory("用户记忆正文").unwrap();
    engine.set_project_memory("项目记忆正文").unwrap();
    engine.set_soul(SOUL_TEXT).unwrap();
    engine.set_ai_name("小索").unwrap();

    let bundle = engine.compose().unwrap();
    assert_eq!(bundle.user_memory.as_deref(), Some("用户记忆正文"));
    assert_eq!(bundle.project_memory.as_deref(), Some("项目记忆正文"));
    assert_eq!(
        bundle.identity,
        Identity {
            ai_name: "小索".into(),
            user_name: agent_memory::DEFAULT_USER_NAME.into(),
            soul: SOUL_TEXT.into(),
        }
    );
    // 落点仍是规格 §1 的固定布局。
    assert!(dir.paths().user_memory_file().is_file());
    assert!(dir.paths().project_memory_file().is_file());
}

#[test]
fn cap_check_still_precedes_any_disk_touch() {
    // 开关放行 → 越界校验 → 容量校验 → 落盘：全新路径超限时连父目录都不出现。
    let dir = TempDir::new("cap-before-disk");
    let engine = dir.engine(true);
    let over = "记".repeat(CAP_SOUL + 1);
    assert!(matches!(
        engine.set_soul(&over),
        Err(MemoryError::CapExceeded { .. })
    ));
    assert!(!dir.paths().identity_dir().exists());
}

// ------------------------------------------------------------------ symlink 逃逸

/// 项目层：`<workspace>/.lengsuo/memory` 是指向外部的 symlink ⇒ 写与删都必须拒绝。
#[cfg(unix)]
#[test]
fn project_memory_write_and_clear_reject_escaped_symlink() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("project-escape");
    let outside = dir.outside();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(dir.paths().project_memory_dir().parent().unwrap()).unwrap();
    symlink(&outside, dir.paths().project_memory_dir()).expect("建立 symlink");

    let engine = dir.engine(true);
    assert_escape(
        engine.set_project_memory("经逃逸路径写"),
        "项目记忆写穿透 symlink",
    );
    assert!(
        TempDir::entries(&outside).is_empty(),
        "拒绝必须发生在落盘前，外部目录保持空：{:?}",
        TempDir::entries(&outside)
    );
    assert!(engine.compose().is_err(), "读侧同样不得经逃逸 symlink 注入");
    assert_escape(engine.clear_project_memory(), "项目记忆清除穿透 symlink");
}

/// 项目层：symlink 指向外部**文件** ⇒ 清除不得删掉 workspace 外的既有文件。
#[cfg(unix)]
#[test]
fn project_memory_clear_does_not_delete_file_outside_workspace() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("project-escape-file");
    let outside = dir.outside();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(dir.paths().project_memory_dir()).unwrap();
    let victim = outside.join("MEMORY.md");
    fs::write(&victim, "外部既有文件").unwrap();
    symlink(&victim, dir.paths().project_memory_file()).expect("建立 symlink");

    let engine = dir.engine(true);
    assert_escape(engine.clear_project_memory(), "项目记忆删外部文件");
    assert!(victim.is_file(), "越权删除必须被拦下，外部文件仍在");
    assert!(
        engine.compose().is_err(),
        "读侧必须 fail-closed 而非读到外部内容"
    );
}

/// 用户层：`<home>/memory` 逃逸 ⇒ 写拒绝、不触盘，读侧不注入外部内容。
#[cfg(unix)]
#[test]
fn user_memory_rejects_escaped_symlink() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("user-escape");
    let outside = dir.outside();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(dir.paths().home).unwrap();
    symlink(&outside, dir.paths().home.join("memory")).expect("建立 symlink");

    let engine = dir.engine(true);
    assert_escape(engine.set_user_memory("经逃逸路径写"), "用户记忆写");
    assert!(
        TempDir::entries(&outside).is_empty(),
        "外部目录必须保持空：{:?}",
        TempDir::entries(&outside)
    );
    assert_escape(engine.clear_user_memory(), "用户记忆清除");
    assert!(engine.compose().is_err(), "读侧必须 fail-closed");
}

/// 身份层：`<home>/identity` 逃逸 ⇒ SOUL/名字写入都拒绝且不触盘。
#[cfg(unix)]
#[test]
fn identity_writes_reject_escaped_symlink() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("identity-escape");
    let outside = dir.outside();
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(dir.paths().home).unwrap();
    symlink(&outside, dir.paths().identity_dir()).expect("建立 symlink");

    let engine = dir.engine(true);
    assert_escape(engine.set_soul(SOUL_TEXT), "SOUL 写");
    assert_escape(engine.set_ai_name("小索"), "AI 名写");
    assert_escape(engine.set_user_name("阿澜"), "用户名写");
    assert!(
        TempDir::entries(&outside).is_empty(),
        "拒绝必须发生在落盘前：{:?}",
        TempDir::entries(&outside)
    );
}

/// 悬空 symlink（落点尚不存在）⇒ 落点不可确认即拒绝，`create_dir_all` 不得穿透建目录。
#[cfg(unix)]
#[test]
fn dangling_symlink_is_rejected_before_dir_creation() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("dangling");
    let ghost = dir.path.join("not-yet-created");
    fs::create_dir_all(dir.paths().project_memory_dir().parent().unwrap()).unwrap();
    symlink(&ghost, dir.paths().project_memory_dir()).expect("建立悬空 symlink");

    let engine = dir.engine(true);
    assert_escape(
        engine.set_project_memory("任意正文"),
        "悬空 symlink 落点不可确认",
    );
    assert!(!ghost.exists(), "拒绝后不得在 symlink 目标处建出任何东西");
}

/// 合法摆放：授权根**自身**是 symlink（dotfile 外置管理）⇒ 仍可在其真实路径内读写。
#[cfg(unix)]
#[test]
fn symlinked_authorised_root_is_still_accepted() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("root-symlink");
    let real_home = dir.path.join("real-home");
    fs::create_dir_all(&real_home).unwrap();
    symlink(&real_home, dir.paths().home).expect("home 根为 symlink");

    let engine = dir.engine(true);
    engine
        .set_user_memory("根为 symlink 时的正文")
        .expect("授权根自身的 symlink 不得误拦");
    assert_eq!(
        fs::read_to_string(real_home.join("memory").join("MEMORY.md")).unwrap(),
        "根为 symlink 时的正文"
    );
    assert_eq!(
        engine.compose().unwrap().user_memory.as_deref(),
        Some("根为 symlink 时的正文")
    );
}
