//! 卡 A 测试：记忆引擎核心（规格 §5 第 1/2/3/5 组 + §2 删除能力）。
//!
//! 只覆盖 `engine.rs` 的 `MemoryEngine` API；`daily.rs` 的追加/尾部/清除/路径安全
//! 在卡 B 的 `daily_tests.rs`（并行开发，本文件仅通过 compose 间接使用当日日志读取）。
//!
//! 时间口径：compose 的「当日」取本地时钟（规格 §1/§3），故涉及日志的用例先取
//! `today()` 再写入同一日期，不在断言里二次读时钟（跨零点才可能漂移，毫秒内不成立）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use agent_memory::{
    append_daily, Identity, MemoryBundle, MemoryEngine, MemoryError, MemoryPaths, NaiveDate,
    CAP_PROJECT_MEMORY, CAP_SOUL, CAP_USER_MEMORY, DEFAULT_AI_NAME, DEFAULT_USER_NAME,
};

/// 本地「今日」——与 compose 内部同一口径。
fn today() -> NaiveDate {
    chrono::Local::now().date_naive()
}

/// `d` 往前 `days` 天（用于「非当日不注入」断言）。
fn days_before(d: NaiveDate, days: u64) -> NaiveDate {
    d.checked_sub_days(chrono::Days::new(days))
        .expect("测试日期有效")
}

/// 极简临时目录（不新增 tempfile 依赖：本 crate `Cargo.toml` 冻结，`--locked` 依赖面不变）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lengsuo-agent-memory-engine-{pid}-{id}-{tag}",
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

    fn user_memory(&self) -> PathBuf {
        self.paths().user_memory_file()
    }

    fn project_memory(&self) -> PathBuf {
        self.paths().project_memory_file()
    }

    fn identity_dir(&self) -> PathBuf {
        self.paths().identity_dir()
    }

    /// 直接落盘（绕过写路径，构造「盘上已有内容」的前置状态）。
    fn put(&self, path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read(&self, path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn default_identity() -> Identity {
    Identity {
        ai_name: DEFAULT_AI_NAME.into(),
        user_name: DEFAULT_USER_NAME.into(),
        soul: String::new(),
    }
}

/// 指定字符数的正文（3 字节/字符，可同时暴露「按字节计数」的错误实现）。
fn text_of_chars(len: usize) -> String {
    "记".repeat(len)
}

/// 断言错误为 `CapExceeded { cap, len }`（变体与两个数值一并核对，失败时打印实际值）。
fn assert_cap_err(err: MemoryError, cap: usize, len: usize) {
    assert!(
        matches!(err, MemoryError::CapExceeded { cap: c, len: l } if c == cap && l == len),
        "期望 CapExceeded{{cap={cap}, len={len}}}，实际 {err:?}"
    );
}

/// 断言 `Result` 为 `Err(MemoryError::Disabled)`。
fn assert_disabled(res: Result<(), MemoryError>, label: &str) {
    assert!(
        matches!(res, Err(MemoryError::Disabled)),
        "{label} 关闭时未返回 Disabled：{res:?}"
    );
}

// ---------------------------------------------------------------- §5.1 compose

#[test]
fn compose_on_empty_dir_returns_default_identity_and_no_layers() {
    // 目录完全不存在（既无身份文件也无记忆文件）：缺失 = 空内容，不是错误（规格 §1）。
    let dir = TempDir::new("empty");
    let bundle = dir.engine(true).compose().expect("空目录不得报错");

    assert_eq!(
        bundle.identity,
        default_identity(),
        "身份缺省名未按规格填充"
    );
    assert_eq!(bundle.user_memory, None);
    assert_eq!(bundle.project_memory, None);
    assert_eq!(bundle.daily_tail, None);
}

#[test]
fn compose_with_all_layers_present_fills_every_field() {
    let dir = TempDir::new("all-layers");
    let paths = dir.paths();
    let day = today();

    dir.put(
        &dir.identity_dir().join("SOUL.md"),
        "冷静、克制、先复现再动手",
    );
    dir.put(&dir.identity_dir().join("USER.md"), "  阿澜 \n"); // 读取时 trim
    dir.put(&dir.identity_dir().join("AI_NAME"), "小索");
    dir.put(&dir.user_memory(), "偏好：中文回复；不碰危险命令。\n");
    dir.put(&dir.project_memory(), "本仓 Rust 网络面；无 unsafe。\n");
    append_daily(&paths, day, "完成分层实现").expect("当日日志写入");

    let bundle = dir.engine(true).compose().expect("compose 失败");

    assert_eq!(
        bundle.identity,
        Identity {
            ai_name: "小索".into(),
            user_name: "阿澜".into(),
            soul: "冷静、克制、先复现再动手".into(),
        },
        "身份层未从文件填充（或 trim 语义不符）"
    );
    assert_eq!(
        bundle.user_memory.as_deref(),
        Some("偏好：中文回复；不碰危险命令。\n")
    );
    assert_eq!(
        bundle.project_memory.as_deref(),
        Some("本仓 Rust 网络面；无 unsafe。\n")
    );
    assert_eq!(bundle.daily_tail.as_deref(), Some("完成分层实现"));
}

#[test]
fn compose_does_not_inject_a_non_today_daily_file() {
    // 规格 §3：daily_tail 只取当日文件；昨日日志存在也必须是 None。
    let dir = TempDir::new("not-today");
    let paths = dir.paths();
    let stale = days_before(today(), 1);
    append_daily(&paths, stale, "昨天的日志").expect("昨日日志写入");

    let bundle = dir.engine(true).compose().expect("compose 失败");
    assert_eq!(bundle.daily_tail, None, "非当日日志被注入");
}

#[test]
fn compose_distinguishes_missing_layer_from_empty_layer() {
    // 缺失 ⇒ None（不注入）；存在但为空 ⇒ Some("")（这一层确实在，只是正文为空）。
    let dir = TempDir::new("missing-vs-empty");
    let engine = dir.engine(true);
    assert_eq!(engine.compose().unwrap().user_memory, None);

    dir.put(&dir.user_memory(), "");
    let bundle = engine.compose().expect("compose 失败");
    assert_eq!(bundle.user_memory.as_deref(), Some(""));
    assert_eq!(bundle.project_memory, None);
}

#[test]
fn compose_fails_closed_when_a_layer_is_unreadable() {
    // fail-closed：单层 IO 失败 ⇒ 整体 Err 上抛，不 panic、不静默降级成 None（规格 §3）。
    let dir = TempDir::new("unreadable-layer");
    let engine = dir.engine(true);
    // 把用户记忆路径占成目录：read_to_string 必失败（Is a directory）。
    fs::create_dir_all(dir.user_memory()).unwrap();

    let err = engine.compose().expect_err("目录占位必须上抛 IO 错误");
    match err {
        MemoryError::Io { path, .. } => assert_eq!(path, dir.user_memory()),
        other => panic!("期望 Io 变体，实际 {other:?}"),
    }
}

// ------------------------------------------------------------------ §5.2 开关

#[test]
fn disabled_engine_composes_identity_only() {
    // enabled=false：三层文件都在盘上也一律不注入（规格 §2 隐私默认）。
    let dir = TempDir::new("disabled-compose");
    let paths = dir.paths();
    dir.put(&dir.user_memory(), "不该出现的用户记忆");
    dir.put(&dir.project_memory(), "不该出现的项目记忆");
    append_daily(&paths, today(), "不该出现的日志").unwrap();

    let bundle: MemoryBundle = dir
        .engine(false)
        .compose()
        .expect("disabled compose 不得报错");
    assert_eq!(bundle.identity, default_identity());
    assert_eq!(bundle.user_memory, None);
    assert_eq!(bundle.project_memory, None);
    assert_eq!(bundle.daily_tail, None);
    assert!(!dir.engine(false).enabled(), "enabled() 与实际开关不符");
}

#[test]
fn disabled_engine_rejects_memory_writes_without_touching_disk() {
    let dir = TempDir::new("disabled-write");
    let engine = dir.engine(false);

    let user = engine.set_user_memory("任意正文");
    let project = engine.set_project_memory("任意正文");
    assert_disabled(user, "set_user_memory");
    assert_disabled(project, "set_project_memory");
    // 闸门先于落盘：既不建文件，也不建父目录。
    assert!(!dir.exists(&dir.user_memory()), "关闭时用户记忆文件被创建");
    assert!(
        !dir.exists(&dir.paths().home.join("memory")),
        "关闭时用户记忆目录被创建"
    );
    assert!(
        !dir.exists(&dir.project_memory()),
        "关闭时项目记忆文件被创建"
    );
}

#[test]
fn identity_reads_and_writes_ignore_the_memory_switch() {
    // 规格 §2：身份层是产品人格，不受跨会话记忆开关限制。
    let dir = TempDir::new("identity-unaffected");
    let engine = dir.engine(false);

    engine.set_soul("先复现，再动手；不猜。").unwrap();
    engine.set_ai_name("小索").unwrap();
    engine.set_user_name("阿澜").unwrap();

    assert_eq!(
        engine.read_identity().unwrap(),
        Identity {
            ai_name: "小索".into(),
            user_name: "阿澜".into(),
            soul: "先复现，再动手；不猜。".into(),
        },
        "disabled 状态下身份读写不一致"
    );
    // compose 的身份层同样填充（开关只压制记忆三层）。
    let bundle = engine.compose().unwrap();
    assert_eq!(bundle.identity.ai_name, "小索");
    assert_eq!(bundle.identity.soul, "先复现，再动手；不猜。");
}

// ------------------------------------------------------------------ §5.3 容量

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

// ------------------------------------------------------------------ §5.5 身份

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

// -------------------------------------------------- §2 删除能力（compose 回归）

#[test]
fn clearing_memory_layers_makes_compose_return_none_again() {
    // 规格 §2：提供查看与删除能力；删除后对应层在 compose 中变回 None。
    let dir = TempDir::new("clear");
    let engine = dir.engine(true);
    engine.set_user_memory("用户记忆正文").unwrap();
    engine.set_project_memory("项目记忆正文").unwrap();
    assert!(engine.compose().unwrap().user_memory.is_some());
    assert!(engine.compose().unwrap().project_memory.is_some());

    engine.clear_user_memory().unwrap();
    engine.clear_project_memory().unwrap();
    let bundle = engine.compose().unwrap();
    assert_eq!(bundle.user_memory, None);
    assert_eq!(bundle.project_memory, None);
    assert!(!dir.exists(&dir.user_memory()));
    assert!(!dir.exists(&dir.project_memory()));

    // 幂等：再删一次仍是 Ok（不存在视为已清空）。
    engine.clear_user_memory().unwrap();
    engine.clear_project_memory().unwrap();
}

#[test]
fn clearing_works_even_when_memory_is_disabled() {
    // 隐私优先于开关字面语义：跨会话记忆关掉之后，历史残留仍必须能删。
    let dir = TempDir::new("clear-disabled");
    dir.engine(true).set_user_memory("待清除").unwrap();

    let off = dir.engine(false);
    off.clear_user_memory().unwrap();
    assert!(!dir.exists(&dir.user_memory()));
    assert_eq!(off.compose().unwrap().user_memory, None);
}
