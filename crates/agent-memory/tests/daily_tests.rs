//! 卡 B 测试：当日日志与路径安全（规格 §5 第 4/6/7/8/9 组）。
//!
//! 只覆盖 `daily.rs` 的自由函数 API；`compose` 层面的三层聚合断言在卡 A 的
//! `engine_tests.rs`，本文件不依赖它（并行开发，互不阻塞）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use agent_memory::{
    append_daily, clear_daily, read_daily_tail, MemoryError, MemoryPaths, NaiveDate, CAP_DAILY_LINE,
};

/// const 构造日期：测试内固定「当日」，不依赖真实时钟。
const fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("无效测试日期")
}

/// 固定「当日」，避免测试受真实时钟影响。
const TODAY: NaiveDate = ymd(2026, 10, 16);
const TOMORROW: NaiveDate = ymd(2026, 10, 17);
const OTHER_DAY: NaiveDate = ymd(2026, 10, 18);

/// 极简临时目录（不新增 tempfile 依赖，保持本 crate `--locked` 依赖面不变）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lengsuo-agent-memory-{}-{id}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("临时目录可创建");
        Self { path }
    }

    fn workspace(&self) -> PathBuf {
        self.path.join("ws")
    }

    fn paths(&self) -> MemoryPaths {
        MemoryPaths::new(self.path.join("home"), self.workspace())
    }

    fn daily_file(&self, d: NaiveDate) -> PathBuf {
        self.paths().daily_file(d)
    }

    fn memory_dir(&self) -> PathBuf {
        self.workspace().join(".lengsuo").join("memory")
    }

    /// 当日文件的原始字节内容（断言落盘形态，含换行）。
    fn raw(&self, d: NaiveDate) -> String {
        fs::read_to_string(self.daily_file(d)).unwrap()
    }

    /// 尾部读取（unwrap 到 Result 外层，None 表示文件缺失）。
    fn tail(&self, d: NaiveDate, max_lines: usize) -> Option<String> {
        read_daily_tail(&self.paths(), d, max_lines).unwrap()
    }

    fn write_raw(&self, d: NaiveDate, content: &str) {
        fs::create_dir_all(self.memory_dir()).unwrap();
        fs::write(self.daily_file(d), content).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // 只读场景若中途 panic，权限可能还锁着；先放开再删，避免 /tmp 残留。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [self.memory_dir(), self.workspace()] {
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// 逃逸场景统一断言：写 / 读 / 删三条入口都必须是 `PathEscape`（不留后门入口）。
#[cfg(unix)]
fn assert_all_paths_escape(tmp: &TempDir, scene: &str) {
    let results = [
        append_daily(&tmp.paths(), TODAY, "经逃逸路径写").map(|_| ()),
        read_daily_tail(&tmp.paths(), TODAY, 10).map(|_| ()),
        clear_daily(&tmp.paths(), TODAY),
    ];
    for result in results {
        assert!(
            matches!(result, Err(MemoryError::PathEscape)),
            "{scene}：读写删必须全部拒绝: {result:?}"
        );
    }
}

/// `ensure_within` 必须判为越界。
fn assert_ensure_escapes(base: &Path, candidate: &Path, scene: &str) {
    let result = MemoryPaths::ensure_within(base, candidate);
    assert!(
        matches!(result, Err(MemoryError::PathEscape)),
        "{scene}: {result:?}"
    );
}

/// §5.4：自动建目录/文件、追加不覆盖、两次追加顺序保持（append 自动补换行）。
#[test]
fn append_daily_creates_dirs_and_appends_in_order() {
    let tmp = TempDir::new("append-order");
    assert!(!tmp.daily_file(TODAY).exists(), "前置：当日文件不存在");

    append_daily(&tmp.paths(), TODAY, "第一行摘要").expect("首次追加应成功");
    assert!(
        tmp.memory_dir().is_dir(),
        "应自动创建 <workspace>/.lengsuo/memory"
    );
    assert_eq!(tmp.raw(TODAY), "第一行摘要\n");

    append_daily(&tmp.paths(), TODAY, "第二行摘要").expect("二次追加应成功");
    let content = tmp.raw(TODAY);
    assert_eq!(content, "第一行摘要\n第二行摘要\n", "追加不得覆盖既有内容");
    assert_eq!(
        content.lines().collect::<Vec<_>>(),
        ["第一行摘要", "第二行摘要"],
        "顺序须与写入顺序一致"
    );
}

/// §5.4：日期隔离——不同 date 落不同文件；未写的日期读为 None（只读「当日」文件）。
#[test]
fn append_daily_isolates_by_date() {
    let tmp = TempDir::new("append-date");

    append_daily(&tmp.paths(), TODAY, "今天的日志").unwrap();
    append_daily(&tmp.paths(), TOMORROW, "明天的日志").unwrap();

    assert_eq!(tmp.raw(TODAY), "今天的日志\n");
    assert_eq!(tmp.raw(TOMORROW), "明天的日志\n");
    assert_eq!(tmp.tail(TODAY, 10).unwrap(), "今天的日志");
    assert_eq!(tmp.tail(TOMORROW, 10).unwrap(), "明天的日志");
    assert_eq!(tmp.tail(OTHER_DAY, 10), None, "未写过的日期 ⇒ None");
}

/// §3：read_daily_tail 只取尾部 ≤max_lines 行并保持原行序。
#[test]
fn read_daily_tail_returns_last_lines_in_order() {
    let tmp = TempDir::new("tail-order");
    for i in 1..=5 {
        append_daily(&tmp.paths(), TODAY, &format!("行 {i}")).unwrap();
    }

    assert_eq!(tmp.tail(TODAY, 2).unwrap(), "行 4\n行 5");
    assert_eq!(
        tmp.tail(TODAY, 99).unwrap(),
        "行 1\n行 2\n行 3\n行 4\n行 5",
        "max_lines 超行数 ⇒ 全文"
    );
    assert_eq!(tmp.tail(TODAY, 0).unwrap(), "", "max_lines=0 ⇒ 空文本");

    // 用户可直接改文件（规格 §1）：无结尾换行时仍取满尾部行。
    tmp.write_raw(TODAY, "a\nb\nc");
    assert_eq!(tmp.tail(TODAY, 2).unwrap(), "b\nc");
}

/// §3 边界：CRLF 行的行终止符按 `lines()` 语义处理；存在但为空的文件 ⇒ Some("")（非 None）。
#[test]
fn read_daily_tail_handles_crlf_and_empty_file() {
    let tmp = TempDir::new("tail-edge");
    tmp.write_raw(TODAY, "甲\r\n乙\r\n丙\r\n");
    assert_eq!(
        tmp.tail(TODAY, 2).unwrap().lines().collect::<Vec<_>>(),
        ["乙", "丙"],
        "CRLF 仍按两行尾部读取"
    );

    // 空文件 ≠ 缺失文件：路径存在即返回 Some（缺失才是 None，规格 §3）。
    tmp.write_raw(TODAY, "");
    assert_eq!(tmp.tail(TODAY, 200), Some(String::new()));
}

/// §5.7：clear_daily 删除后读取变 None；不存在视为成功（幂等）；不误删其他日期。
#[test]
fn clear_daily_makes_tail_none_and_is_idempotent() {
    let tmp = TempDir::new("clear");
    append_daily(&tmp.paths(), TODAY, "待清除").unwrap();
    append_daily(&tmp.paths(), TOMORROW, "另一天").unwrap();
    assert!(tmp.tail(TODAY, 10).is_some());

    clear_daily(&tmp.paths(), TODAY).expect("删除应成功");
    assert!(!tmp.daily_file(TODAY).exists());
    assert_eq!(tmp.tail(TODAY, 10), None, "§5.7：删除后对应层为 None");
    assert!(tmp.tail(TOMORROW, 10).is_some(), "其他日期不受影响");

    clear_daily(&tmp.paths(), TODAY).expect("文件不存在视为成功");
    clear_daily(&tmp.paths(), OTHER_DAY).expect("目录也不存在时同样视为已清空");
}

/// §5.6：`..` 词法穿越拒绝（PathEscape）；边界内合法；同名前缀兄弟目录不算「在内」。
#[test]
fn path_traversal_with_dotdot_is_rejected() {
    let tmp = TempDir::new("escape-lexical");
    fs::create_dir_all(tmp.memory_dir()).unwrap();
    let ws = tmp.workspace();

    let escape = ws.join(".lengsuo/memory/../../../../etc/lengsuo.md");
    assert_ensure_escapes(&ws, &escape, "`..` 词法越界必须拒绝");

    let inside = ws.join(".lengsuo/memory/2026-10-16.md");
    MemoryPaths::ensure_within(&ws, &inside).expect("workspace 内合法路径不得误拒");

    // `/ws-evil/…` 与 `/ws` 字符串前缀相同，但不是同一父路径组件 ⇒ 必须拒。
    let sibling = ws.parent().unwrap().join("ws-evil/.lengsuo/memory/x.md");
    assert_ensure_escapes(
        &ws,
        &sibling,
        "字符串前缀相同不构成授权（校验按路径组件，不按字节前缀）",
    );

    // 反例：`join` 追加组件，`/ws/-evil/…` 确实在 workspace 内 ⇒ 不得误拒。
    MemoryPaths::ensure_within(&ws, &ws.join("-evil/x.md")).expect("workspace 内子目录不得误拒");

    // 日期是 chrono 强类型，`{date}.md` 无法携带 `..`；文件名保持规范形态。
    assert_eq!(
        tmp.daily_file(TODAY).file_name().unwrap().to_string_lossy(),
        "2026-10-16.md"
    );
}

/// §5.6 加固：`.lengsuo` 换成指向 workspace 外的 symlink ⇒ 三条路径均 PathEscape，且不触盘。
#[cfg(unix)]
#[test]
fn symlink_escaping_workspace_is_rejected() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new("escape-symlink");
    let outside = tmp.path.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(tmp.workspace()).unwrap();
    symlink(&outside, tmp.workspace().join(".lengsuo")).expect("建立 symlink");

    assert_all_paths_escape(&tmp, ".lengsuo symlink 逃逸");
    assert_eq!(
        fs::read_dir(&outside).unwrap().count(),
        0,
        "拒绝须发生在落盘前，外部目录保持空"
    );
}

/// §5.6 加固：悬空 symlink（指向尚不存在的外部路径）同样拒绝——否则 create_dir_all
/// 会穿透它在外层建目录；落点无法确认即 fail-closed。
#[cfg(unix)]
#[test]
fn dangling_symlink_is_rejected_fail_closed() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new("escape-dangling");
    let ghost = tmp.path.join("not-yet-created");
    fs::create_dir_all(tmp.workspace()).unwrap();
    symlink(&ghost, tmp.workspace().join(".lengsuo")).expect("建立悬空 symlink");

    assert_all_paths_escape(&tmp, "悬空 symlink 落点不可确认");
    assert!(!ghost.exists(), "拒绝后不得在 symlink 目标处建出任何东西");
}

/// §5.6 加固：当日日志文件本身是指向外部的 symlink ⇒ 不越权读、不越权删。
#[cfg(unix)]
#[test]
fn daily_file_symlink_to_outside_is_not_touched() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new("escape-file-symlink");
    let outside = tmp.path.join("outside.md");
    fs::write(&outside, "不该被读到的内容").unwrap();
    fs::create_dir_all(tmp.memory_dir()).unwrap();
    symlink(&outside, tmp.daily_file(TODAY)).expect("建立 symlink");

    assert_all_paths_escape(&tmp, "当日文件 symlink 指向外部");
    assert!(outside.exists(), "越权删除必须被拦下，外部文件仍在");
}

/// §5.8 容量侧：超限 ⇒ CapExceeded 且不留下部分写入；恰好等于上限放行。
#[test]
fn over_cap_append_writes_nothing() {
    let tmp = TempDir::new("cap");
    let too_long = "超".repeat(CAP_DAILY_LINE + 1);
    match append_daily(&tmp.paths(), TODAY, &too_long) {
        Err(MemoryError::CapExceeded { cap, len }) => {
            assert_eq!(cap, CAP_DAILY_LINE);
            assert_eq!(len, CAP_DAILY_LINE + 1, "计数按字符，不按字节");
        }
        other => panic!("应为 CapExceeded，实际 {other:?}"),
    }
    assert!(
        !tmp.daily_file(TODAY).exists(),
        "超限不得留下文件（无部分写入）"
    );

    append_daily(&tmp.paths(), TODAY, &"超".repeat(CAP_DAILY_LINE)).expect("恰好等于上限应放行");
    assert_eq!(
        tmp.raw(TODAY).chars().count(),
        CAP_DAILY_LINE + 1,
        "含自动补的换行"
    );
}

/// §5.8 失败面：写入路径不可写 ⇒ `Io` 显式上抛，不 panic、不静默降级。
///
/// 部分环境（root / ACL 豁免）对 0o500 目录仍可写；此时探测后跳过，不误报红。
#[cfg(unix)]
#[test]
fn read_only_directory_surfaces_io_error() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new("read-only");
    fs::create_dir_all(tmp.memory_dir()).unwrap();
    let memory_dir = tmp.memory_dir();
    fs::set_permissions(&memory_dir, fs::Permissions::from_mode(0o500)).unwrap();

    let blocked = append_daily(&tmp.paths(), TODAY, "只读目录写入");
    if blocked.is_ok() {
        // 权限未能拦下（uid 0 等）：还原权限后跳过断言，避免依赖环境的假失败。
        eprintln!("跳过 §5.8 只读断言：当前环境可写 0o500 目录");
        let _ = fs::set_permissions(&memory_dir, fs::Permissions::from_mode(0o700));
        return;
    }

    match blocked {
        Err(MemoryError::Io { path, source }) => {
            assert!(!path.as_os_str().is_empty(), "Io 错误必须带路径");
            assert!(
                !format!("{source}").contains("只读目录"),
                "错误不得泄漏记忆内容"
            );
        }
        other => panic!("只读目录应为 Io，实际 {other:?}"),
    }

    // 读取与清除同一目录也不得 panic，失败面只能是 Io。
    let read = read_daily_tail(&tmp.paths(), TODAY, 10);
    assert!(
        matches!(read, Ok(_) | Err(MemoryError::Io { .. })),
        "读取: {read:?}"
    );
    let cleared = clear_daily(&tmp.paths(), OTHER_DAY);
    assert!(
        matches!(cleared, Ok(()) | Err(MemoryError::Io { .. })),
        "清除: {cleared:?}"
    );
    let _ = fs::set_permissions(&memory_dir, fs::Permissions::from_mode(0o700));
}

/// 写入被拒（不依赖权限，root 下同样生效）：目标路径被同名目录占据。
///
/// 与上面的 0o500 用例同一失败面契约：被拒必须显式上抛 `Io`，不 panic、
/// 不静默降级、不返回 Ok 谎报已落盘；错误只带路径与 OS 原因，不泄漏记忆内容。
#[test]
fn write_denied_by_existing_directory_surfaces_io_error() {
    let tmp = TempDir::new("denied");
    fs::create_dir_all(tmp.memory_dir()).unwrap();
    // 期望是文件的位置放一个目录 ⇒ open(Append|Create) 必然 EISDIR。
    fs::create_dir_all(tmp.daily_file(TODAY)).unwrap();

    let blocked = append_daily(&tmp.paths(), TODAY, "不该落盘的内容");
    match blocked {
        Err(MemoryError::Io { path, source }) => {
            assert_eq!(path, tmp.daily_file(TODAY), "Io 错误必须指向被拒的路径");
            assert!(
                !format!("{source}").contains("不该落盘"),
                "错误不得泄漏记忆内容"
            );
        }
        Ok(()) => panic!("被拒的写入不得谎报成功"),
        Err(other) => panic!("被拒写入应为 Io，实际 {other:?}"),
    }
    // 被拒后不得留下半截文件；占据路径的仍是那个目录。
    assert!(fs::metadata(tmp.daily_file(TODAY))
        .map(|m| m.is_dir())
        .unwrap_or(false));
}

/// workspace 尚未创建（合法路径、无逃逸）⇒ 自动补齐整条目录链。
#[test]
fn append_creates_missing_workspace_chain() {
    let tmp = TempDir::new("missing-ws");
    let paths = tmp.paths();
    assert!(!Path::new(&paths.workspace).exists());
    append_daily(&paths, TODAY, "首次会话写入").expect("应自动补齐 workspace 链");
    assert!(tmp.daily_file(TODAY).exists());
}

/// §5.9 性能锚：1000 行日志取尾部 200 行 < 10ms。
///
/// 规格明写「标注不强制 CI」：测量与打印始终执行，阈值断言只在非 CI 下生效，
/// 避免慢盘/负载抖动把基线卡成随机红。
#[test]
fn perf_anchor_tail_of_1000_lines_under_10ms() {
    let tmp = TempDir::new("perf");
    let mut blob = String::with_capacity(110 * 1000);
    for i in 1..=1000 {
        blob.push_str(&format!("第 {i} 行日志摘要内容\n"));
    }
    tmp.write_raw(TODAY, &blob);

    let mut best = u128::MAX;
    for _ in 0..5 {
        let started = Instant::now();
        let tail = tmp.tail(TODAY, 200).unwrap();
        best = best.min(started.elapsed().as_micros());
        assert_eq!(tail.lines().count(), 200, "必须正好取到尾部 200 行");
        assert_eq!(tail.lines().next().unwrap(), "第 801 行日志摘要内容");
        assert_eq!(tail.lines().last().unwrap(), "第 1000 行日志摘要内容");
    }
    let budget = std::time::Duration::from_millis(10).as_micros();
    println!("1000 行日志 tail(200) 最快一次: {best} µs（预算 {budget} µs）");
    if std::env::var_os("CI").is_none() {
        assert!(best < budget, "§5.9 性能锚：{best} µs 超过 10ms 预算");
    } else {
        println!("CI 环境：性能锚仅打印不断言（规格 §5.9）");
    }
}
