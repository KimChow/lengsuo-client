//! 路径逃逸与 symlink 安全（fail-closed，规格 §5.6）。

use std::fs;

use agent_memory::MemoryPaths;

use crate::{assert_ensure_escapes, TempDir, TODAY};

#[cfg(unix)]
use crate::assert_all_paths_escape;

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
