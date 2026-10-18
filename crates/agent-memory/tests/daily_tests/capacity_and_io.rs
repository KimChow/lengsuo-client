//! 容量上限与 IO 错误面（超限零写入、只读目录/同名目录占据均显式上抛，规格 §5.8）。

use std::fs;

use agent_memory::{append_daily, clear_daily, read_daily_tail, MemoryError, CAP_DAILY_LINE};

use crate::{TempDir, OTHER_DAY, TODAY};

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
