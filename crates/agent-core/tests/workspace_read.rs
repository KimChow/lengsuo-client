//! 授权工作区有界文本读取（R06-1 / PC06 §2）的行为测试。
//!
//! 覆盖：正常读取、恰好达上限、`../` 逃逸、绝对外部路径、指向外部的 symlink、
//! 超限整体失败（不部分返回）、无效 UTF-8 拒绝、0 字节上限拒绝。

use std::fs;
use std::io::ErrorKind;

use agent_core::workspace_read::read_workspace_file;

#[cfg(unix)]
use std::os::unix::fs::symlink;

fn write(path: &std::path::Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

#[test]
fn reads_text_file_inside_workspace() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    write(&root_path.join("notes.md"), "# hello 你好\n".as_bytes());

    let text = read_workspace_file(&root_path, "notes.md", 4096).unwrap();
    assert_eq!(text, "# hello 你好\n");
}

#[test]
fn reads_nested_path_and_absolute_inner_path() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    write(&root_path.join("src").join("main.rs"), b"fn main() {}\n");

    assert_eq!(
        read_workspace_file(&root_path, "src/main.rs", 4096).unwrap(),
        "fn main() {}\n"
    );
    let abs = root_path.join("src").join("main.rs");
    assert_eq!(
        read_workspace_file(&root_path, &abs, 4096).unwrap(),
        "fn main() {}\n"
    );
}

#[test]
fn accepts_exact_limit_and_rejects_one_byte_more() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    write(&root_path.join("a.txt"), b"12345");

    assert_eq!(
        read_workspace_file(&root_path, "a.txt", 5).unwrap(),
        "12345"
    );

    let err = read_workspace_file(&root_path, "a.txt", 4).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
    // 超限必须整体失败：调用方拿不到任何部分内容（Result::Err 已保证）。
    assert!(format!("{err}").contains("4"));
}

#[test]
fn rejects_parent_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let outer = dir.path().join("outer");
    fs::create_dir_all(&outer).unwrap();
    let root = outer.join("ws");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    write(&outer.canonicalize().unwrap().join("secret.txt"), b"secret");

    let err = read_workspace_file(&root, "../secret.txt", 4096).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");

    fs::create_dir_all(root.join("inner")).unwrap();
    let err = read_workspace_file(&root, "inner/../../secret.txt", 4096).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
}

#[test]
fn rejects_absolute_path_outside_root() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let outside = std::env::temp_dir().join("workspace_read_outside_file.txt");
    write(&outside, b"outside");

    let err = read_workspace_file(&root_path, &outside, 4096).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
    fs::remove_file(&outside).ok();
}

#[test]
fn rejects_root_itself_and_missing_file() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();

    // 目录不是文本文件。
    let err = read_workspace_file(&root_path, ".", 4096).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");

    let err = read_workspace_file(&root_path, "nope.txt", 4096).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound, "{err}");
}

#[cfg(unix)]
#[test]
fn rejects_symlink_pointing_outside_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let root = base.join("ws");
    fs::create_dir_all(&root).unwrap();
    write(&base.join("secret.txt"), b"secret");
    symlink(base.join("secret.txt"), root.join("link.txt")).unwrap();

    let err = read_workspace_file(&root, "link.txt", 4096).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
}

#[cfg(unix)]
#[test]
fn allows_symlink_inside_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let root = base.join("ws");
    fs::create_dir_all(root.join("inner")).unwrap();
    write(&root.join("inner").join("real.txt"), b"inside\n");
    symlink(root.join("inner").join("real.txt"), root.join("link.txt")).unwrap();

    assert_eq!(
        read_workspace_file(&root, "link.txt", 4096).unwrap(),
        "inside\n"
    );
}

#[test]
fn rejects_invalid_utf8() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    write(&root_path.join("bin.txt"), &[0xF0, 0x28, 0x8C, 0x28]);

    let err = read_workspace_file(&root_path, "bin.txt", 4096).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData, "{err}");
}

#[test]
fn rejects_zero_max_bytes() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    write(&root_path.join("empty.txt"), b"");

    let err = read_workspace_file(&root_path, "empty.txt", 0).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
}

#[test]
fn reads_empty_file() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    write(&root_path.join("empty.txt"), b"");

    assert_eq!(
        read_workspace_file(&root_path, "empty.txt", 10).unwrap(),
        ""
    );
}
