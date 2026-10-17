//! 安全闸与 `file:exists / info` 通道：穿越、绝对路径逃逸与元信息。

use std::fs;
use std::path::Path;

use agent_tools::{FsToolbox, ToolError};

mod support;

use support::Sandbox;

#[test]
fn guard_拒绝相对穿越_公开api返回denied() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    for evil in [
        "../escape.txt",
        "a/../../escape.txt",
        "./../escape.txt",
        "inside/../outside.txt",
    ] {
        let err = tb.read(evil, 1024).unwrap_err();
        assert!(
            matches!(err, ToolError::Denied(ref p) if *p == Path::new(evil)),
            "期望 Denied({evil:?})，实际 {err:?}"
        );
        assert!(!tb.exists(evil), "越界路径 exists 必须为 false");
    }
}

#[test]
fn guard_拒绝工作区外绝对路径() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    let outside = sb.outside.join("secret.txt");
    fs::write(&outside, b"do-not-read").unwrap();
    let abs_str = outside.to_str().unwrap();
    assert!(matches!(
        tb.read(abs_str, 1024).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.get_info(abs_str).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.list_dir(abs_str, 0, 10).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.write(abs_str, "pwned", false).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.make_dir(abs_str).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.remove(abs_str).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.rename("a.txt", abs_str).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.search(abs_str, "*", 10).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(matches!(
        tb.glob(abs_str, "*", 10).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert_eq!(fs::read_to_string(&outside).unwrap(), "do-not-read");
}

#[test]
fn guard_接受工作区内绝对路径与点段() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    fs::write(sb.workspace.join("ok.txt"), b"content").unwrap();
    let abs_str = sb.workspace.join("ok.txt").to_str().unwrap().to_string();
    assert_eq!(tb.read(&abs_str, 1024).unwrap(), "content");
    assert!(tb.exists("./ok.txt"));
    // 词法策略：任何 `..` 成分一律拒绝，即使字面上仍在工作区内。
    assert!(matches!(
        tb.read("./sub/../ok.txt", 1024).unwrap_err(),
        ToolError::Denied(_)
    ));
    assert!(!tb.exists("./sub/../ok.txt"));
}

#[test]
fn exists_区分存在缺失与目录() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    fs::write(sb.workspace.join("f.txt"), b"x").unwrap();
    fs::create_dir(sb.workspace.join("d")).unwrap();
    assert!(tb.exists("f.txt"));
    assert!(tb.exists("d"));
    assert!(tb.exists("."));
    // 空串与工作区自身等价（均指向工作区根）。
    assert!(tb.exists(""));
    assert!(!tb.exists("missing.txt"));
}

#[test]
fn get_info_返回大小目录标记与修改时间() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    fs::write(sb.workspace.join("f.txt"), b"12345").unwrap();
    fs::create_dir(sb.workspace.join("d")).unwrap();

    let info = tb.get_info("f.txt").unwrap();
    assert_eq!(info.size, 5);
    assert!(!info.is_dir);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(
        info.modified_ms > 0 && info.modified_ms <= now_ms + 2_000,
        "modified_ms={} 应接近当前时间 {now_ms}",
        info.modified_ms
    );

    let dir_info = tb.get_info("d").unwrap();
    assert!(dir_info.is_dir);
}

#[test]
fn get_info_缺失路径返回notfound() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    let err = tb.get_info("nope.txt").unwrap_err();
    assert!(
        matches!(err, ToolError::NotFound(ref p) if *p == sb.workspace.join("nope.txt")),
        "期望 NotFound，实际 {err:?}"
    );
}
