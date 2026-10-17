//! `file:list / makeDir / read / readChunked`：分页边界、大小上限、编码失败。

use std::fs;

use agent_tools::{FsToolbox, ToolError, MAX_SINGLE_READ_BYTES};

mod support;

use support::Sandbox;

#[test]
fn list_dir_排序分页并回报总数() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    for name in ["b.txt", "a.txt", "c.txt"] {
        sb.put(&format!("list_sort/{name}"), "x");
    }
    fs::create_dir_all(sb.ws("list_sort/zdir")).unwrap();

    let (page, total) = tb.list_dir("list_sort", 0, 2).unwrap();
    assert_eq!(total, 4, "总数应含目录");
    assert_eq!(
        page.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        vec!["a.txt", "b.txt"]
    );
    assert!(!page[0].is_dir);
    assert_eq!(page[0].rel_path, "list_sort/a.txt");
    assert_eq!(page[0].size, 1);

    let (page2, total2) = tb.list_dir("list_sort", 2, 2).unwrap();
    assert_eq!(total2, 4);
    assert_eq!(
        page2.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        vec!["c.txt", "zdir"]
    );
    assert!(page2[1].is_dir);
}

#[test]
fn list_dir_分页边界() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    for i in 0..3 {
        sb.put(&format!("page/{i}.txt"), "x");
    }
    // offset 越界：空页但总数不变。
    let (page, total) = tb.list_dir("page", 10, 5).unwrap();
    assert!(page.is_empty());
    assert_eq!(total, 3);
    // limit 为 0：空页但总数不变。
    let (page, total) = tb.list_dir("page", 0, 0).unwrap();
    assert!(page.is_empty());
    assert_eq!(total, 3);
    // limit 大于总数：全部返回。
    let (page, total) = tb.list_dir("page", 0, 100).unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(total, 3);
    // 空目录。
    fs::create_dir_all(sb.ws("empty")).unwrap();
    let (page, total) = tb.list_dir("empty", 0, 10).unwrap();
    assert!(page.is_empty());
    assert_eq!(total, 0);
}

#[test]
fn list_dir_对文件报错_对缺失报错() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    sb.put("notdir.txt", "x");
    assert!(matches!(
        tb.list_dir("notdir.txt", 0, 10).unwrap_err(),
        ToolError::NotADirectory(ref p) if *p == sb.ws("notdir.txt")
    ));
    assert!(matches!(
        tb.list_dir("missing", 0, 10).unwrap_err(),
        ToolError::NotFound(_)
    ));
}

#[test]
fn make_dir_幂等且递归() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    tb.make_dir("deep/a/b/c").unwrap();
    assert!(sb.ws("deep/a/b/c").is_dir());
    // 幂等：重复创建同一目录不报错。
    tb.make_dir("deep/a/b/c").unwrap();
    assert!(sb.ws("deep/a/b/c").is_dir());
    // 已存在的文件同名 ⇒ AlreadyExists。
    sb.put("conflict.txt", "x");
    assert!(matches!(
        tb.make_dir("conflict.txt").unwrap_err(),
        ToolError::AlreadyExists(ref p) if *p == sb.ws("conflict.txt")
    ));
    // 越界 ⇒ Denied。
    assert!(matches!(
        tb.make_dir("../evil").unwrap_err(),
        ToolError::Denied(_)
    ));
}

#[test]
fn read_整读成功并记录已读() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    sb.put("hello.txt", "line1\nline2\n");
    assert_eq!(tb.read("hello.txt", 4096).unwrap(), "line1\nline2\n");
    assert!(matches!(
        tb.read("missing.txt", 4096).unwrap_err(),
        ToolError::NotFound(_)
    ));
}

#[test]
fn read_超限返回toolarge_与8mb上限取小() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    sb.put("big.txt", &"x".repeat(1000));

    // 调用方上限更小 ⇒ 用调用方上限。
    let err = tb.read("big.txt", 512).unwrap_err();
    assert!(
        matches!(err, ToolError::TooLarge { ref path, ref limit } if *limit == 512 && *path == sb.ws("big.txt")),
        "期望 TooLarge(limit=512)，实际 {err:?}"
    );
    // 调用方上限超过 8 MiB ⇒ 实际生效 8 MiB。
    sb.put(
        "huge.txt",
        &"y".repeat((MAX_SINGLE_READ_BYTES as usize) + 8),
    );
    let err = tb.read("huge.txt", u64::MAX).unwrap_err();
    assert!(
        matches!(err, ToolError::TooLarge { limit, .. } if limit == MAX_SINGLE_READ_BYTES),
        "期望 TooLarge(limit=8MiB)，实际 {err:?}"
    );
    // 恰好等于上限 ⇒ 允许。
    assert_eq!(tb.read("big.txt", 1000).unwrap().len(), 1000);
}

#[test]
fn read_非utf8返回io错误() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    fs::write(sb.ws("binary.bin"), [0xFFu8, 0xFE, 0x00, 0x41]).unwrap();
    let err = tb.read("binary.bin", 4096).unwrap_err();
    match err {
        ToolError::Io { path, source } => {
            assert_eq!(path, sb.ws("binary.bin"));
            assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
        }
        other => panic!("期望 Io(InvalidData)，实际 {other:?}"),
    }
}

#[test]
fn read_目录报错为io_isadirectory() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    fs::create_dir_all(sb.ws("adir")).unwrap();
    let err = tb.read("adir", 4096).unwrap_err();
    match err {
        ToolError::Io { source, .. } => {
            assert_eq!(source.kind(), std::io::ErrorKind::IsADirectory);
        }
        other => panic!("期望 Io(IsADirectory)，实际 {other:?}"),
    }
}

#[test]
fn read_chunked_按行对齐并报告has_more() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    sb.put("lines.txt", "a\nb\nc\nd\ne");

    let (chunk, more) = tb.read_chunked("lines.txt", 0, 2).unwrap();
    assert_eq!(chunk, vec!["a".to_string(), "b".to_string()]);
    assert!(more);

    let (chunk, more) = tb.read_chunked("lines.txt", 2, 2).unwrap();
    assert_eq!(chunk, vec!["c".to_string(), "d".to_string()]);
    assert!(more);

    let (chunk, more) = tb.read_chunked("lines.txt", 4, 5).unwrap();
    assert_eq!(chunk, vec!["e".to_string()]);
    assert!(!more, "已到末尾 has_more 必须为 false");

    // 首页即全量。
    let (chunk, more) = tb.read_chunked("lines.txt", 0, 100).unwrap();
    assert_eq!(chunk.len(), 5);
    assert!(!more);
}

#[test]
fn read_chunked_空文件与越界起始行() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    sb.put("empty.txt", "");
    let (chunk, more) = tb.read_chunked("empty.txt", 0, 10).unwrap();
    assert!(chunk.is_empty());
    assert!(!more);

    sb.put("one.txt", "only");
    let (chunk, more) = tb.read_chunked("one.txt", 99, 10).unwrap();
    assert!(chunk.is_empty());
    assert!(!more, "起始行越界不算还有更多");

    // max_lines 为 0：空块但如实报告还有更多。
    let (chunk, more) = tb.read_chunked("one.txt", 0, 0).unwrap();
    assert!(chunk.is_empty());
    assert!(more);

    assert!(matches!(
        tb.read_chunked("missing.txt", 0, 1).unwrap_err(),
        ToolError::NotFound(_)
    ));
}

#[test]
fn read_chunked_尾随换行不产生空行() {
    let sb = Sandbox::new();
    let tb = FsToolbox::new(&sb.workspace);
    sb.put("trailing.txt", "a\nb\n");
    let (chunk, more) = tb.read_chunked("trailing.txt", 0, 10).unwrap();
    assert_eq!(chunk, vec!["a".to_string(), "b".to_string()]);
    assert!(!more);
}
