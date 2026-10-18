//! `file:search / glob`：文件名 glob 限量搜索 + 总数，路径模式含 `**` 递归。

use std::fs;

use agent_tools::{FsToolbox, ToolError};

mod support;

use support::Sandbox;

fn fixture(sb: &Sandbox) -> FsToolbox {
    let tb = FsToolbox::new(&sb.workspace);
    sb.put("search/root-a.rs", "x");
    sb.put("search/root-b.txt", "x");
    sb.put("search/nested/inner-a.rs", "xx");
    sb.put("search/nested/deep/deeper-a.rs", "xxx");
    sb.put("search/.hidden.rs", "x");
    fs::create_dir_all(sb.ws("search/nested/dirname")).unwrap();
    tb
}

#[test]
fn search_按文件名递归匹配并回报总数() {
    let sb = Sandbox::new();
    let tb = fixture(&sb);

    let (hits, total) = tb.search("search", "*.rs", 10).unwrap();
    assert_eq!(total, 4, "四个 .rs 文件（含隐藏文件所在目录不计入）");
    assert_eq!(
        hits.iter().map(|h| h.rel_path.as_str()).collect::<Vec<_>>(),
        vec![
            "search/.hidden.rs",
            "search/nested/deep/deeper-a.rs",
            "search/nested/inner-a.rs",
            "search/root-a.rs"
        ]
    );
    assert!(!hits[0].is_dir);
    assert_eq!(hits[3].size, 1);
}

#[test]
fn search_limit截断但总数不变() {
    let sb = Sandbox::new();
    let tb = fixture(&sb);

    let (hits, total) = tb.search("search", "*.rs", 2).unwrap();
    assert_eq!(hits.len(), 2, "limit 生效");
    assert_eq!(total, 4, "总数必须是全量");

    // limit 0 ⇒ 只回报总数。
    let (hits, total) = tb.search("search", "*.rs", 0).unwrap();
    assert!(hits.is_empty());
    assert_eq!(total, 4);

    // 无命中。
    let (hits, total) = tb.search("search", "*.zzz", 10).unwrap();
    assert!(hits.is_empty());
    assert_eq!(total, 0);
}

#[test]
fn search_模式与目录条目也可命中() {
    let sb = Sandbox::new();
    let tb = fixture(&sb);

    let (hits, total) = tb.search("search", "dirname", 10).unwrap();
    assert_eq!(total, 1);
    assert!(hits[0].is_dir, "目录名参与文件名匹配");

    // 前缀通配。
    let (_, total) = tb.search("search", "*-a.rs", 10).unwrap();
    assert_eq!(total, 3, "root-a/inner-a/deeper-a");
    // ? 单字符。
    let (hits, total) = tb.search("search", "root-?.txt", 10).unwrap();
    assert_eq!(total, 1);
    assert_eq!(hits[0].name, "root-b.txt");
}

#[test]
fn search_错误路径_非法模式_非目录_越界() {
    let sb = Sandbox::new();
    let tb = fixture(&sb);

    assert!(
        matches!(
            tb.search("search", "[a", 10).unwrap_err(),
            ToolError::Io { .. }
        ),
        "非法 glob 模式必须报错而非静默"
    );
    assert!(matches!(
        tb.search("search/root-a.rs", "*", 10).unwrap_err(),
        ToolError::NotADirectory(_)
    ));
    assert!(matches!(
        tb.search("search/ghost", "*", 10).unwrap_err(),
        ToolError::NotFound(_)
    ));
    assert!(matches!(
        tb.search("../", "*", 10).unwrap_err(),
        ToolError::Denied(_)
    ));
}

#[test]
fn glob_路径模式支持递归与单层差异() {
    let sb = Sandbox::new();
    let tb = fixture(&sb);

    // `**` 跨目录。
    let all = tb.glob("search", "**/*.rs", 100).unwrap();
    assert_eq!(
        all,
        vec![
            "search/.hidden.rs".to_string(),
            "search/nested/deep/deeper-a.rs".to_string(),
            "search/nested/inner-a.rs".to_string(),
            "search/root-a.rs".to_string()
        ]
    );

    // 单层 `*` 不跨分隔符：只命中 search 直属文件（点开头文件照常参与，与 search 一致）。
    let shallow = tb.glob("search", "*.rs", 100).unwrap();
    assert_eq!(
        shallow,
        vec![
            "search/.hidden.rs".to_string(),
            "search/root-a.rs".to_string()
        ]
    );

    // 指定层级。
    let two = tb.glob("search", "nested/*.rs", 100).unwrap();
    assert_eq!(two, vec!["search/nested/inner-a.rs".to_string()]);

    // 根为工作区自身时返回相对工作区路径。
    let from_root = tb.glob(".", "search/**/*.txt", 100).unwrap();
    assert_eq!(from_root, vec!["search/root-b.txt".to_string()]);
}

#[test]
fn glob_limit截断且结果稳定排序() {
    let sb = Sandbox::new();
    let tb = fixture(&sb);

    let two = tb.glob("search", "**/*.rs", 2).unwrap();
    assert_eq!(two.len(), 2);
    let mut expect: Vec<String> = vec![
        "search/.hidden.rs".to_string(),
        "search/nested/deep/deeper-a.rs".to_string(),
        "search/nested/inner-a.rs".to_string(),
        "search/root-a.rs".to_string(),
    ];
    expect.sort();
    assert_eq!(two, expect[..2], "返回必须是排序后的前 N 条");

    // 无命中 ⇒ 空列表。
    assert!(tb.glob("search", "**/*.zzz", 10).unwrap().is_empty());
    // 错误路径。
    assert!(matches!(
        tb.glob("search", "[a", 10).unwrap_err(),
        ToolError::Io { .. }
    ));
    assert!(matches!(
        tb.glob("search/ghost", "*", 10).unwrap_err(),
        ToolError::NotFound(_)
    ));
    assert!(matches!(
        tb.glob("../etc", "*", 10).unwrap_err(),
        ToolError::Denied(_)
    ));
}
