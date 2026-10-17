use lengsuo_browser_installer::*;
fn plan() -> ArchivePlan {
    ArchivePlan::new(Limits {
        entries: 4,
        total_bytes: 12,
        entry_bytes: 8,
    })
    .unwrap()
}
#[test]
fn normal_and_windows_collisions() {
    let mut p = plan();
    assert_eq!(p.register("bin/", EntryKind::Directory, 0).unwrap(), "bin");
    p.register("bin/chrome.exe", EntryKind::File, 4).unwrap();
    assert!(p.register("BIN/CHROME.EXE", EntryKind::File, 1).is_err());
    assert!(p
        .register("bin/chrome.exe/child", EntryKind::File, 1)
        .is_err());
}
#[test]
fn reject_paths() {
    for name in [
        "",
        "/root",
        "../x",
        "a/../b",
        "a/./b",
        "a//b",
        "C:/x",
        "a\\b",
        "//host/share",
        "file:ads",
        "CON",
        "con.txt",
        "aux.dat",
        "COM1.txt",
        "LPT9",
        "a.",
        "a ",
        "é",
        "a\n",
    ] {
        assert!(plan().register(name, EntryKind::File, 1).is_err(), "{name}");
    }
    assert!(plan()
        .register(&"a".repeat(241), EntryKind::File, 1)
        .is_err());
}
#[test]
fn kinds_and_budgets() {
    let mut p = plan();
    assert!(p.register("link", EntryKind::Symlink, 0).is_err());
    assert!(p.register("dir", EntryKind::Directory, 1).is_err());
    assert!(p.register("large", EntryKind::File, 9).is_err());
    p.register("a", EntryKind::File, 8).unwrap();
    assert!(p.register("b", EntryKind::File, 5).is_err());
    p.register("c", EntryKind::File, 4).unwrap();
    assert!(p.register("overflow", EntryKind::File, 1).is_err());
}
#[test]
fn count_and_prefix() {
    let mut p = plan();
    p.register("a/b", EntryKind::File, 0).unwrap();
    assert!(p.register("a", EntryKind::File, 0).is_err());
    for n in ["x", "y", "z"] {
        p.register(n, EntryKind::File, 0).unwrap();
    }
    assert!(p.register("w", EntryKind::File, 0).is_err());
}
#[test]
fn invalid_limits() {
    for limits in [
        Limits {
            entries: 0,
            total_bytes: 1,
            entry_bytes: 1,
        },
        Limits {
            entries: 1,
            total_bytes: 0,
            entry_bytes: 1,
        },
        Limits {
            entries: 1,
            total_bytes: 1,
            entry_bytes: 2,
        },
    ] {
        assert!(ArchivePlan::new(limits).is_err());
    }
}
