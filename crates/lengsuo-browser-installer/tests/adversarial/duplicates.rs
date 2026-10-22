// ---- 重复声明：前缀冲突、大小写折叠重复、目录项必须零字节 ----

// ---------------------------------------------------------------------------
// 2. Prefix collisions: `a` vs `a/b` in BOTH declaration orders.
// ---------------------------------------------------------------------------

#[test]
fn prefix_collision_declared_both_orders() {
    // Order 1: file `a` first, nested `a/b` second.
    let mut p = plan(8, 1_024, 512);
    assert_eq!(p.register("a", EntryKind::File, 1).unwrap(), "a");
    assert_eq!(
        p.register("a/b", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "file `a` cannot gain a child `a/b`: declared prefix collision"
    );

    // Order 2: nested `a/b` first, parent `a` second.
    let mut q = plan(8, 1_024, 512);
    assert_eq!(q.register("a/b", EntryKind::File, 1).unwrap(), "a/b");
    assert_eq!(
        q.register("a", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "declaring the parent `a` after `a/b` is the same collision, other order"
    );

    // One level deeper, both orders.
    let mut r = plan(8, 1_024, 512);
    assert_eq!(r.register("x/y", EntryKind::File, 1).unwrap(), "x/y");
    assert_eq!(
        r.register("x/y/z", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "`x/y` as a file blocks any path below it"
    );
    let mut s = plan(8, 1_024, 512);
    assert_eq!(s.register("x/y/z", EntryKind::File, 1).unwrap(), "x/y/z");
    assert_eq!(
        s.register("x/y", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "re-declaring an ancestor of a file is a collision, opposite order"
    );

    // Directory/file mix on one and the same path name, both orders.
    let mut t = plan(8, 1_024, 512);
    assert_eq!(
        t.register("logs/", EntryKind::Directory, 0).unwrap(),
        "logs"
    );
    assert_eq!(
        t.register("logs", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "directory `logs/` then file `logs` declares one path twice"
    );
    assert!(
        t.register("logs/run.txt", EntryKind::File, 1).is_ok(),
        "`logs/` declared as a directory must allow content below it"
    );
    let mut u = plan(8, 1_024, 512);
    assert_eq!(u.register("logs", EntryKind::File, 1).unwrap(), "logs");
    assert_eq!(
        u.register("logs/", EntryKind::Directory, 0),
        Err(ArchiveError::Collision),
        "file `logs` then directory `logs/` declares one path twice"
    );

    // A sibling sharing only letters is NOT a component prefix.
    let mut v = plan(8, 1_024, 512);
    assert_eq!(v.register("app", EntryKind::File, 1).unwrap(), "app");
    assert_eq!(
        v.register("apple", EntryKind::File, 1).unwrap(),
        "apple",
        "`apple` only shares letters with `app`; component prefixes need a `/`"
    );
    assert_eq!(
        v.register("app/b", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "`app/b` is a true component prefix of file `app`"
    );
}

// ---------------------------------------------------------------------------
// 3. Case-insensitive duplicates (Windows semantics).
// ---------------------------------------------------------------------------

#[test]
fn case_insensitive_duplicates_rejected_both_orders() {
    let mut p = plan(8, 1_024, 512);
    assert_eq!(p.register("A", EntryKind::File, 1).unwrap(), "A");
    assert_eq!(
        p.register("a", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "Windows treats `A` and `a` as one path"
    );

    // Opposite declaration order, plus a duplicate crossing the kind boundary.
    let mut q = plan(8, 1_024, 512);
    assert_eq!(q.register("a", EntryKind::File, 1).unwrap(), "a");
    assert_eq!(
        q.register("A", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "`A` after `a` is the same case-folded duplicate"
    );
    assert_eq!(
        q.register("A/", EntryKind::Directory, 0),
        Err(ArchiveError::Collision),
        "case-folded duplicate collides even as a directory entry"
    );

    // Nested mixed case: several foldings of one declared path.
    let mut r = plan(8, 1_024, 512);
    assert_eq!(
        r.register("Bin/Chrome.exe", EntryKind::File, 1).unwrap(),
        "Bin/Chrome.exe"
    );
    for dup in ["bin/chrome.exe", "BIN/CHROME.EXE", "bIn/ChRoMe.Exe"] {
        assert_eq!(
            r.register(dup, EntryKind::File, 1),
            Err(ArchiveError::Collision),
            "{dup:?} is a case-folded duplicate of `Bin/Chrome.exe`"
        );
    }
    assert_eq!(
        r.register("BIN/CHROME.EXE/child", EntryKind::File, 1),
        Err(ArchiveError::Collision),
        "case-folded prefix nesting is still a prefix collision"
    );
    assert_eq!(
        r.register("bin/chrome-x", EntryKind::File, 1).unwrap(),
        "bin/chrome-x",
        "`chrome-x` differs from `chrome.exe` even case-folded"
    );
}

// ---------------------------------------------------------------------------
// 4. Directory entries must carry size 0.
// ---------------------------------------------------------------------------

#[test]
fn directory_entries_must_carry_zero_size() {
    // entry_bytes 8: sizes 1..=8 are inside every byte budget, so the only
    // reason to refuse `tools/` is the declared directory-size-must-be-zero
    // rule. Size 9 exceeds the per-entry cap and must be refused too.
    for size in [1u64, 2, 7, 8] {
        let mut p = plan(8, 1_024, 8);
        let outcome = p.register("tools/", EntryKind::Directory, size);
        assert!(
            outcome.is_err(),
            "a directory claiming {size} bytes (inside the byte budgets) must be refused, got {outcome:?}"
        );
        // Nothing may have been recorded or charged: the same path with
        // size 0 still registers cleanly.
        assert_eq!(
            p.register("tools/", EntryKind::Directory, 0).unwrap(),
            "tools",
            "the refused size-{size} directory must have left the plan untouched"
        );
    }
    let mut p = plan(8, 1_024, 8);
    assert!(
        p.register("deep/", EntryKind::Directory, 9).is_err(),
        "a directory over the per-entry byte cap must be refused"
    );
    assert_eq!(
        p.register("deep/", EntryKind::Directory, 0).unwrap(),
        "deep",
        "the refused directory must have left the plan untouched"
    );
}
