//! Adversarial expectations for `ArchivePlan` path-plan validation only.
//!
//! Every expected value below is written by hand or derived from the
//! *declared* boundaries (240-byte path limit, 32-component limit, Windows
//! reserved-device list, directory size 0, capacity budgets). The crate under
//! test is never used as an oracle. Real extraction/install is not
//! implemented and is not certified by this file.

use lengsuo_browser_installer::{ArchiveError, ArchivePlan, EntryKind, Limits};

/// Builds a plan from explicitly stated budgets so each test names its own
/// boundary expectations.
fn plan(entries: usize, total_bytes: u64, entry_bytes: u64) -> ArchivePlan {
    ArchivePlan::new(Limits {
        entries,
        total_bytes,
        entry_bytes,
    })
    .expect("limits are valid by construction")
}

fn lower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

// ---------------------------------------------------------------------------
// 1. Declared limits: 240-byte path, 32 components (exactly at / one over).
// ---------------------------------------------------------------------------

#[test]
fn path_byte_limit_exact_and_over() {
    // Budgets 8 entries / 1024 total / 512 per entry: a 1-byte file at any
    // legal length fits, so the only possible refusal is the 240-byte
    // declared path ceiling itself.
    let at_limit = "p".repeat(240);
    assert_eq!(
        at_limit.len(),
        240,
        "test premise: exactly at the declared path ceiling"
    );
    let mut p = plan(8, 1_024, 512);
    assert_eq!(
        p.register(&at_limit, EntryKind::File, 1).unwrap(),
        at_limit,
        "a 240-byte path is inside the declared ceiling and must be kept verbatim"
    );

    let over = "p".repeat(241);
    assert_eq!(over.len(), 241, "test premise: one byte over the ceiling");
    assert_eq!(
        p.register(&over, EntryKind::File, 1),
        Err(ArchiveError::InvalidPath),
        "241 bytes exceeds the declared 240-byte path limit"
    );
    // The refusal must not have consumed budget or a slot: another 240-byte
    // path still registers fine (2 entries of 1 byte against 8/1024).
    let second = "q".repeat(240);
    assert_eq!(
        p.register(&second, EntryKind::File, 1).unwrap(),
        second,
        "the rejected over-long path must not have consumed any budget"
    );
}

#[test]
fn component_count_limit_exact_and_over() {
    // 32 components of 3 bytes: 32*3 + 31 separators = 127 path bytes, well
    // under 240, so the only possible refusal is the 32-component ceiling.
    let parts: Vec<String> = (0..32u8).map(|i| format!("c{i:02}")).collect();
    let joined = parts.join("/");
    assert_eq!(parts.len(), 32, "test premise: exactly 32 components");
    assert_eq!(joined.len(), 127, "hand-computed: 32*3 + 31 = 127");
    let mut p = plan(8, 1_024, 512);
    assert_eq!(
        p.register(&joined, EntryKind::File, 1).unwrap(),
        joined,
        "32 components is exactly the declared ceiling and must be accepted"
    );

    let parts: Vec<String> = (0..33u8).map(|i| format!("c{i:02}")).collect();
    let joined = parts.join("/");
    assert_eq!(parts.len(), 33, "test premise: one component over");
    assert_eq!(joined.len(), 131, "hand-computed: 33*3 + 32 = 131");
    assert_eq!(
        p.register(&joined, EntryKind::File, 1),
        Err(ArchiveError::InvalidPath),
        "33 components exceeds the declared 32-component ceiling"
    );
}

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

// ---------------------------------------------------------------------------
// 5. Windows illegal characters and reserved device names.
// ---------------------------------------------------------------------------

#[test]
fn windows_reserved_device_names_rejected() {
    // Declared reserved set: CON, PRN, AUX, NUL, COM1..COM9, LPT1..LPT9;
    // case-insensitive; extension ignored; nested under a directory too.
    let mut rejected: Vec<String> = Vec::new();
    for base in ["CON", "PRN", "AUX", "NUL"] {
        rejected.push(base.to_string());
        rejected.push(lower(base));
        rejected.push(format!("{base}.txt"));
        rejected.push(format!("{}.dat", lower(base)));
    }
    for digit in '1'..='9' {
        for port in ["COM", "LPT"] {
            rejected.push(format!("{port}{digit}"));
            rejected.push(format!("{}{digit}", lower(port)));
            rejected.push(format!("{port}{digit}.log"));
        }
    }
    rejected.push("drivers/CON".into());
    rejected.push("Drivers/nul.dat".into());

    for name in &rejected {
        assert!(
            name.len() <= 240 && name.is_ascii(),
            "test premise: {name:?} must not be refus-able on length or charset"
        );
        // Fresh empty plan each time: the refusal cannot be a collision.
        let outcome = plan(4, 1_024, 512).register(name, EntryKind::File, 1);
        assert_eq!(
            outcome,
            Err(ArchiveError::InvalidPath),
            "{name:?} is on the declared reserved-device list"
        );
    }
}

#[test]
fn names_that_only_look_reserved_are_accepted() {
    // Hand-checked against the declared list: none of these is reserved,
    // so each must be accepted verbatim.
    for name in [
        "COM0",
        "COM10",
        "com0",
        "LPT0",
        "LPT11",
        "LPT10",
        "NULL",
        "CONSOLE",
        "PRN1",
        "AUX1",
        "auxiliary",
        "assist",
        "LPTA",
        "COM",
        "LPT",
        "co",
        "lp",
        "ports",
    ] {
        let mut p = plan(4, 1_024, 512);
        assert_eq!(
            p.register(name, EntryKind::File, 1).unwrap(),
            name,
            "{name:?} is not a declared reserved device name"
        );
    }
}

#[test]
fn windows_illegal_characters_rejected() {
    // Declared illegal component characters: < > : \" | ? * \\
    for bad in ['<', '>', ':', '"', '|', '?', '*', '\\'] {
        let name = format!("safe{bad}name");
        let outcome = plan(4, 1_024, 512).register(&name, EntryKind::File, 1);
        assert_eq!(
            outcome,
            Err(ArchiveError::InvalidPath),
            "component containing {bad:?} is illegal on Windows"
        );
    }
    // Trailing dot / trailing space (Windows strips them silently).
    for name in ["a.", "a ", "dir/a.", "dir/a ", "a.b.", "a  ", "a ."] {
        let outcome = plan(4, 1_024, 512).register(name, EntryKind::File, 1);
        assert_eq!(
            outcome,
            Err(ArchiveError::InvalidPath),
            "{name:?} ends with a dot or a space"
        );
    }
    // Directory entries follow the same component rules.
    for name in ["a./", "a /", "a<b/", "CON/", "a>:/"] {
        let outcome = plan(4, 1_024, 512).register(name, EntryKind::Directory, 0);
        assert_eq!(
            outcome,
            Err(ArchiveError::InvalidPath),
            "directory {name:?} contains an illegal component"
        );
    }
    // Interior dots/spaces and a leading dot are not declared illegal.
    for name in ["a.b", "a b", ".hidden", "a..b", "v1.2.3"] {
        let mut p = plan(4, 1_024, 512);
        assert_eq!(
            p.register(name, EntryKind::File, 1).unwrap(),
            name,
            "{name:?} has no trailing dot/space and is not reserved"
        );
    }
}

#[test]
fn traversal_drive_slash_and_non_ascii_rejected() {
    for name in [
        "",
        "/",
        "/abs",
        "../x",
        "a/../b",
        "a/./b",
        "a//b",
        "a/b/",
        "C:/x",
        "a\\b",
        "//host/share",
        "aé",
        "a\n",
        "a\tb",
        "bell\u{7}",
    ] {
        let outcome = plan(4, 1_024, 512).register(name, EntryKind::File, 1);
        assert!(
            outcome.is_err(),
            "file path {name:?} must be refused, got {outcome:?}"
        );
    }
    // A file may not carry a trailing slash; a directory gets exactly one.
    let mut p = plan(4, 1_024, 512);
    assert_eq!(p.register("bin/", EntryKind::Directory, 0).unwrap(), "bin");
    assert_eq!(
        p.register("bin//", EntryKind::Directory, 0),
        Err(ArchiveError::InvalidPath),
        "only one trailing directory separator is allowed"
    );
    assert_eq!(
        p.register("bin/", EntryKind::File, 1),
        Err(ArchiveError::InvalidPath),
        "a trailing slash on a file entry is not the declared directory form"
    );
}

// ---------------------------------------------------------------------------
// 6. Cumulative capacity: near-boundary accumulation and u64 overflow.
// ---------------------------------------------------------------------------

#[test]
fn cumulative_total_budget_enforced_near_boundary() {
    // entry_bytes 12, total_bytes 30. Hand-computed: 12 + 12 = 24 fits,
    // 24 + 7 = 31 > 30 refuses, 24 + 6 = 30 fills exactly, then +1 refuses.
    let mut p = plan(8, 30, 12);
    assert_eq!(p.register("f1", EntryKind::File, 12).unwrap(), "f1");
    assert_eq!(p.register("f2", EntryKind::File, 12).unwrap(), "f2");
    assert_eq!(
        p.register("f3", EntryKind::File, 7),
        Err(ArchiveError::Limit),
        "12 + 12 + 7 = 31 exceeds the declared 30-byte total"
    );
    // The refusal may not have been charged: the same slot still fits 6.
    assert_eq!(
        p.register("f3", EntryKind::File, 6).unwrap(),
        "f3",
        "a refused entry must not have consumed budget"
    );
    assert_eq!(
        p.register("f4", EntryKind::File, 1),
        Err(ArchiveError::Limit),
        "total is exactly full at 12+12+6 = 30, so one more byte must be refused"
    );

    // Per-entry cap and entry-count cap are cumulative refusals as well.
    let mut q = plan(2, 1_024, 8);
    assert_eq!(q.register("g1", EntryKind::File, 8).unwrap(), "g1");
    assert_eq!(
        q.register("g2", EntryKind::File, 9),
        Err(ArchiveError::Limit),
        "9 > declared per-entry cap of 8"
    );
    assert_eq!(q.register("g2", EntryKind::File, 1).unwrap(), "g2");
    assert_eq!(
        q.register("g3", EntryKind::File, 0),
        Err(ArchiveError::Limit),
        "the declared entries cap of 2 is reached, even for a 0-byte file"
    );
}

#[test]
fn u64_overflow_in_accumulation_is_refused() {
    // 2^63 + 2^63 = 2^64 leaves u64 entirely; failing closed is mandatory.
    let half = 1u64 << 63;
    assert_eq!(half, 9_223_372_036_854_775_808, "hand-written 2^63");
    assert_eq!(
        half.checked_add(half),
        None,
        "test premise: sum overflows u64"
    );
    let mut p = plan(4, u64::MAX, half);
    assert_eq!(p.register("big", EntryKind::File, half).unwrap(), "big");
    assert_eq!(
        p.register("big2", EntryKind::File, half),
        Err(ArchiveError::Limit),
        "two 2^63-byte entries overflow u64 and must fail closed"
    );
    // No charge taken for the overflowed entry: the plan can still be filled
    // up to the declared entry-count cap of 4.
    assert_eq!(p.register("small", EntryKind::File, 1).unwrap(), "small");
    assert_eq!(p.register("s2", EntryKind::File, 1).unwrap(), "s2");
    assert_eq!(p.register("s3", EntryKind::File, 1).unwrap(), "s3");
    assert_eq!(
        p.register("s4", EntryKind::File, 1),
        Err(ArchiveError::Limit),
        "entries big+small+s2+s3 = 4 fill the declared count cap"
    );
}

// ---------------------------------------------------------------------------
// 7. Failure invariance: refusals change nothing observable.
// ---------------------------------------------------------------------------

/// Golden sequence declared twice: once clean, once with adversarial refusals
/// interleaved. The produced canonical names and later budget decisions must
/// be identical, i.e. a refused registration never writes partially.
#[test]
fn refused_registrations_leave_plan_output_identical() {
    // Declared ceilings: 8 entries, 1_024 total, 512 per entry.
    // Golden byte usage: 0 + 500 + 100 + 20 = 620; 620 + 400 = 1_020 <= 1_024.
    let golden: [(&str, EntryKind, u64, &str); 4] = [
        ("bin/", EntryKind::Directory, 0, "bin"),
        ("bin/chrome.exe", EntryKind::File, 500, "bin/chrome.exe"),
        (
            "profile/Default/Preferences",
            EntryKind::File,
            100,
            "profile/Default/Preferences",
        ),
        (
            "profile/Default/Bookmarks",
            EntryKind::File,
            20,
            "profile/Default/Bookmarks",
        ),
    ];
    // Refused by content rules alone, in every plan state below.
    let overlong = format!("{}z", "p".repeat(240)); // 241 bytes
    assert_eq!(overlong.len(), 241, "hand-computed over-long path");
    let mut stateless_noise: Vec<(&str, EntryKind, u64)> = vec![
        ("CON", EntryKind::File, 1),                   // reserved name
        ("bad/name:", EntryKind::File, 1),             // illegal char
        ("trai l.", EntryKind::File, 1),               // trailing dot
        ("huge", EntryKind::File, 513),                // over per-entry cap
        ("no-such-kind", EntryKind::Symlink, 0),       // unsupported kind
        ("profile/Default/", EntryKind::Directory, 5), // directory with size
    ];
    stateless_noise.push((overlong.as_str(), EntryKind::File, 1));
    // Refused only once the full golden content exists (collision rules).
    let collision_noise: [(&str, EntryKind, u64); 5] = [
        ("bin/chrome.exe", EntryKind::File, 1),   // exact duplicate
        ("BIN/CHROME.EXE", EntryKind::File, 1),   // case duplicate
        ("bin/chrome.exe/x", EntryKind::File, 1), // file-as-parent prefix
        ("profile/Default", EntryKind::File, 1),  // parent of existing files
        ("Profile/Default/", EntryKind::Directory, 3), // case + dir size
    ];

    let mut clean = plan(8, 1_024, 512);
    let mut attacked = plan(8, 1_024, 512);
    let mut reference: Vec<String> = Vec::new();
    let mut observed: Vec<String> = Vec::new();

    for (index, (name, kind, size, expected)) in golden.iter().enumerate() {
        let got = clean.register(name, *kind, *size).unwrap();
        assert_eq!(&got, expected, "clean golden[{index}] canonical name");
        reference.push(got);

        // Attack with state-independent refusals after every accepted step.
        for entry in stateless_noise.iter() {
            let outcome = attacked.register(entry.0, entry.1, entry.2);
            assert!(
                outcome.is_err(),
                "adversarial input {:?} must be refused, got {outcome:?}",
                entry.0
            );
        }
        let got = attacked.register(name, *kind, *size).unwrap();
        assert_eq!(&got, expected, "attacked golden[{index}] canonical name");
        observed.push(got);
    }

    assert_eq!(
        observed, reference,
        "the produced plan must be identical to the failure-free plan"
    );

    // After the full golden content, collision refusals must also change
    // nothing: both plans then take the same over-boundary decisions.
    for entry in collision_noise.iter() {
        let outcome = attacked.register(entry.0, entry.1, entry.2);
        assert!(
            outcome.is_err(),
            "collision-phase input {:?} must be refused, got {outcome:?}",
            entry.0
        );
    }

    // Remaining capacity must match the clean plan, against hand-computed
    // numbers: 620 used, 4 entries, 404 bytes left => 400 fits, +5 refuses.
    let clean_extra = clean.register("extra", EntryKind::File, 400);
    let attacked_extra = attacked.register("extra", EntryKind::File, 400);
    assert_eq!(
        clean_extra.as_deref(),
        Ok("extra"),
        "hand-computed: 620 + 400 = 1_020 <= 1_024 must succeed"
    );
    assert_eq!(
        attacked_extra, clean_extra,
        "a plan under adversarial load must make the same budget decision"
    );
    assert_eq!(
        clean.register("over", EntryKind::File, 5),
        Err(ArchiveError::Limit),
        "hand-computed: 1_020 + 5 = 1_025 > 1_024 must be refused"
    );
    assert_eq!(
        attacked.register("over", EntryKind::File, 5),
        Err(ArchiveError::Limit),
        "same refusal in the attacked plan"
    );
}
