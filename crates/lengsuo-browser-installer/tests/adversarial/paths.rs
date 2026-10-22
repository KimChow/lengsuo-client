// ---- Windows 路径规则：保留设备名、非法字符、穿越/盘符/非 ASCII ----

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
