// ---- 声明上限：240 字节路径、32 个路径分量、累计字节预算与 u64 溢出 ----

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
