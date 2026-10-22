// ---- 失败不变性：被拒绝的登记不得留下任何可观测痕迹 ----

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
