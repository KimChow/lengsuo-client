// 差分回放的两个用例：手写边界串 + 随机差分扫描。
/// 手写边界串的差分回放。
#[test]
#[ignore = "需要参考探针二进制 LENGSUO_WG_ALLOWEDIPS_ORACLE"]
fn boundary_sequence_matches_the_reference() {
    let lookups = assert_matches_reference(&boundary_ops(), "边界操作串");
    assert!(lookups >= 25, "边界串的 lookup 数量偏少：{lookups}");
    println!("边界操作串：{lookups} 次 lookup 与参考逐条相等");
}

/// 随机差分扫描：三个模式各若干种子，0 处不一致才算通过。
#[test]
#[ignore = "需要参考探针二进制 LENGSUO_WG_ALLOWEDIPS_ORACLE"]
fn randomized_differential_scan_matches_the_reference() {
    const SEEDS_PER_MODE: u64 = 200;
    const STEPS: usize = 200;
    let mut lookups = 0usize;
    for mode in Mode::ALL {
        for seed in 0..SEEDS_PER_MODE {
            let ops = random_ops(seed, mode, STEPS);
            lookups += assert_matches_reference(&ops, &format!("模式 {} 种子 {seed}", mode.name()));
        }
    }
    println!(
        "随机差分：{} 个模式 × {} 个种子 = {} 串，{lookups} 次 lookup 全部与参考相等",
        Mode::ALL.len(),
        SEEDS_PER_MODE,
        Mode::ALL.len() * SEEDS_PER_MODE as usize
    );
}
