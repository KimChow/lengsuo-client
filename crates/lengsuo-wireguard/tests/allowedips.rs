//! allowedIPs 路由表测试：最长前缀匹配、v4/v6 分离、删除回退、精确命中。
//! 语义对照 wireguard-go `device/allowedips.go`（commit 2631ce99）。

use lengsuo_wireguard::AllowedIps;

const PEER_A: usize = 0;
const PEER_B: usize = 1;
const PEER_C: usize = 2;

fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
    [a, b, c, d]
}

fn v6(prefix: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..prefix.len()].copy_from_slice(prefix);
    out
}

#[test]
fn empty_table_returns_none() {
    let table = AllowedIps::new();
    assert_eq!(table.lookup(&v4(10, 0, 0, 1)), None);
    assert_eq!(table.lookup(&v6(&[0x20, 0x01])), None);
}

#[test]
fn exact_slash32_and_slash128_hit() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 1), 32));
    assert_eq!(table.lookup(&v4(10, 0, 0, 1)), Some(PEER_A));
    assert_eq!(table.lookup(&v4(10, 0, 0, 2)), None);

    assert!(table.insert(PEER_B, &v6(&[0x20, 0x01, 0x0d, 0xb8]), 128));
    assert_eq!(table.lookup(&v6(&[0x20, 0x01, 0x0d, 0xb8])), Some(PEER_B));
    assert_eq!(table.lookup(&v6(&[0x20, 0x01, 0x0d, 0xb9])), None);
}

#[test]
fn longest_prefix_wins() {
    let mut table = AllowedIps::new();
    // 重叠前缀：10/8 → A，10.1/16 → B，10.1.2/24 → C。
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v4(10, 1, 0, 0), 16));
    assert!(table.insert(PEER_C, &v4(10, 1, 2, 0), 24));

    assert_eq!(table.lookup(&v4(10, 9, 9, 9)), Some(PEER_A));
    assert_eq!(table.lookup(&v4(10, 1, 9, 9)), Some(PEER_B));
    assert_eq!(table.lookup(&v4(10, 1, 2, 9)), Some(PEER_C));
    // 11.0.0.0/8 无匹配。
    assert_eq!(table.lookup(&v4(11, 0, 0, 1)), None);
}

#[test]
fn overlapping_inserted_in_reverse_order_still_matches_longest() {
    let mut table = AllowedIps::new();
    // 逆序插入：先窄后宽。
    assert!(table.insert(PEER_C, &v4(10, 1, 2, 0), 24));
    assert!(table.insert(PEER_B, &v4(10, 1, 0, 0), 16));
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));

    assert_eq!(table.lookup(&v4(10, 1, 2, 9)), Some(PEER_C));
    assert_eq!(table.lookup(&v4(10, 1, 9, 9)), Some(PEER_B));
    assert_eq!(table.lookup(&v4(10, 9, 9, 9)), Some(PEER_A));
}

#[test]
fn v4_and_v6_are_separate_trees() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(0, 0, 0, 0), 0));
    assert!(table.insert(PEER_B, &v6(&[]), 0));
    assert_eq!(table.lookup(&v4(1, 2, 3, 4)), Some(PEER_A));
    assert_eq!(table.lookup(&v6(&[0xde, 0xad])), Some(PEER_B));
}

#[test]
fn default_route_slash0_matches_everything() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(0, 0, 0, 0), 0));
    assert_eq!(table.lookup(&v4(8, 8, 8, 8)), Some(PEER_A));

    assert!(table.insert(PEER_B, &v6(&[]), 0));
    assert_eq!(table.lookup(&v6(&[0xff; 16])), Some(PEER_B));
}

#[test]
fn remove_exact_falls_back_to_secondary_prefix() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v4(10, 1, 0, 0), 16));
    assert_eq!(table.lookup(&v4(10, 1, 2, 3)), Some(PEER_B));

    // 删掉 /16 后回退到 /8。
    assert!(table.remove(PEER_B, &v4(10, 1, 0, 0), 16));
    assert_eq!(table.lookup(&v4(10, 1, 2, 3)), Some(PEER_A));

    // 删掉 /8 后空表。
    assert!(table.remove(PEER_A, &v4(10, 0, 0, 0), 8));
    assert_eq!(table.lookup(&v4(10, 1, 2, 3)), None);
}

#[test]
fn remove_ignores_peer_mismatch_and_absent_entries() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    // peer 不匹配：不动。
    assert!(!table.remove(PEER_B, &v4(10, 0, 0, 0), 8));
    assert_eq!(table.lookup(&v4(10, 1, 1, 1)), Some(PEER_A));
    // 不存在的条目：不动。
    assert!(!table.remove(PEER_A, &v4(172, 16, 0, 0), 12));
    assert!(!table.remove(PEER_A, &v4(10, 0, 0, 0), 16));
    assert_eq!(table.lookup(&v4(10, 1, 1, 1)), Some(PEER_A));
}

#[test]
fn remove_by_peer_drops_all_prefixes_of_that_peer() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_A, &v4(192, 168, 0, 0), 16));
    assert!(table.insert(PEER_B, &v4(172, 16, 0, 0), 12));

    table.remove_by_peer(PEER_A);
    assert_eq!(table.lookup(&v4(10, 1, 1, 1)), None);
    assert_eq!(table.lookup(&v4(192, 168, 1, 1)), None);
    assert_eq!(table.lookup(&v4(172, 16, 1, 1)), Some(PEER_B));
}

#[test]
fn reinsert_reassigns_peer_for_same_prefix() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert_eq!(table.lookup(&v4(10, 1, 1, 1)), Some(PEER_A));
    // 同前缀重插给另一个 peer：直接改归属（对照参考的 exact 分支）。
    assert!(table.insert(PEER_B, &v4(10, 0, 0, 0), 8));
    assert_eq!(table.lookup(&v4(10, 1, 1, 1)), Some(PEER_B));
}

#[test]
fn host_bits_in_prefix_are_masked() {
    let mut table = AllowedIps::new();
    // 传入带主机位的地址：应被掩码成 10.0.0.0/8。
    assert!(table.insert(PEER_A, &v4(10, 1, 2, 3), 8));
    assert_eq!(table.lookup(&v4(10, 200, 200, 200)), Some(PEER_A));
    // 精确删除也应用同样的掩码。
    assert!(table.remove(PEER_A, &v4(10, 9, 9, 9), 8));
    assert_eq!(table.lookup(&v4(10, 200, 200, 200)), None);
}

#[test]
fn invalid_ip_length_or_cidr_is_rejected() {
    let mut table = AllowedIps::new();
    assert!(!table.insert(PEER_A, &[1, 2, 3], 24));
    assert!(!table.insert(PEER_A, &v4(1, 2, 3, 4), 33));
    assert!(!table.insert(PEER_A, &v6(&[1, 2]), 129));
    assert_eq!(table.lookup(&[1, 2, 3]), None);
    assert!(!table.remove(PEER_A, &[1, 2, 3], 24));
}

#[test]
fn lookups_do_not_mutate_table() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    for _ in 0..5 {
        assert_eq!(table.lookup(&v4(10, 1, 2, 3)), Some(PEER_A));
    }
    assert_eq!(table.lookup(&v4(10, 1, 2, 3)), Some(PEER_A));
}

#[test]
fn v6_longest_prefix_overlap() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v6(&[0x20, 0x01, 0x0d, 0xb8]), 32));
    assert!(table.insert(PEER_B, &v6(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]), 48));
    assert_eq!(
        table.lookup(&v6(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02])),
        Some(PEER_A)
    );
    assert_eq!(
        table.lookup(&v6(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0xff])),
        Some(PEER_B)
    );
}
