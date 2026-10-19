//! 全局 index 表矩阵：分配 / 回收 / 冲突 / 耗尽。

use lengsuo_wireguard::index_table::{IndexError, IndexTable, DEFAULT_CAPACITY};

#[test]
fn alloc_returns_free_index_and_is_lookupable() {
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 1);
    let idx = table.new_index_for_handshake(7, 42).unwrap();
    assert!(table.contains(idx));
    let entry = table.lookup(idx).unwrap();
    assert_eq!(entry.peer, 7);
    assert_eq!(entry.handshake, Some(42));
    assert_eq!(entry.keypair, None);
    assert_eq!(table.len(), 1);
}

#[test]
fn alloc_distinct_indices_do_not_collide() {
    let mut table = IndexTable::new();
    let mut seen = std::collections::HashSet::new();
    for i in 0..1000 {
        let idx = table.new_index_for_handshake(i, i as u64).unwrap();
        assert!(seen.insert(idx), "duplicate index {idx}");
    }
    assert_eq!(table.len(), 1000);
}

#[test]
fn swap_replaces_handshake_with_keypair_same_index() {
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 2);
    let idx = table.new_index_for_handshake(1, 5).unwrap();
    table.swap_index_for_keypair(idx, 99);
    let entry = table.lookup(idx).unwrap();
    assert_eq!(entry.peer, 1);
    assert_eq!(entry.handshake, None);
    assert_eq!(entry.keypair, Some(99));
}

#[test]
fn swap_missing_index_is_silent() {
    let mut table = IndexTable::new();
    table.swap_index_for_keypair(12345, 1); // 不 panic
    assert!(table.is_empty());
}

#[test]
fn delete_is_idempotent_and_allows_reuse() {
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 3);
    let idx = table.new_index_for_handshake(0, 0).unwrap();
    table.delete(idx);
    table.delete(idx); // 幂等
    assert!(!table.contains(idx));
    assert_eq!(table.len(), 0);
}

#[test]
fn delete_peer_reclaims_all_its_indices() {
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 4);
    let a1 = table.new_index_for_handshake(1, 0).unwrap();
    let a2 = table.new_index_for_handshake(1, 1).unwrap();
    let b1 = table.new_index_for_handshake(2, 0).unwrap();
    assert_eq!(table.delete_peer(1), 2);
    assert!(!table.contains(a1));
    assert!(!table.contains(a2));
    assert!(table.contains(b1));
    // 回收后 index 重新可分配（此处仅验证表状态）。
    assert_eq!(table.len(), 1);
}

#[test]
fn lookup_of_unknown_index_returns_none() {
    let table = IndexTable::new();
    assert!(table.lookup(0xffff_ffff).is_none());
}

#[test]
fn capacity_exhaustion_is_fail_closed() {
    // 容量 4：分配 4 个成功，第 5 个必须 TableFull 且不覆盖既有条目。
    let mut table = IndexTable::with_seed(4, 5);
    let mut allocated = Vec::new();
    for i in 0..4 {
        allocated.push(table.new_index_for_handshake(i, i as u64).unwrap());
    }
    assert_eq!(table.len(), 4);
    match table.new_index_for_handshake(99, 99) {
        Err(IndexError::TableFull) => {}
        other => panic!("expected TableFull, got {other:?}"),
    }
    // 既有条目完好（未被静默覆盖）。
    for (i, idx) in allocated.iter().enumerate() {
        let entry = table.lookup(*idx).unwrap();
        assert_eq!(entry.peer, i);
        assert_eq!(entry.handshake, Some(i as u64));
    }
    assert_eq!(table.len(), 4);
}

#[test]
fn freed_slot_can_be_reallocated_after_exhaustion() {
    let mut table = IndexTable::with_seed(2, 6);
    let a = table.new_index_for_handshake(0, 0).unwrap();
    let _b = table.new_index_for_handshake(0, 1).unwrap();
    assert!(matches!(
        table.new_index_for_handshake(0, 2),
        Err(IndexError::TableFull)
    ));
    table.delete(a);
    assert!(table.new_index_for_handshake(0, 3).is_ok());
}

#[test]
fn no_collision_when_same_seed_same_capacity() {
    // 两个同种子同容量的表，分配序列应完全一致（确定性 PRNG）。
    let mut t1 = IndexTable::with_seed(64, 0xdead_beef);
    let mut t2 = IndexTable::with_seed(64, 0xdead_beef);
    for i in 0..50 {
        assert_eq!(
            t1.new_index_for_handshake(i, 0).unwrap(),
            t2.new_index_for_handshake(i, 0).unwrap()
        );
    }
    assert_eq!(t1.attempts_total(), t2.attempts_total());
}

#[test]
fn stale_packet_after_delete_is_rejected() {
    // peer 移除 → index 回收 → 旧包按 receiver 查不到条目（fail-closed）。
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 7);
    let stale = table.new_index_for_handshake(1, 0).unwrap();
    table.delete_peer(1);
    assert!(table.lookup(stale).is_none());
}
