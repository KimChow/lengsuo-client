//! 非规范前缀（host bits 非零）与前缀长度边界的**对齐**用例。
//!
//! 参考：wireguard-go `device/allowedips.go`（commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）的
//! `parentIndirection.insert` / `trieEntry.maskSelf` / `trieEntry.lookup`。
//!
//! 期望值来源：在参考仓内直接调用 `device.AllowedIPs` 回放同一串操作，取回
//! lookup 的归属 peer。本文件逐条断言与该结果**逐字节相等**。
//!
//! 语义要点（均为参考的真实行为，不是本仓的设计选择）：
//! - 插入时主机位被 `maskSelf` 清零：`10.1.2.3/8` 存成 `10.0.0.0/8`；
//! - 因此**同一网段的两种写法**（`10.1.2.3/8` 与 `10.9.9.9/8`）命中**同一个**
//!   前缀节点，后插入者接管归属；
//! - `/0` 覆盖该族**全部**地址，`/32`（v4）/`/128`（v6）只覆盖那一个地址；
//! - v4 与 v6 是两棵独立的树，互不覆盖。

use lengsuo_wireguard::AllowedIps;

use super::fixture::{assert_owner, assert_unowned, v4, v6, v6_2001db8, PEER_A, PEER_B, PEER_C};

/// 空表：任何地址都没有归属。
#[test]
fn empty_table_owns_nothing() {
    let table = AllowedIps::new();
    assert_unowned(&table, &v4(10, 0, 0, 1));
    assert_unowned(&table, &v6_2001db8(1));
}

/// 非规范前缀：主机位在插入时被清零，覆盖整段 /8。
///
/// 参考行为：`insert` → `newNode.maskSelf()`（`allowedips.go:131`）把
/// `10.1.2.3/8` 的主机位清成 `10.0.0.0/8`。
#[test]
fn non_canonical_prefix_is_masked_on_insert() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 1, 2, 3), 8));

    assert_owner(&table, &v4(10, 0, 0, 1), Some(PEER_A));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
    assert_owner(&table, &v4(10, 255, 255, 255), Some(PEER_A));
    assert_unowned(&table, &v4(11, 0, 0, 1));
}

/// 同一网段的两种写法命中同一前缀节点，后插入者接管归属。
///
/// 参考行为：`insert` 的 exact 分支（`allowedips.go:116-121`）只把节点的
/// `peer` 换成新 peer，不新建节点；删除后**不恢复**旧归属（落到 `nil`）。
#[test]
fn two_spellings_of_the_same_network_share_one_node() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 1, 2, 3), 8));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));

    // 同一网段的另一种写法。
    assert!(table.insert(PEER_B, &v4(10, 9, 9, 9), 8));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));

    // 删除该前缀后**不**回落到 A：参考的 exact 分支只是改写归属。
    assert!(table.remove(PEER_B, &v4(10, 5, 5, 5), 8));
    assert_unowned(&table, &v4(10, 1, 2, 3));
}

/// v4 前缀长度边界：`/0`、`/1`、`/31`、`/32`。
#[test]
fn v4_prefix_length_boundaries() {
    // /0 覆盖全部 v4 地址。
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(0, 0, 0, 0), 0));
    assert_owner(&table, &v4(10, 0, 0, 1), Some(PEER_A));
    assert_owner(&table, &v4(128, 0, 0, 1), Some(PEER_A));
    assert_owner(&table, &v4(255, 255, 255, 255), Some(PEER_A));

    // /1 只覆盖最高位为 0 的一半。
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 1));
    assert_owner(&table, &v4(10, 0, 0, 1), Some(PEER_A));
    assert_unowned(&table, &v4(128, 0, 0, 1));

    // /31 覆盖两个地址。
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 31));
    assert_owner(&table, &v4(10, 0, 0, 0), Some(PEER_A));
    assert_owner(&table, &v4(10, 0, 0, 1), Some(PEER_A));
    assert_unowned(&table, &v4(10, 0, 0, 2));

    // /32 只覆盖那一个地址。
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 1), 32));
    assert_owner(&table, &v4(10, 0, 0, 1), Some(PEER_A));
    assert_unowned(&table, &v4(10, 0, 0, 2));
}

/// v6 前缀长度边界：`/0`、`/127`、`/128`。
#[test]
fn v6_prefix_length_boundaries() {
    // /0 覆盖全部 v6 地址。
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_B, &[0u8; 16], 0));
    assert_owner(&table, &v6_2001db8(1), Some(PEER_B));
    assert_owner(&table, &[0u8; 16], Some(PEER_B));

    // /127 覆盖最后两个地址。
    let mut table = AllowedIps::new();
    let mut base = v6_2001db8(0);
    base[15] = 0;
    assert!(table.insert(PEER_B, &base, 127));
    assert_owner(&table, &v6_2001db8(0), Some(PEER_B));
    assert_owner(&table, &v6_2001db8(1), Some(PEER_B));
    assert_unowned(&table, &v6_2001db8(2));

    // /128 只覆盖那一个地址。
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_B, &v6_2001db8(1), 128));
    assert_owner(&table, &v6_2001db8(1), Some(PEER_B));
    assert_unowned(&table, &v6_2001db8(2));
}

/// v4 与 v6 是两棵独立的树：v4 前缀不覆盖 v6 查询，反之亦然。
#[test]
fn v4_and_v6_trees_do_not_cover_each_other() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v6_2001db8(0), 32));

    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
    assert_owner(&table, &v6_2001db8(1), Some(PEER_B));
    assert_unowned(&table, &v4(192, 168, 1, 1));
    // `2001:db8::/32` 只覆盖 `2001:db8::` 这一段；`2001:db9::` 在它之外。
    let mut outside = v6_2001db8(9);
    outside[3] = 0xb9;
    assert_unowned(&table, &outside);
}

/// IPv4-mapped IPv6（`::ffff:x.x.x.x`）归 **v6 树**，不是 v4 树。
///
/// 参考行为：`AllowedIPs.Insert` 用 `prefix.Addr().Is6()` 分派（`allowedips.go:295`），
/// 而 `netip.Addr.Is4In6()` 为真时 `Is6()` 也为真 ⇒ 4-in-6 地址进 **IPv6 树**；
/// `Lookup` 再按 `len(ip)` 分派，4 字节查询永远查不到 IPv6 树。
///
/// 参考回放（`I A ::ffff:1.2.3.4 120`）：
/// `E A -> [::ffff:1.2.3.0/120]`、`L ::ffff:1.2.3.4 -> A`、`L 1.2.3.4 -> -`。
#[test]
fn ipv4_mapped_ipv6_addresses_belong_to_the_v6_tree() {
    let mut table = AllowedIps::new();
    // `::ffff:1.2.3.4` 的 16 字节形式。
    let mapped = v6(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]);
    assert!(table.insert(PEER_A, &mapped, 120));

    // 掩码后是 `::ffff:1.2.3.0/120`：同段（末字节 0~255）都归 A。
    assert_owner(&table, &mapped, Some(PEER_A));
    let mut other = mapped;
    other[15] = 200;
    assert_owner(&table, &other, Some(PEER_A));
    // 段外：`::ffff:1.2.4.0` 的第 14 字节变了，不在该 /120 内。
    let mut outside = mapped;
    outside[14] = 4;
    assert_unowned(&table, &outside);

    // v4 的 4 字节查询查的是**另一棵树** ⇒ 无归属。
    assert_unowned(&table, &v4(1, 2, 3, 4));
}

/// 嵌套前缀：最长前缀匹配。
#[test]
fn nested_prefixes_resolve_to_the_longest_match() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v4(10, 1, 0, 0), 16));
    assert!(table.insert(PEER_C, &v4(10, 1, 2, 0), 24));

    assert_owner(&table, &v4(10, 9, 9, 9), Some(PEER_A));
    assert_owner(&table, &v4(10, 1, 9, 9), Some(PEER_B));
    assert_owner(&table, &v4(10, 1, 2, 9), Some(PEER_C));
}

/// 删除最窄前缀后回落到覆盖它的前缀。
#[test]
fn removing_the_narrowest_prefix_falls_back_to_the_covering_one() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v4(10, 1, 0, 0), 16));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));

    assert!(table.remove(PEER_B, &v4(10, 1, 0, 0), 16));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
}
