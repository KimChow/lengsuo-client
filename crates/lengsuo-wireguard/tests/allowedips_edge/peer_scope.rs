//! peer 作用域边界的**对齐**用例：移除 peer 后旧包 fail-closed、多 peer
//! 路由隔离、空 peer。
//!
//! 参考：wireguard-go `device/allowedips.go`（commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）的 `AllowedIPs.RemoveByPeer`
//! / `AllowedIPs.Remove` / `AllowedIPs.Insert`；路由判据见
//! `device/receive.go:483,500`（`device.allowedips.Lookup(src) != peer` ⇒
//! 丢包）与 `device/send.go:259,266`（`peer = device.allowedips.Lookup(dst)`，
//! `nil` ⇒ 丢包）。
//!
//! 期望值来源：在参考仓内直接调用 `device.AllowedIPs` 回放同一串操作，取回
//! lookup 的归属 peer。
//!
//! 语义要点（参考的真实行为）：
//! - `RemoveByPeer` 摘掉该 peer 的**全部**前缀；摘掉后这些地址**不再**路由到
//!   它（lookup 返回 `nil` ⇒ 收发两侧都 fail-closed 丢包）；
//! - 其它 peer 的前缀**不受影响**（路由隔离）；
//! - 移除一个**不存在**的 peer、或用**错误的 peer** 删前缀，都是**无操作**
//!   （不静默改表）；
//! - 删前缀只命中 `(前缀, peer)` **完全相等**的那一条：cidr 不同 ⇒ 无操作。

use lengsuo_wireguard::AllowedIps;

use super::fixture::{assert_owner, assert_unowned, v4, v6_2001db8, PEER_A, PEER_B, PEER_C};

/// 移除 peer 后，它的前缀**立即**不再路由到它（fail-closed）。
///
/// 参考：`AllowedIPs.RemoveByPeer`（`allowedips.go:280-289`）逐个摘掉该 peer
/// 的节点；此后 `Lookup` 返回 `nil`，收发两侧都按「无归属」丢包。
#[test]
fn removing_a_peer_makes_its_routes_fail_closed() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));

    table.remove_by_peer(PEER_A);
    assert_unowned(&table, &v4(10, 1, 2, 3));
}

/// 移除 peer 只影响它自己的前缀，其它 peer 的路由**不受影响**。
#[test]
fn removing_one_peer_leaves_other_peers_routes_intact() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v4(192, 168, 0, 0), 16));
    assert!(table.insert(PEER_C, &v4(172, 16, 0, 0), 12));

    table.remove_by_peer(PEER_A);

    assert_unowned(&table, &v4(10, 1, 2, 3));
    assert_owner(&table, &v4(192, 168, 1, 1), Some(PEER_B));
    assert_owner(&table, &v4(172, 16, 1, 1), Some(PEER_C));
}

/// 移除 peer 之后，覆盖全族的默认路由也一并摘掉（否则旧包仍会被路由出去）。
#[test]
fn removing_a_peer_also_drops_its_default_route() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(0, 0, 0, 0), 0));
    assert!(table.insert(PEER_B, &v4(10, 0, 0, 0), 8));

    assert_owner(&table, &v4(8, 8, 8, 8), Some(PEER_A));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));

    table.remove_by_peer(PEER_A);
    assert_unowned(&table, &v4(8, 8, 8, 8));
    // 另一条窄前缀仍在：路由隔离。
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));
}

/// 多 peer 路由隔离：三条互不重叠的前缀各自归属自己的 peer。
#[test]
fn multiple_peers_have_isolated_routes() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v4(192, 168, 0, 0), 16));
    assert!(table.insert(PEER_C, &v4(172, 16, 0, 0), 12));

    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
    assert_owner(&table, &v4(192, 168, 1, 1), Some(PEER_B));
    assert_owner(&table, &v4(172, 16, 1, 1), Some(PEER_C));
    // 不属于任何一条前缀的地址：无归属。
    assert_unowned(&table, &v4(8, 8, 8, 8));
}

/// v4 与 v6 的 peer 作用域彼此独立：移除 v4 侧的 peer 不动 v6 侧。
#[test]
fn removing_a_v4_peer_leaves_v6_routes_intact() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert!(table.insert(PEER_B, &v6_2001db8(0), 32));

    table.remove_by_peer(PEER_A);

    assert_unowned(&table, &v4(10, 1, 2, 3));
    assert_owner(&table, &v6_2001db8(1), Some(PEER_B));
}

/// 空 peer：移除一个从未插入过任何前缀的 peer 是**无操作**。
#[test]
fn removing_an_empty_peer_is_a_no_op() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));

    table.remove_by_peer(PEER_C);
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
}

/// 用**错误的 peer** 删前缀是**无操作**（参考只命中 `(前缀, peer)` 完全相等的）。
#[test]
fn removing_with_a_mismatched_peer_is_a_no_op() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));

    assert!(!table.remove(PEER_B, &v4(10, 0, 0, 0), 8));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
}

/// 用**不同的 cidr** 删同一网段是**无操作**。
#[test]
fn removing_with_a_different_prefix_length_is_a_no_op() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));

    assert!(!table.remove(PEER_A, &v4(10, 0, 0, 0), 16));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));

    // 删一条根本不存在的网段。
    assert!(!table.remove(PEER_A, &v4(192, 168, 0, 0), 16));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
}

/// 两个 peer 抢同一条前缀：后插入者接管；删除后**不**回落到先插入者。
#[test]
fn the_later_peer_takes_over_a_shared_prefix_without_fallback() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));

    assert!(table.insert(PEER_B, &v4(10, 0, 0, 0), 8));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));

    // 参考的 exact 分支只改写归属，不保留旧归属 ⇒ 删掉后无归属。
    assert!(table.remove(PEER_B, &v4(10, 0, 0, 0), 8));
    assert_unowned(&table, &v4(10, 1, 2, 3));
}

/// 移除 peer 后，**在途的旧包**不再命中它的任何前缀。
///
/// 参考 `device/receive.go:483`：`device.allowedips.Lookup(src) != peer` ⇒
/// 继续（丢包）。这里把「旧包源地址」建模为该 peer 曾拥有的地址，断言移除
/// 之后 lookup 不再等于该 peer —— 即收发两侧都 fail-closed。
#[test]
fn in_flight_old_packets_no_longer_match_the_removed_peer() {
    let mut table = AllowedIps::new();
    let old_src = v4(10, 1, 2, 3);
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));
    assert_owner(&table, &old_src, Some(PEER_A));

    table.remove_by_peer(PEER_A);

    // 旧包的源地址不再路由到 A：接收侧按「归属 ≠ 发送 peer」丢弃。
    assert_ne!(table.lookup(&old_src), Some(PEER_A));
    assert_unowned(&table, &old_src);
}
