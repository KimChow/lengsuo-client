//! 缺省路由（`/0`）与显式允许的**对齐**用例。
//!
//! 参考：wireguard-go `device/allowedips.go`（commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）的
//! `parentIndirection.insert` / `trieEntry.lookup`。
//!
//! 期望值来源：在参考仓内直接调用 `device.AllowedIPs` 回放同一串操作，取回
//! lookup 的归属 peer。
//!
//! 语义要点（参考的真实行为）：
//! - **默认路由必须显式允许**：插了 `10.0.0.0/8` 并不等于允许默认路由，
//!   `8.8.8.8` 仍然无归属；只有显式插 `0.0.0.0/0`（v4）或 `::/0`（v6）才覆盖
//!   全族；
//! - v4 的 `/0` **不**覆盖 v6，v6 的 `/0` **不**覆盖 v4（两棵独立的树）；
//! - `/0` 与更窄的前缀共存时按最长前缀匹配，窄的赢；
//! - 删掉 `/0` 后立刻回落到更窄的前缀（不是「一旦有默认路由就再也窄的赢」）。

use lengsuo_wireguard::AllowedIps;

use super::fixture::{assert_owner, assert_unowned, v4, v6_2001db8, PEER_A, PEER_B};

/// 插了窄前缀**不等于**允许默认路由。
#[test]
fn a_narrow_prefix_does_not_imply_the_default_route() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(10, 0, 0, 0), 8));

    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_A));
    assert_unowned(&table, &v4(8, 8, 8, 8));
}

/// 显式允许 v4 默认路由后覆盖该族全部地址。
#[test]
fn explicit_v4_default_route_covers_the_whole_family() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_B, &v4(0, 0, 0, 0), 0));

    assert_owner(&table, &v4(8, 8, 8, 8), Some(PEER_B));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));
    assert_owner(&table, &v4(255, 255, 255, 255), Some(PEER_B));
}

/// v4 默认路由**不**覆盖 v6 查询。
#[test]
fn v4_default_route_does_not_cover_v6() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_B, &v4(0, 0, 0, 0), 0));
    assert_unowned(&table, &v6_2001db8(1));
}

/// v6 默认路由**不**覆盖 v4 查询。
#[test]
fn v6_default_route_does_not_cover_v4() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &[0u8; 16], 0));
    assert_owner(&table, &v6_2001db8(1), Some(PEER_A));
    assert_unowned(&table, &v4(1, 2, 3, 4));
}

/// 两族各配自己的默认路由，互不串味。
#[test]
fn both_families_can_have_their_own_default_route() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &[0u8; 16], 0));
    assert!(table.insert(PEER_B, &v4(0, 0, 0, 0), 0));

    assert_owner(&table, &v6_2001db8(1), Some(PEER_A));
    assert_owner(&table, &v4(1, 2, 3, 4), Some(PEER_B));
}

/// `/0` 与更窄前缀共存：最长前缀匹配，窄的赢。
#[test]
fn default_route_and_narrow_prefix_use_longest_prefix_match() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(0, 0, 0, 0), 0));
    assert!(table.insert(PEER_B, &v4(10, 0, 0, 0), 8));

    assert_owner(&table, &v4(8, 8, 8, 8), Some(PEER_A));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));
}

/// 删掉默认路由后回落到更窄的前缀。
#[test]
fn removing_the_default_route_falls_back_to_the_narrow_prefix() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(0, 0, 0, 0), 0));
    assert!(table.insert(PEER_B, &v4(10, 0, 0, 0), 8));
    assert_owner(&table, &v4(8, 8, 8, 8), Some(PEER_A));

    assert!(table.remove(PEER_A, &v4(0, 0, 0, 0), 0));
    assert_unowned(&table, &v4(8, 8, 8, 8));
    assert_owner(&table, &v4(10, 1, 2, 3), Some(PEER_B));
}

/// `/0` 与 `/32` 共存：窄的赢；删掉 `/32` 后回落到 `/0`。
#[test]
fn slash32_inside_the_default_route_wins_and_falls_back() {
    let mut table = AllowedIps::new();
    assert!(table.insert(PEER_A, &v4(0, 0, 0, 0), 0));
    assert!(table.insert(PEER_B, &v4(10, 0, 0, 1), 32));

    assert_owner(&table, &v4(10, 0, 0, 1), Some(PEER_B));
    assert_owner(&table, &v4(10, 0, 0, 2), Some(PEER_A));

    assert!(table.remove(PEER_B, &v4(10, 0, 0, 1), 32));
    assert_owner(&table, &v4(10, 0, 0, 1), Some(PEER_A));
}
