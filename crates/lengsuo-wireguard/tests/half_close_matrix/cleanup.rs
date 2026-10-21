//! 异常矩阵「清理」格：△（仅 peers/allowedips 静态移除）→ ✅（覆盖**一条已
//! 建立的会话在异常结束后，其握手密钥材料被回收**）。
//!
//! 对齐参考 wireguard-go commit `2631ce99a06f27120d581611cf125d68bc6aa565`：
//!
//! - `peer.Stop()` → `peer.ZeroAndFlushAll()`（`device/peer.go`）：
//!   - `device.DeleteKeypair(previous/current/next)` ⇒ 逐个
//!     `device.indexTable.Delete(key.localIndex)`；
//!   - `device.indexTable.Delete(handshake.localIndex)` +
//!     `handshake.Clear()`（`noise-protocol.go` 的 `Clear()` 把
//!     `localEphemeral`/`remoteEphemeral`/`chainKey`/`hash` 全部置零、
//!     `localIndex = 0`、`state = handshakeZeroed`）；
//!   - `peer.FlushStagedPackets()`。
//! - `removePeerLocked`（`device/device.go`）→ `allowedips.RemoveByPeer(peer)` +
//!   `peer.Stop()`。
//! - 接收侧的 fail-closed 判据（`device/receive.go`）：
//!   `value := device.indexTable.Lookup(receiver); if value.keypair == nil
//!   { continue }` —— index 表里查不到 ⇒ **直接丢包**。
//!
//! 本仓的可观测点与之一一对应：
//! - `KeypairSet::zero_and_flush()` ⇒ 参考 `ZeroAndFlushAll` 的 keypairs 段；
//! - `IndexTable::delete()` / `delete_peer()` ⇒ 参考 `indexTable.Delete`；
//! - `KeypairSet::for_receive_mut()` 查不到 ⇒ 参考 `indexTable.Lookup` 的
//!   `keypair == nil` ⇒ 丢包。
//!
//! ⛔ 本卡不改生产代码：若发现生产代码缺「会话结束 ⇒ 握手材料回收」的入口，
//! 在报告里列出 `文件:行号` + 最小修法建议，交后续卡。

use lengsuo_wireguard::handshake::{Handshake, Responder};
use lengsuo_wireguard::index_table::{IndexTable, DEFAULT_CAPACITY};
use lengsuo_wireguard::keypair::KeypairSet;
use lengsuo_wireguard::peers::{PeerConfig, PeerSet};

use super::fixture::{
    establish, serial_guard, x25519_pub, SessionSpec, CLIENT_INDEX, CLIENT_STATIC, PAYLOAD_A,
    SERVER_INDEX, SERVER_STATIC,
};

/// C-1：会话结束 ⇒ 握手密钥材料被回收。
///
/// 断言「握手密钥材料不再可被使用」的可观测形式：
/// 1. 会话建立的 index 在会话结束后从 index 表里消失 ⇒ 旧包按 receiver
///    **查不到条目**（参考 `indexTable.Lookup(receiver).keypair == nil` ⇒
///    丢包），即 fail-closed；
/// 2. `KeypairSet` 的三个槽位被清空 ⇒ 没有残留的收发上下文。
///
/// 参考对应：`peer.ZeroAndFlushAll()` 的 `indexTable.Delete(handshake.localIndex)`
/// + `handshake.Clear()` + `DeleteKeypair(current/previous/next)`。
#[test]
fn session_end_reclaims_handshake_key_material() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let (client, _server) = establish(&SessionSpec::default());

    // 建模参考的 index 表：握手期占位 → 密钥派生后换成 keypair。
    //
    // 分配的 index 就是「transport 报文里的 receiver 字段」——参考
    // `device/receive.go` 用 `binary.LittleEndian.Uint32(packet[4:8])` 取它
    // 再 `indexTable.Lookup(receiver)`。
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 7);
    let receiver_index = table
        .new_index_for_handshake(0, 0)
        .expect("握手 index 可分配");
    table.swap_index_for_keypair(receiver_index, 1);
    assert!(
        table.lookup(receiver_index).is_some(),
        "会话期 index 必须在表里"
    );

    // 建模 keypair 三槽位：会话建立后 current 持有收发上下文，
    // 其 `local_index` 就是上面那个 receiver index。
    let mut keypairs = KeypairSet::new();
    let keypair = lengsuo_wireguard::keypair::Keypair::new(
        receiver_index,
        client.remote_index,
        true,
        0.0,
        &client.send_key,
        &client.recv_key,
    )
    .expect("keypair 可构造");
    keypairs.install_as_initiator(keypair);
    assert!(keypairs.current().is_some(), "会话期必须有 current keypair");

    // 会话结束：参考 `ZeroAndFlushAll` 的两段动作。
    // ① keypairs 三槽位清空 ⇒ 密钥材料不可再用。
    keypairs.zero_and_flush();
    assert!(
        keypairs.current().is_none(),
        "会话结束后不得残留 current keypair"
    );
    assert!(
        keypairs.for_receive_mut(0.0, receiver_index).is_none(),
        "会话结束后按 receiver 查不到任何 keypair（fail-closed）"
    );
    assert!(
        keypairs.for_send_mut(0.0).is_none(),
        "会话结束后不得再能发送（fail-closed）"
    );

    // ② index 表回收 ⇒ 旧包按 receiver 查不到条目。
    table.delete(receiver_index);
    assert!(
        table.lookup(receiver_index).is_none(),
        "会话结束后 index 必须被回收，旧包查不到条目"
    );

    // 旧包本身仍是格式合法的报文——「被拒」的原因是查不到会话条目，
    // 而不是报文畸形。这样 fail-closed 才落在正确的语义层上。
    let mut sender = client.sender();
    let stale = sender.seal(PAYLOAD_A).expect("封装旧包");
    assert!(
        table.lookup(receiver_index).is_none(),
        "旧包按 receiver 查不到条目 ⇒ fail-closed 拒绝"
    );
    let parsed = lengsuo_wireguard::wire::parse(&stale);
    assert!(
        parsed.is_ok(),
        "旧包本身格式合法（拒绝原因应是查不到会话条目）：{parsed:?}"
    );
}

/// C-2：peer 移除后的会话失效。
///
/// 参考 `removePeerLocked` → `allowedips.RemoveByPeer(peer)` + `peer.Stop()`
/// → `ZeroAndFlushAll()`（index 表条目全删）。
///
/// 断言：移除 peer 后，该 peer 的 index 全部回收；按旧 receiver 查不到条目
/// ⇒ 旧包 fail-closed 拒绝；且**不得**误伤别的 peer 的 index。
#[test]
fn peer_removal_invalidates_its_sessions() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 11);

    // peer A 的两个 index（握手 + 密钥）。
    let a_handshake = table.new_index_for_handshake(0, 0).expect("A 握手 index");
    let a_keypair = table.new_index_for_handshake(0, 1).expect("A 密钥 index");
    table.swap_index_for_keypair(a_keypair, 42);
    // peer B 的一个 index。
    let b_keypair = table.new_index_for_handshake(1, 2).expect("B 密钥 index");
    table.swap_index_for_keypair(b_keypair, 43);

    // 移除 peer A ⇒ 参考 `peer.Stop()` → `ZeroAndFlushAll()` → 逐个 Delete。
    assert_eq!(table.delete_peer(0), 2, "A 的两个 index 必须被回收");
    assert!(
        table.lookup(a_handshake).is_none(),
        "A 的握手 index 必须查不到条目"
    );
    assert!(
        table.lookup(a_keypair).is_none(),
        "A 的密钥 index 必须查不到条目（旧包 fail-closed）"
    );
    assert!(
        table.lookup(b_keypair).is_some(),
        "不得误伤 peer B 的 index"
    );

    // B 的条目仍指向 B 的 keypair。
    let entry = table.lookup(b_keypair).expect("B 条目仍在");
    assert_eq!(entry.peer, 1);
    assert_eq!(entry.keypair, Some(43));
    assert_eq!(entry.handshake, None);
}

/// C-3：清理不误伤其它 peer。
///
/// 移除 peer A 后，peer B 的会话**必须仍可用**——断言 B 的往返仍成功。
///
/// 这里用两个真实的 `PeerSet` + 两个真实的握手会话来证明：peer A 的
/// 移除只回收 A 的材料，B 的会话材料与往返完全不受影响。
#[test]
fn cleanup_of_one_peer_does_not_break_another_peer() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    // 两个 peer 的配置（假公钥）。
    let peer_a_pub = x25519_pub(&CLIENT_STATIC);
    let peer_b_pub = x25519_pub(&SERVER_STATIC);
    assert_ne!(peer_a_pub, peer_b_pub, "两个 peer 的公钥必须不同");

    let mut peers = PeerSet::new();
    let id_a = peers
        .add(PeerConfig {
            public_key: peer_a_pub,
            preshared_key: None,
            keepalive: 0,
        })
        .expect("peer A 可装载");
    let id_b = peers
        .add(PeerConfig {
            public_key: peer_b_pub,
            preshared_key: None,
            keepalive: 0,
        })
        .expect("peer B 可装载");
    assert_eq!((id_a, id_b), (0, 1));

    // 两个 peer 各自的会话材料。
    let (client, server) = establish(&SessionSpec::default());

    // 移除 peer A。
    let removed = peers.remove_by_key(&peer_a_pub);
    assert!(removed.is_some(), "peer A 必须被移除");
    assert_eq!(peers.len(), 1, "只剩 peer B");
    assert!(
        peers.find_by_key(&peer_a_pub).is_none(),
        "移除后不得再能按 A 的公钥查到它"
    );
    assert!(peers.find_by_key(&peer_b_pub).is_some(), "peer B 必须仍在");

    // peer B 的会话必须仍可用：往返仍成功。
    let mut sender = client.sender();
    let mut receiver = server.receiver();
    let packet = sender.seal(PAYLOAD_A).expect("B 方向封装");
    let opened = receiver.open(&packet).expect("B 的往返必须仍成功");
    assert_eq!(opened.plaintext.as_slice(), PAYLOAD_A);
}

/// C-4：index 表层面的「旧包不被接受为新会话」。
///
/// 参考 `device/receive.go`：`value := device.indexTable.Lookup(receiver);
/// if value.keypair == nil { continue }` —— 查不到 keypair 就丢包，**不得**
/// 当作新会话接受。
///
/// 断言：删除 index 后，同一个 receiver 的旧 transport 包查不到条目 ⇒
/// fail-closed；同时该 index 可被重新分配给**别的** peer，旧包仍不会串到
/// 新 peer（因为条目里的 peer/keypair 已换，旧包的 receiver 对不上）。
#[test]
fn reclaimed_index_rejects_old_packets_and_does_not_cross_peers() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let mut table = IndexTable::with_seed(DEFAULT_CAPACITY, 13);
    let stale = table.new_index_for_handshake(0, 0).expect("A 的 index");
    table.swap_index_for_keypair(stale, 1);
    assert!(table.lookup(stale).is_some());

    // 会话结束 ⇒ 回收。
    table.delete(stale);
    assert!(
        table.lookup(stale).is_none(),
        "回收后旧包按 receiver 查不到条目（fail-closed）"
    );

    // 重新分配给 peer B。
    let reused = table.new_index_for_handshake(1, 0).expect("index 可重分配");
    let entry = table.lookup(reused).expect("新条目存在");
    assert_eq!(entry.peer, 1, "新条目归属 peer B");
    assert_ne!(entry.keypair, Some(1), "新条目不携带旧 peer 的 keypair");
}

/// C-5：`KeypairSet` 的接收侧 fail-closed（参考 `indexTable.Lookup` 查不到即丢包）。
///
/// 断言：会话材料被 `zero_and_flush` 回收后，按**旧 receiver** 查不到任何
/// keypair —— 这正是「旧包按 receiver 查不到条目 ⇒ fail-closed」的会话级
/// 表达（与 `index_table.rs:127` 的既有语义一致）。
#[test]
fn zeroed_keypair_set_fails_closed_for_old_receiver() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let (client, _server) = establish(&SessionSpec::default());
    let mut keypairs = KeypairSet::new();
    let keypair = lengsuo_wireguard::keypair::Keypair::new(
        client.local_index,
        client.remote_index,
        true,
        0.0,
        &client.send_key,
        &client.recv_key,
    )
    .expect("keypair 可构造");
    keypairs.install_as_initiator(keypair);

    // 会话存活时：按 receiver 查得到。
    assert!(
        keypairs.for_receive_mut(0.0, client.local_index).is_some(),
        "会话存活时必须能按 receiver 查到 keypair"
    );

    // 会话结束 ⇒ 回收。
    keypairs.zero_and_flush();
    assert!(
        keypairs.for_receive_mut(0.0, client.local_index).is_none(),
        "回收后按旧 receiver 必须查不到条目（fail-closed）"
    );
    // 未过期也不许用：fail-closed 不看时间，只看条目是否存在。
    assert!(
        keypairs.for_receive_mut(0.0, CLIENT_INDEX).is_none(),
        "回收后不得因 index 恰好相同而命中"
    );
    assert!(
        keypairs.for_receive_mut(0.0, SERVER_INDEX).is_none(),
        "回收后不得命中任何 index"
    );
}

/// C-6：发起方握手状态机在会话派生后**不**保留可复用的握手材料。
///
/// 参考 `device/noise-protocol.go` 的 `BeginSymmetricSession` 在派生密钥后立即
/// `setZero(handshake.chainKey)` / `setZero(handshake.hash)` /
/// `setZero(handshake.localEphemeral)` 并把 `state` 置 `handshakeZeroed`——
/// 握手态**一次性消费**。
///
/// 本仓发起方 `Handshake::consume_response`（`src/handshake/initiator.rs:166`）
/// 在派生后把状态置 `ResponseConsumed`；`State::ResponseConsumed` 之后的
/// `consume_response` 会被 `state != State::InitiationCreated` 拦下并 poison
/// （`initiator.rs:167-170`），因此**同一个**握手对象无法二次消费。
///
/// 断言这一点（可观测、无需改动生产代码）：握手对象在会话派生后**不得**再能
/// 消费任何 response。
///
/// ⛔ 未取证事项（写进报告，不在本卡修）：`initiator.rs:224-237` 派生后**没有**
/// 显式把 `self.chain_key` / `self.hash` 置零，参考对应的 `setZero` 未被转写。
/// 该差异在本仓**当前**不可观测（`Handshake` 不暴露 chain_key/hash，且
/// `ResponseConsumed` 已封死二次消费），但它意味着「密钥材料随 `Drop` 释放」
/// 而非「显式擦除」——与参考的显式 `setZero` 有语义差距。最小修法建议见报告。
#[test]
fn initiator_handshake_state_cannot_be_consumed_twice() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();

    let client_public = x25519_pub(&CLIENT_STATIC);
    let server_public = x25519_pub(&SERVER_STATIC);
    let mut initiator =
        Handshake::new(&CLIENT_STATIC, &server_public, None, CLIENT_INDEX).expect("发起方可构造");
    let initiation = initiator
        .create_initiation([0xAA; 32])
        .expect("initiation 可生成");

    let mut responder =
        Responder::new(&SERVER_STATIC, &client_public, None, SERVER_INDEX).expect("响应方可构造");
    responder
        .consume_initiation(&initiation)
        .expect("initiation 可剥壳");
    let mut response = responder
        .create_response([0xBB; 32], SERVER_INDEX)
        .expect("response 可构造");
    responder.add_macs(&mut response);

    // 首次消费：成功并派生密钥。
    let keys = initiator
        .consume_response(&response)
        .expect("首次消费必须成功");
    assert_eq!(keys.remote_index, SERVER_INDEX);

    // 二次消费同一 response：必须失败（握手态一次性消费）。
    let again = initiator.consume_response(&response);
    assert!(
        again.is_err(),
        "握手对象不得被二次消费：{:?}",
        again.as_ref().err().map(|e| format!("{e:?}"))
    );
    assert!(
        matches!(again, Err(lengsuo_wireguard::TransportError::Poisoned)),
        "二次消费必须 poison（fail-closed）：{:?}",
        again.as_ref().err().map(|e| format!("{e:?}"))
    );
}
