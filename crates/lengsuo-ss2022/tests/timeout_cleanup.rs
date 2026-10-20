//! 异常矩阵补缺（ALL-1 审计 §3）：SS2022 的「超时」与「清理」两类格。
//!
//! 只测公开可观测入口（[`Sessions::gc`] / [`Receiver::gc`] / `last_peer`），
//! 不改 `src/`。全部 API 同步且时钟由 [`Clock`] 注入，无真实 socket 与
//! `await`，故无需 `tokio::time::timeout` 截止时间。
//!
//! 过期判定（`src/receiver.rs`）：`unix 差 > 60 秒` **且** `存活 >= retention`
//! 两者同时成立才可回收；`retention` 下限 60 秒由 `SessionPolicy` 强制。
//! 参考实现（xray `proxy/shadowsocks_2022/`）没有会话表与 gc 层，
//! 本组用例对齐的是本项目自身文档化的会话语义，不与 xray 逐行对照。
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    receiver::{Clock, Receiver, Sessions},
    replay_store::ReplayStore,
    Error,
};
use ss_core::target::TargetAddr;
use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};
fn key() -> Key {
    Key::new(Method::Aes128, &[0x42; 16]).unwrap()
}
fn clock(base: Instant, seconds: u64) -> Clock {
    clock_at(base, 1000 + seconds, seconds)
}
/// unix 秒与单调秒各自独立推进，用于把两个过期维度分开压边界。
fn clock_at(base: Instant, unix_seconds: u64, mono_seconds: u64) -> Clock {
    Clock {
        unix_seconds,
        monotonic: base + Duration::from_secs(mono_seconds),
    }
}
fn peer(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}
fn seal(sender: &mut Sender, time: u64) -> Vec<u8> {
    sender
        .seal(&TargetAddr::V4([1; 4], 80), b"test", time, 0)
        .unwrap()
}
fn receiver(cap: usize) -> Receiver {
    Receiver::new(key(), None, cap, Duration::from_secs(60)).unwrap()
}
fn temporary_path(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "lengsuo-ss2022-timeout-cleanup-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory.join("replay.bin")
}

/// A0 策略下限：保留期必须 ≥ 60 秒、容量必须 ≥ 1，否则拒绝建表。
///
/// 记录此下限是因为任务书要求「短保留期」——实现把保留期硬下限定在 60 秒
/// （与「已证明过期」的判定条件一致），故可测的保留期只有 60 秒一档。
#[test]
fn session_policy_rejects_short_retention_and_zero_capacity() {
    assert!(matches!(
        Sessions::new(1, Duration::from_secs(59)),
        Err(Error::SessionPolicy)
    ));
    assert!(Sessions::new(1, Duration::from_secs(60)).is_ok());
    assert!(matches!(
        Sessions::new(0, Duration::from_secs(60)),
        Err(Error::SessionPolicy)
    ));
    assert!(matches!(
        Receiver::new(key(), None, 0, Duration::from_secs(60)),
        Err(Error::SessionPolicy)
    ));
}

/// A1 会话过期：gc 回收后 `last_peer` 失效；同会话再次出现登记新地址，
/// 不复活回收前的旧对端。
#[test]
fn session_expiry_reclaims_and_does_not_revive_old_peer() {
    let base = Instant::now();
    let mut sessions = Sessions::new(2, Duration::from_secs(60)).unwrap();
    let session_id = [0xA0; 8];
    sessions
        .accept(session_id, 1, peer(1), clock(base, 0))
        .unwrap();
    assert_eq!(sessions.last_peer(session_id), Some(peer(1)));
    sessions.gc(clock(base, 120)).unwrap();
    assert_eq!(sessions.last_peer(session_id), None);
    // 回收后同会话重现：按新会话登记，旧 peer 不再可见。
    sessions
        .accept(session_id, 2, peer(2), clock(base, 121))
        .unwrap();
    assert_eq!(sessions.last_peer(session_id), Some(peer(2)));
}

/// A2 边界值：两个过期维度各自在边界上结果确定——
/// unix 差恰为 60 保留 / 61 回收；存活恰为 retention-1 保留 / == retention 回收。
#[test]
fn retention_boundary_is_deterministic_on_both_sides() {
    let base = Instant::now();
    let session_id = [0xA1; 8];

    // 维度一：unix 差边界（存活时间远超 retention，隔离出唯一变量）。
    let mut unix_edge = Sessions::new(2, Duration::from_secs(60)).unwrap();
    unix_edge
        .accept(session_id, 1, peer(1), clock(base, 0))
        .unwrap();
    unix_edge.gc(clock_at(base, 1060, 600)).unwrap();
    assert_eq!(unix_edge.last_peer(session_id), Some(peer(1)));
    unix_edge.gc(clock_at(base, 1061, 601)).unwrap();
    assert_eq!(unix_edge.last_peer(session_id), None);

    // 维度二：存活时长边界（unix 差远超 60，隔离出唯一变量）。
    let mut age_edge = Sessions::new(2, Duration::from_secs(60)).unwrap();
    age_edge
        .accept(session_id, 1, peer(2), clock(base, 0))
        .unwrap();
    age_edge.gc(clock_at(base, 1100, 59)).unwrap();
    assert_eq!(age_edge.last_peer(session_id), Some(peer(2)));
    age_edge.gc(clock_at(base, 1100, 60)).unwrap();
    assert_eq!(age_edge.last_peer(session_id), None);
}

/// A3 时钟回滚：`gc()` 路径必须 fail-closed 返回 `Err(ClockRollback)`，
/// 会话既不被误回收也不被当作新鲜延续；水位恢复后正常 gc 仍可回收。
#[test]
fn gc_fails_closed_on_rolled_back_clock() {
    let base = Instant::now();
    let mut sessions = Sessions::new(2, Duration::from_secs(60)).unwrap();
    let session_id = [0xA2; 8];
    sessions
        .accept(session_id, 1, peer(3), clock(base, 0))
        .unwrap();
    // 推进水位但会话未过期。
    sessions.gc(clock_at(base, 1001, 1)).unwrap();
    assert_eq!(sessions.last_peer(session_id), Some(peer(3)));
    // unix 回退。
    assert!(matches!(
        sessions.gc(clock_at(base, 1000, 2)),
        Err(Error::ClockRollback)
    ));
    // 单调钟冻结（unix 不变、monotonic 倒退）。
    assert!(matches!(
        sessions.gc(Clock {
            unix_seconds: 1001,
            monotonic: base
        }),
        Err(Error::ClockRollback)
    ));
    assert_eq!(sessions.last_peer(session_id), Some(peer(3)));
    // 水位之后的正常 gc 不受失败影响，照常回收。
    sessions.gc(clock(base, 61)).unwrap();
    assert_eq!(sessions.last_peer(session_id), None);
}

/// A4 UDP 侧超时：静默超过保留期后 `Receiver::gc()` 使反射地址失效，
/// 旧报文不能重新绑定旧地址；新报文按新会话重新绑定。
#[test]
fn receiver_gc_expires_reflection_address_after_silence() {
    let base = Instant::now();
    let mut rx = receiver(1);
    let mut tx = Sender::new(key(), None).unwrap();
    let packet = seal(&mut tx, 1000);
    rx.receive(&packet, peer(1), clock(base, 0)).unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), Some(peer(1)));
    rx.gc(clock(base, 120)).unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), None);
    // 旧报文重放：时间戳已出窗口，先被拒，不可能反射回旧地址。
    assert!(matches!(
        rx.receive(&packet, peer(2), clock(base, 120)),
        Err(Error::Timestamp)
    ));
    // 合法新报文以新会话身份重新绑定。
    rx.receive(&seal(&mut tx, 1120), peer(2), clock(base, 120))
        .unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), Some(peer(2)));
}

/// B5 容量压力：满员时拒绝**新**会话（fail-closed，不淘汰旧会话），
/// gc 回收过期会话后腾出容量，且不残留任何被回收会话。
///
/// 偏离说明：任务书假设「淘汰最旧会话」；实际实现是满员即拒
/// （`accept` 文档化的「容量拒绝不改变任何状态」），本用例按真实语义断言。
#[test]
fn capacity_pressure_rejects_overflow_then_gc_frees_slots() {
    let base = Instant::now();
    let mut sessions = Sessions::new(2, Duration::from_secs(60)).unwrap();
    let oldest = [0xB1; 8];
    let middle = [0xB2; 8];
    let newcomer = [0xB3; 8];
    sessions.accept(oldest, 1, peer(1), clock(base, 0)).unwrap();
    sessions.accept(middle, 1, peer(2), clock(base, 0)).unwrap();
    // 满员：新会话被拒，最旧的两个会话原样保留、地址不失。
    assert!(matches!(
        sessions.accept(newcomer, 1, peer(3), clock(base, 1)),
        Err(Error::SessionCapacity)
    ));
    assert_eq!(sessions.last_peer(oldest), Some(peer(1)));
    assert_eq!(sessions.last_peer(middle), Some(peer(2)));
    assert_eq!(sessions.last_peer(newcomer), None);
    // gc 回收全部过期会话，容量腾出，新会话可登记。
    sessions.gc(clock(base, 120)).unwrap();
    assert_eq!(sessions.last_peer(oldest), None);
    assert_eq!(sessions.last_peer(middle), None);
    sessions
        .accept(newcomer, 1, peer(3), clock(base, 121))
        .unwrap();
    assert_eq!(sessions.last_peer(newcomer), Some(peer(3)));
    // 不残留：新会话过期后同样被回收。
    sessions.gc(clock(base, 200)).unwrap();
    assert_eq!(sessions.last_peer(newcomer), None);
}

/// B6 重放存储清理：`flush_replay()` 落盘后，会话被 gc 回收也不得清掉
/// 持久化去重集合——同 `(session, packet id)` 重放始终 fail-closed；
/// 已回收会话的地址不再可见。
#[test]
fn replay_store_cleanup_preserves_dedup_window() {
    let path = temporary_path("receiver");
    let _ = std::fs::remove_file(&path);
    let base = Instant::now();
    let store = ReplayStore::load(&path).unwrap();
    let mut rx = Receiver::new(key(), None, 2, Duration::from_secs(60))
        .unwrap()
        .with_replay_store(store);
    let mut tx = Sender::new(key(), None).unwrap();

    let first = seal(&mut tx, 1000);
    let first_id = rx
        .receive(&first, peer(1), clock(base, 0))
        .unwrap()
        .packet_id;
    rx.flush_replay().unwrap();
    assert!(matches!(
        rx.receive(&first, peer(1), clock(base, 0)),
        Err(Error::Replay)
    ));
    // 会话过期回收，地址不再泄漏。
    rx.gc(clock(base, 120)).unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), None);
    // 旧报文因时间戳出窗口被拒（不可能借 gc 复活）。
    assert!(matches!(
        rx.receive(&first, peer(2), clock(base, 120)),
        Err(Error::Timestamp)
    ));
    // 新报文登记并落盘；同报文重放被去重集合拒绝。
    let second = seal(&mut tx, 1120);
    let second_id = rx
        .receive(&second, peer(2), clock(base, 120))
        .unwrap()
        .packet_id;
    rx.flush_replay().unwrap();
    assert!(matches!(
        rx.receive(&second, peer(2), clock(base, 120)),
        Err(Error::Replay)
    ));
    // 再次过期回收后：地址不可见，持久化集合仍持有两个已收 id，
    // 同 id 重放 fail-closed（清理不得清掉去重窗口）。
    rx.gc(clock(base, 240)).unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), None);
    let mut reloaded = ReplayStore::load(&path).unwrap();
    assert!(reloaded.contains(tx.session_id(), first_id));
    assert!(reloaded.contains(tx.session_id(), second_id));
    assert!(!reloaded.accept(tx.session_id(), second_id));
    let _ = std::fs::remove_file(&path);
}

/// B7 错误输入不污染状态：认证失败 / 截断包 / 容量超限各喂一次后，
/// `gc()` 照常回收、后续合法会话照常登记（补「失败后再 gc 也不炸、能继续服务」）。
#[test]
fn failed_inputs_do_not_block_gc_or_fresh_sessions() {
    let base = Instant::now();
    let mut rx = receiver(1);
    let mut tx = Sender::new(key(), None).unwrap();
    let packet = seal(&mut tx, 1000);
    rx.receive(&packet, peer(1), clock(base, 0)).unwrap();

    // 认证失败（篡改认证尾）。
    let mut bad = packet.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(rx.receive(&bad, peer(2), clock(base, 0)).is_err());
    // 截断包。
    assert!(rx
        .receive(&packet[..packet.len() - 1], peer(2), clock(base, 0))
        .is_err());
    // 容量超限：容量 1 已被合法会话占满。
    let mut other = Sender::new(key(), None).unwrap();
    assert!(matches!(
        rx.receive(&seal(&mut other, 1000), peer(2), clock(base, 0)),
        Err(Error::SessionCapacity)
    ));
    assert_eq!(rx.last_peer(tx.session_id()), Some(peer(1)));

    // 失败之后 gc 照常回收过期会话。
    rx.gc(clock(base, 120)).unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), None);
    // 后续合法会话照常登记。
    rx.receive(&seal(&mut other, 1120), peer(2), clock(base, 120))
        .unwrap();
    assert_eq!(rx.last_peer(other.session_id()), Some(peer(2)));
}
