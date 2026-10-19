//! keypair 轮换生命周期的确定性测试。
//! 语义对照 wireguard-go `device/keypair.go` / `noise-protocol.go`(`BeginSymmetricSession`,
//! `ReceivedWithKeypair`) / `receive.go` 的到期检查 / `send.go` 的 `keepKeyFreshSending`。

use lengsuo_wireguard::keypair::{Keypair, KeypairSet, KeypairStatus};
use lengsuo_wireguard::timers::constants::{REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME};

const KEY_A: [u8; 32] = [0x11; 32];
const KEY_B: [u8; 32] = [0x22; 32];
const KEY_C: [u8; 32] = [0x33; 32];

fn keypair(local: u32, remote: u32, initiator: bool, created: f64, key: &[u8; 32]) -> Keypair {
    Keypair::new(local, remote, initiator, created, key, key).expect("32 字节密钥应被接受")
}

#[test]
fn keypair_requires_32_byte_keys() {
    assert!(Keypair::new(1, 2, true, 0.0, &[0u8; 31], &[0u8; 32]).is_none());
    assert!(Keypair::new(1, 2, true, 0.0, &[0u8; 32], &[0u8; 33]).is_none());
    assert!(Keypair::new(1, 2, true, 0.0, &[0u8; 32], &[0u8; 32]).is_some());
}

#[test]
fn lifetime_boundaries_are_inclusive_at_reject_after_time() {
    let kp = keypair(1, 2, true, 0.0, &KEY_A);
    assert_eq!(kp.status(0.0), KeypairStatus::Ok);
    // 179.999s：未过期。
    assert!(!kp.age_expired(179.999));
    assert!(kp.can_send(179.999));
    assert!(kp.can_receive(179.999));
    // 恰好 180s：参考用 `created.Add(RejectAfterTime).Before(now)`，边界即拒绝。
    assert!(kp.age_expired(REJECT_AFTER_TIME));
    assert_eq!(kp.status(REJECT_AFTER_TIME), KeypairStatus::Expired);
    assert!(!kp.can_send(REJECT_AFTER_TIME));
    assert!(!kp.can_receive(REJECT_AFTER_TIME));
}

#[test]
fn send_side_rekey_advised_after_120s_for_initiator_only() {
    let initiator = keypair(1, 2, true, 0.0, &KEY_A);
    assert_eq!(initiator.status(120.0), KeypairStatus::Ok);
    assert_eq!(initiator.status(120.001), KeypairStatus::RekeyAdvised);
    // 仍是可发送状态，只是应主动重握手。
    assert!(initiator.can_send(120.001));

    let responder = keypair(1, 2, false, 0.0, &KEY_A);
    assert_eq!(responder.status(179.999), KeypairStatus::Ok);
}

#[test]
fn counter_exhaustion_expires_keypair() {
    let mut kp = keypair(1, 2, true, 0.0, &KEY_A);
    // 前 8 条报文推进计数器到 8。
    for index in 0..8u8 {
        kp.seal(&[index]).expect("计数器未到上限，应可封装");
    }
    assert!(!kp.counter_exhausted());
    assert_eq!(kp.status(0.0), KeypairStatus::Ok);

    // 直接把计数器顶到 RejectAfterMessages（对照 ExpireCurrentKeypairs）。
    kp.expire();
    assert!(kp.counter_exhausted());
    assert_eq!(kp.status(0.0), KeypairStatus::Expired);
    assert!(!kp.can_send(0.0));
    assert!(!kp.can_receive(REJECT_AFTER_TIME));
    assert_eq!(REJECT_AFTER_MESSAGES, u64::MAX - (1 << 13) - 1);
}

#[test]
fn seal_then_open_roundtrips_within_same_keypair() {
    let mut sender = keypair(1, 2, true, 0.0, &KEY_A);
    let mut receiver = keypair(2, 1, false, 0.0, &KEY_A);
    // receiver 期望的 local index 是 2。sender 写 remote index 2。
    let packet = sender.seal(b"hello").expect("封装应成功");
    let decrypted = receiver.open(&packet).expect("同密钥应可解封");
    assert_eq!(decrypted.plaintext, b"hello");
    assert_eq!(decrypted.counter, 0);
    assert_eq!(decrypted.receiver, 2);
}

#[test]
fn send_only_uses_current_never_falls_back_to_previous() {
    let mut set = KeypairSet::new();
    // responder 分支：新 keypair 只进 next，current 仍为 A。
    set.install_as_initiator(keypair(1, 2, true, 0.0, &KEY_A));
    set.install_as_responder(keypair(3, 4, false, 1.0, &KEY_B));

    // current = A（index 1）；next = B（index 3）。
    assert_eq!(set.for_send(0.0).map(|k| k.local_index), Some(1));

    // A 过期后（t=180）发送侧不得回落到 B（B 只在 next，未晋升）。
    assert!(set.for_send(REJECT_AFTER_TIME).is_none());
    // 但接收侧仍可用 B（next 参与接收查找）。
    assert!(set.for_receive_mut(REJECT_AFTER_TIME, 3).is_some());
    // 接收侧不得再用已过期的 A。
    assert!(set.for_receive_mut(REJECT_AFTER_TIME, 1).is_none());
}

#[test]
fn previous_keypair_still_receives_after_rotation() {
    let mut set = KeypairSet::new();
    set.install_as_initiator(keypair(1, 2, true, 0.0, &KEY_A));
    // 发起方分支重轮换：A 降为 previous，B 成为 current。
    set.install_as_initiator(keypair(3, 4, true, 10.0, &KEY_B));

    // 发送必须用新的 current（B）。
    assert_eq!(set.for_send(10.0).map(|k| k.local_index), Some(3));
    // 接收：旧的 A 仍可收（在途包），新的 B 也可收。
    assert!(set.for_receive_mut(10.0, 1).is_some());
    assert!(set.for_receive_mut(10.0, 3).is_some());
}

#[test]
fn previous_keypair_rejected_after_reject_after_time() {
    let mut set = KeypairSet::new();
    set.install_as_initiator(keypair(1, 2, true, 0.0, &KEY_A));
    set.install_as_initiator(keypair(3, 4, true, 10.0, &KEY_B));

    // A 生成于 t=0；t=180 后必须被拒。
    assert!(set.for_receive_mut(179.999, 1).is_some());
    assert!(set.for_receive_mut(180.0, 1).is_none());
    // B 生成于 t=10，要到 t=190 才过期。
    assert!(set.for_receive_mut(180.0, 3).is_some());
    assert!(set.for_receive_mut(190.0, 3).is_none());
}

#[test]
fn received_with_keypair_promotes_next_to_current() {
    let mut set = KeypairSet::new();
    set.install_as_initiator(keypair(1, 2, true, 0.0, &KEY_A));
    set.install_as_responder(keypair(3, 4, false, 1.0, &KEY_B));
    // 此时发送仍用 A；收到用 B 的包后 B 晋升。
    assert_eq!(set.for_send(1.0).map(|k| k.local_index), Some(1));

    assert!(set.received_with_keypair(3));
    assert_eq!(set.for_send(1.0).map(|k| k.local_index), Some(3));
    assert_eq!(set.current().map(|k| k.local_index), Some(3));
    // previous 现在是 A，仍可接收。
    assert!(set.for_receive_mut(1.0, 1).is_some());
    // 再次调用不会重复晋升。
    assert!(!set.received_with_keypair(3));
}

#[test]
fn zero_and_flush_clears_all_slots() {
    let mut set = KeypairSet::new();
    set.install_as_initiator(keypair(1, 2, true, 0.0, &KEY_A));
    set.install_as_responder(keypair(3, 4, false, 1.0, &KEY_B));
    set.zero_and_flush();
    assert!(set.current().is_none());
    assert!(set.for_send(0.0).is_none());
    assert!(set.for_receive_mut(0.0, 1).is_none());
    assert!(set.for_receive_mut(0.0, 3).is_none());
}

#[test]
fn expire_current_blocks_send_but_keeps_key_material_structurally() {
    let mut set = KeypairSet::new();
    set.install_as_initiator(keypair(1, 2, true, 0.0, &KEY_A));
    assert!(set.for_send(0.0).is_some());
    set.expire_current();
    // 计数器顶满 → 发送被拒。
    assert!(set.for_send(0.0).is_none());
    // 结构上 keypair 仍在（参考只删 indexTable 条目，不清空 Keypairs 槽位）。
    assert!(set.current().is_some());
}

#[test]
fn receiver_only_keypair_cannot_send() {
    let kp = Keypair::receive_only(1, 2, false, 0.0, &KEY_C).expect("32 字节密钥应被接受");
    assert!(!kp.can_send(0.0));
    assert!(kp.can_receive(0.0));
}
