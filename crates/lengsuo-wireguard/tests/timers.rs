//! 握手定时器状态机的确定性测试：用注入时钟逐点断言动作序列。
//! 语义对照 wireguard-go `device/timers.go`（commit 2631ce99）。
//! 不使用真实 sleep，全部用 `Instant + Duration` 推进。

use std::time::{Duration, Instant};

use lengsuo_wireguard::timers::{constants::*, TimerAction, TimerState};

fn at(epoch: Instant, secs: f64) -> Instant {
    epoch + Duration::from_secs_f64(secs)
}

/// t=0 时启动一个已发握手的 peer，抖动设为 0 便于精确断言。
fn started(epoch: Instant) -> TimerState {
    let mut timers = TimerState::new(epoch);
    timers.set_jitter(0.0);
    timers.set_running(true);
    timers.on_handshake_initiated(0.0);
    timers
}

#[test]
fn rekey_constants_match_reference() {
    assert_eq!(REKEY_AFTER_TIME, 120.0);
    assert_eq!(REKEY_ATTEMPT_TIME, 90.0);
    assert_eq!(REKEY_TIMEOUT, 5.0);
    assert_eq!(MAX_TIMER_HANDSHAKES, 18);
    assert_eq!(REJECT_AFTER_TIME, 180.0);
    assert_eq!(KEEPALIVE_TIMEOUT, 10.0);
    assert_eq!(REKEY_AFTER_MESSAGES, 1 << 60);
    assert_eq!(REJECT_AFTER_MESSAGES, u64::MAX - (1 << 13) - 1);
    assert_eq!(LAST_MINUTE_HANDSHAKE_AGE, 165.0);
}

#[test]
fn not_running_produces_no_actions() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_jitter(0.0);
    // 未 set_running：即便到期也不产生任何动作。
    timers.on_handshake_initiated(0.0);
    assert_eq!(timers.tick(at(epoch, 5.0)), vec![]);
    assert_eq!(timers.tick(at(epoch, 1000.0)), vec![]);
}

#[test]
fn retransmit_fires_at_t5_and_records_attempt() {
    let epoch = Instant::now();
    let mut timers = started(epoch);

    // t=0..4.999：无动作。
    assert_eq!(timers.tick(at(epoch, 0.0)), vec![]);
    assert_eq!(timers.tick(at(epoch, 4.999)), vec![]);
    assert_eq!(timers.handshake_attempts(), 0);

    // t=5：重发一次，attempts 变为 1，并重新武装到 t=10。
    assert_eq!(
        timers.tick(at(epoch, 5.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    assert_eq!(timers.handshake_attempts(), 1);
    assert_eq!(timers.last_sent_handshake(), Some(5.0));

    // t=6 无动作；t=10 第二次重发。
    assert_eq!(timers.tick(at(epoch, 6.0)), vec![]);
    assert_eq!(
        timers.tick(at(epoch, 10.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    assert_eq!(timers.handshake_attempts(), 2);
}

#[test]
fn retransmit_stops_at_max_handshakes_and_arms_zero_key() {
    let epoch = Instant::now();
    let mut timers = started(epoch);

    // 重试到 attempts == MAX_TIMER_HANDSHAKES（18）：t=5,10,…,90。
    for step in 1..=MAX_TIMER_HANDSHAKES {
        let t = REKEY_TIMEOUT * f64::from(step);
        assert_eq!(
            timers.tick(at(epoch, t)),
            vec![TimerAction::RetransmitHandshake],
            "第 {step} 次重发应对应在 t={t}s"
        );
    }
    assert_eq!(timers.handshake_attempts(), MAX_TIMER_HANDSHAKES);

    // t=95：attempts(=18) 未大于上限，仍重发一次，attempts 变 19，重装到 t=100。
    assert_eq!(
        timers.tick(at(epoch, 95.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    assert_eq!(timers.handshake_attempts(), MAX_TIMER_HANDSHAKES + 1);

    // t=100：attempts(=19) > 18，放弃；同刻武装 zeroKeyMaterial 到 t=100+540。
    assert_eq!(
        timers.tick(at(epoch, 100.0)),
        vec![TimerAction::HandshakeGaveUp]
    );
    // 放弃后 retransmit 不再武装：t=105 无动作。
    assert_eq!(timers.tick(at(epoch, 105.0)), vec![]);

    // t=639.999：zeroKeyMaterial 未到；t=640：擦除全部密钥。
    assert_eq!(timers.tick(at(epoch, 639.999)), vec![]);
    assert_eq!(
        timers.tick(at(epoch, 640.0)),
        vec![TimerAction::ZeroKeyMaterial]
    );
}

#[test]
fn handshake_complete_clears_retransmit_and_attempts() {
    let epoch = Instant::now();
    let mut timers = started(epoch);

    // t=5 重试一次 → attempts=1，重装到 t=10。
    assert_eq!(
        timers.tick(at(epoch, 5.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    // t=7 握手完成：清 retransmit、attempts 归零。
    timers.on_handshake_complete(7.0);
    assert_eq!(timers.handshake_attempts(), 0);
    assert_eq!(timers.last_sent_handshake(), Some(7.0));
    // t=10 原本的重试已被清除。
    assert_eq!(timers.tick(at(epoch, 10.0)), vec![]);
    assert_eq!(timers.tick(at(epoch, 100.0)), vec![]);
}

#[test]
fn keepalive_timeout_and_need_another() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_jitter(0.0);
    timers.set_running(true);

    // t=0 收到数据包：武装 sendKeepalive 到 t=10。
    timers.on_data_received(0.0);
    assert_eq!(timers.tick(at(epoch, 9.999)), vec![]);
    assert_eq!(
        timers.tick(at(epoch, 10.0)),
        vec![TimerAction::SendKeepalive]
    );

    // t=11 收到认证包：清 newHandshake（未武装，无副作用）。
    timers.on_authenticated_received();
    // t=12 收到数据：武装 sendKeepalive 到 t=22。
    timers.on_data_received(12.0);
    // t=14 再收到数据：sendKeepalive 已武装 → needAnotherKeepalive=true。
    timers.on_data_received(14.0);
    // needAnotherKeepalive：同刻只产生一条动作，但定时器重装到 t=32。
    assert_eq!(
        timers.tick(at(epoch, 22.0)),
        vec![TimerAction::SendKeepalive],
        "needAnotherKeepalive 不额外产生动作，但把定时器重装到 t=32"
    );
    assert_eq!(
        timers.tick(at(epoch, 32.0)),
        vec![TimerAction::SendKeepalive]
    );
    // 之后再无 keepalive。
    assert_eq!(timers.tick(at(epoch, 100.0)), vec![]);
}

#[test]
fn authenticated_packet_sent_cancels_keepalive() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_running(true);

    timers.on_data_received(0.0);
    // t=3 发出认证包：取消待发 keepalive。
    timers.on_authenticated_sent();
    assert_eq!(timers.tick(at(epoch, 10.0)), vec![]);
    assert_eq!(timers.tick(at(epoch, 50.0)), vec![]);
}

#[test]
fn new_handshake_after_data_sent() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_jitter(0.0);
    timers.set_running(true);

    // t=0 发出数据：武装 newHandshake 到 t=15（10+5+0 抖动）。
    timers.on_data_sent(0.0);
    assert_eq!(timers.tick(at(epoch, 14.999)), vec![]);
    // NewHandshake 语义上会发起一次握手：同刻也武装 retransmitHandshake（t=20）。
    // 参考中 newHandshake 回调先于 retransmitHandshake 注册但更晚到期，这里在
    // 同一次 tick 内 newHandshake 到期并把 retransmit 武装到 t=20。
    assert_eq!(
        timers.tick(at(epoch, 15.0)),
        vec![TimerAction::NewHandshake]
    );
    // 触发后 lastSentHandshake 记录在 t=15。
    assert_eq!(timers.last_sent_handshake(), Some(15.0));

    // 先触发 t=20 的 retransmit，清掉这条遗留链路。
    assert_eq!(
        timers.tick(at(epoch, 20.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    // t=21 又发数据，newHandshake 未武装 → 重新武装到 t=36。
    timers.on_data_sent(21.0);
    // t=25 触发 t=20 重发留下的下一次重发，清空该链路。
    assert_eq!(
        timers.tick(at(epoch, 25.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    // 清零重发定时器，避免污染后续断言。
    timers.on_handshake_complete(25.0);
    assert_eq!(
        timers.tick(at(epoch, 36.0)),
        vec![TimerAction::NewHandshake]
    );
    // 清理：t=41 触发这次 NewHandshake 留下的重发定时器，确认它确实被武装。
    assert_eq!(
        timers.tick(at(epoch, 41.0)),
        vec![TimerAction::RetransmitHandshake]
    );
}

#[test]
fn new_handshake_not_rearmed_while_pending() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_jitter(0.0);
    timers.set_running(true);

    timers.on_data_sent(0.0);
    // 已在 pending：t=2 再发数据不推迟（不应重装到 t=17）。
    timers.on_data_sent(2.0);
    assert_eq!(
        timers.tick(at(epoch, 15.0)),
        vec![TimerAction::NewHandshake]
    );

    // 收到认证包会取消它；此时 t=16 的武装不会触发，而 NewHandshake 在 t=15
    // 触发的重发会把 retransmitHandshake 武装到 t=20。
    timers.on_data_sent(16.0);
    timers.on_authenticated_received();
    assert_eq!(
        timers.tick(at(epoch, 20.0)),
        vec![TimerAction::RetransmitHandshake],
        "仅剩 t=15 NewHandshake 遗留的重发定时器，newHandshake 已被取消"
    );
}

#[test]
fn jitter_shifts_deadlines_within_bound() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_running(true);
    // 抖动上限 334ms。
    timers.set_jitter(0.334);
    timers.on_handshake_initiated(0.0);

    // 恰好 5.0s 未到；5.334s 才到期。
    assert_eq!(timers.tick(at(epoch, 5.0)), vec![]);
    assert_eq!(
        timers.tick(at(epoch, 5.334)),
        vec![TimerAction::RetransmitHandshake]
    );

    // 超过上限的抖动被截断。
    timers.set_jitter(10.0);
    timers.on_handshake_initiated(6.0);
    assert_eq!(timers.tick(at(epoch, 11.0)), vec![]);
    assert_eq!(
        timers.tick(at(epoch, 11.334)),
        vec![TimerAction::RetransmitHandshake]
    );
}

#[test]
fn session_derived_arms_zero_key_material() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_running(true);

    timers.on_session_derived(0.0);
    assert_eq!(timers.tick(at(epoch, 539.999)), vec![]);
    assert_eq!(
        timers.tick(at(epoch, 540.0)),
        vec![TimerAction::ZeroKeyMaterial]
    );
}

#[test]
fn persistent_keepalive_fires_on_interval() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_running(true);
    timers.set_persistent_keepalive(25);

    // t=0 有认证包穿越：武装 persistentKeepalive 到 t=25。
    timers.on_authenticated_traversal(0.0);
    assert_eq!(timers.tick(at(epoch, 24.999)), vec![]);
    assert_eq!(
        timers.tick(at(epoch, 25.0)),
        vec![TimerAction::PersistentKeepalive]
    );
    // 定时器不自动重装：t=50 无动作，直到下一次穿越事件。
    assert_eq!(timers.tick(at(epoch, 50.0)), vec![]);
    timers.on_authenticated_traversal(30.0);
    assert_eq!(
        timers.tick(at(epoch, 55.0)),
        vec![TimerAction::PersistentKeepalive]
    );
}

#[test]
fn persistent_keepalive_disabled_when_zero() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_running(true);
    timers.set_persistent_keepalive(0);
    timers.on_authenticated_traversal(0.0);
    assert_eq!(timers.tick(at(epoch, 1000.0)), vec![]);
}

#[test]
fn last_minute_handshake_only_once() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_running(true);
    // 发起方 keypair 生成于 t=0。
    timers.set_current_keypair(Some(0.0), true);

    // 年龄 165s 之前不需要。
    assert!(!timers.keypair_receive_needs_last_minute_handshake(165.0));
    // 超过 165s 需要一次。
    assert!(timers.keypair_receive_needs_last_minute_handshake(165.1));
    timers.mark_last_minute_handshake_sent();
    assert!(!timers.keypair_receive_needs_last_minute_handshake(166.0));

    // 非发起方 keypair 永不触发。
    timers.set_current_keypair(Some(0.0), false);
    assert!(!timers.keypair_receive_needs_last_minute_handshake(170.0));
}

#[test]
fn keypair_send_rekey_after_120s_only_for_initiator() {
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_running(true);

    timers.set_current_keypair(Some(0.0), true);
    assert!(!timers.keypair_send_needs_rekey(120.0));
    assert!(timers.keypair_send_needs_rekey(120.1));

    timers.set_current_keypair(Some(0.0), false);
    assert!(!timers.keypair_send_needs_rekey(500.0));

    timers.set_current_keypair(None, true);
    assert!(!timers.keypair_send_needs_rekey(500.0));
}

#[test]
fn stop_cancels_every_timer() {
    let epoch = Instant::now();
    let mut timers = started(epoch);
    timers.set_persistent_keepalive(25);
    timers.on_authenticated_traversal(0.0);
    timers.on_session_derived(0.0);
    timers.on_data_received(0.0);

    timers.stop();
    assert_eq!(timers.tick(at(epoch, 1000.0)), vec![]);
}
