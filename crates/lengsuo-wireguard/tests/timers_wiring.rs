//! 定时器接线回归锁（W4 核验卡）：证明 `timers` 模块**不是孤岛**——
//! `device::Device` 持有并驱动 `TimerState`（`src/device.rs:23,42,54,88-94,108-148,151`），
//! 本文件的全部动作都经由 `Device` 公开接口产生，而非直连 `TimerState`。
//!
//! 常量一律引用 `timers::constants`（与参考 wireguard-go
//! `device/constants.go:15-23`、commit `2631ce99a06f27120d581611cf125d68bc6aa565`
//! 对齐），不硬编码魔数；注入时钟推进，不使用真实 sleep。

use std::time::{Duration, Instant};

use lengsuo_wireguard::device::{Device, Output};
use lengsuo_wireguard::keypair::Keypair;
use lengsuo_wireguard::timers::constants::*;
use lengsuo_wireguard::timers::TimerAction;
use lengsuo_wireguard::transport::{Sender, TransportKey};
use lengsuo_wireguard::wire::TRANSPORT_MIN_LEN;

fn at(epoch: Instant, secs: f64) -> Instant {
    epoch + Duration::from_secs_f64(secs)
}

/// 测试专用 index 与假密钥（绝非真实凭据）。
const LOCAL_INDEX: u32 = 0x0100_0001;
const REMOTE_INDEX: u32 = 0x0100_0002;
/// 本端 → 对端的发送密钥。
const SEND_KEY: [u8; 32] = [0xA5; 32];
/// 对端 → 本端的发送密钥（本端接收方向）。
const RECV_KEY: [u8; 32] = [0x5A; 32];

/// 已运行、已装 current keypair 的设备（抖动置 0 便于精确断言）。
fn started(epoch: Instant) -> Device {
    let mut device = Device::new(epoch);
    device.set_running(true);
    device.timers_mut().set_jitter(0.0);
    let keypair = Keypair::new(LOCAL_INDEX, REMOTE_INDEX, true, 0.0, &SEND_KEY, &RECV_KEY)
        .expect("测试密钥可构造 keypair");
    device.keypairs_mut().install_as_initiator(keypair);
    device
}

#[test]
fn device_retransmit_fires_at_rekey_timeout() {
    let epoch = Instant::now();
    let mut device = started(epoch);
    device.timers_mut().on_handshake_initiated(0.0);

    // 到期前一刻无动作；恰在 RekeyTimeout 到期重发一次 initiation。
    assert_eq!(device.tick(at(epoch, REKEY_TIMEOUT - 0.001)), vec![]);
    assert_eq!(
        device.tick(at(epoch, REKEY_TIMEOUT)),
        vec![TimerAction::RetransmitHandshake],
        "RekeyTimeout 到期必须经 Device::tick 产出重发动作"
    );
    assert_eq!(device.timers().handshake_attempts(), 1);

    // 同刻重装：第二个周期照常触发。
    assert_eq!(
        device.tick(at(epoch, REKEY_TIMEOUT * 2.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    assert_eq!(device.timers().handshake_attempts(), 2);
}

#[test]
fn device_gives_up_after_max_timer_handshakes_and_arms_zero_key_material() {
    let epoch = Instant::now();
    let mut device = started(epoch);
    device.timers_mut().on_handshake_initiated(0.0);

    // 前 MAX_TIMER_HANDSHAKES（18）次：每 RekeyTimeout 一次重发。
    for step in 1..=MAX_TIMER_HANDSHAKES {
        let t = REKEY_TIMEOUT * f64::from(step);
        assert_eq!(
            device.tick(at(epoch, t)),
            vec![TimerAction::RetransmitHandshake],
            "第 {step} 次重发应对应在 t={t}s"
        );
    }
    assert_eq!(device.timers().handshake_attempts(), MAX_TIMER_HANDSHAKES);

    // 第 19 次（attempts=19 > 上限）：仍重发一次，随后放弃。
    let second_to_last = REKEY_TIMEOUT * f64::from(MAX_TIMER_HANDSHAKES + 1);
    assert_eq!(
        device.tick(at(epoch, second_to_last)),
        vec![TimerAction::RetransmitHandshake]
    );
    let gave_up_at = REKEY_TIMEOUT * f64::from(MAX_TIMER_HANDSHAKES + 2);
    assert_eq!(
        device.tick(at(epoch, gave_up_at)),
        vec![TimerAction::HandshakeGaveUp],
        "超过 MaxTimerHandshakes 后必须在有限时间内放弃（timers.go expiredRetransmitHandshake）"
    );
    // 放弃后不再重发。
    assert_eq!(
        device.tick(at(epoch, gave_up_at + REKEY_TIMEOUT)),
        vec![],
        "放弃后不得再产出重发动作"
    );

    // 放弃同刻武装 zeroKeyMaterial 到 RejectAfterTime*3（对照
    // timers.go:95-96 与 expiredZeroKeyMaterial → ZeroAndFlushAll）。
    let erase_at = gave_up_at + REJECT_AFTER_TIME * 3.0;
    assert_eq!(device.tick(at(epoch, erase_at - 0.001)), vec![]);
    assert_eq!(
        device.tick(at(epoch, erase_at)),
        vec![TimerAction::ZeroKeyMaterial],
        "放弃后必须在 RejectAfterTime*3 时产出密钥擦除动作"
    );
}

#[test]
fn device_receive_arms_keepalive_and_zero_length_keepalive_matches_seal_empty() {
    let epoch = Instant::now();
    let mut device = started(epoch);

    // 对端用本端的接收密钥封一条带载荷的数据报文。
    let mut peer = Sender::new(
        TransportKey::new(&RECV_KEY).expect("测试密钥合法"),
        LOCAL_INDEX,
        0,
    );
    let packet = peer.seal(b"hello").expect("对端封装");
    assert_eq!(
        device.receive(epoch, &packet),
        Output::Deliver {
            peer: 0,
            payload: b"hello".to_vec(),
        },
        "认证通过的报文必须被投递"
    );

    // 收到数据 ⇒ 武装 sendKeepalive，恰在 KeepaliveTimeout 到期发一次。
    assert_eq!(device.tick(at(epoch, KEEPALIVE_TIMEOUT - 0.001)), vec![]);
    assert_eq!(
        device.tick(at(epoch, KEEPALIVE_TIMEOUT)),
        vec![TimerAction::SendKeepalive],
        "数据到达后 KeepaliveTimeout 到期必须产出 keepalive 动作"
    );

    // 零长 keepalive：结构合法（头 + 16 字节标签）、认证通过并投递空载荷。
    let keepalive = peer.seal(&[]).expect("零长载荷合法");
    assert_eq!(keepalive.len(), TRANSPORT_MIN_LEN);
    assert_eq!(
        device.receive(at(epoch, 1.0), &keepalive),
        Output::Deliver {
            peer: 0,
            payload: Vec::new(),
        },
        "零长载荷 keepalive 必须认证通过且投递空载荷"
    );

    // 参考 receive.go:458-467/518-524：零长包不计入 dataPacketReceived，
    // 不得再武装 sendKeepalive（数据武装的那条已在上面到期）。
    assert_eq!(
        device.tick(at(epoch, 1.0 + 2.0 * KEEPALIVE_TIMEOUT)),
        vec![],
        "keepalive 不得触发 keepKeyFreshReceiving 的数据路径"
    );

    // seal(&[]) 与 keepalive() 等价：同密钥同计数器 ⇒ 同报文。
    let mut explicit = Sender::new(
        TransportKey::new(&RECV_KEY).expect("测试密钥合法"),
        LOCAL_INDEX,
        0,
    );
    let mut shorthand = Sender::new(
        TransportKey::new(&RECV_KEY).expect("测试密钥合法"),
        LOCAL_INDEX,
        0,
    );
    assert_eq!(
        explicit.seal(&[]).expect("seal 空载荷"),
        shorthand.keepalive().expect("keepalive"),
    );
}
