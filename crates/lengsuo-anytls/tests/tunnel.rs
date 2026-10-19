//! SYNACK 看门狗与隧道恢复测试：纯内存、注入时钟，不涉及真实时间。
//! 对齐 anytls-go fd6167a `proxy/session/session.go`：
//! `OpenStream` 的 `if sid >= 2 && peerVersion >= 2` 武装、
//! `synDone` 回调 `s.Close()`、`recvLoop` 里 SYNACK/SYN/ServerSettings 的处理。
use lengsuo_anytls::client_state::Event;
use lengsuo_anytls::frame::{Command, Frame};
use lengsuo_anytls::tunnel::{Expiry, Tunnel, TunnelError, SYNACK_TIMEOUT};
use std::time::{Duration, Instant};

fn t0() -> Instant {
    Instant::now()
}

fn server_settings_v2() -> Frame {
    Frame {
        command: Command::ServerSettings,
        stream_id: 0,
        data: b"v=2".to_vec(),
    }
}

fn syn_ack(stream_id: u32, data: Vec<u8>) -> Frame {
    Frame {
        command: Command::SynAck,
        stream_id,
        data,
    }
}

/// 走完握手：发 Settings、开编号 1 的流、协商 v2 并确认该流。
fn handshaken() -> Tunnel {
    let mut tunnel = Tunnel::new(16).expect("容量合法");
    tunnel.send_settings().expect("发送 Settings");
    // 编号 1 的流：参考在 peerVersion 仍为 1 时开流，因此不武装看门狗。
    let (_, syn) = tunnel.open_stream(t0()).expect("开流 1");
    assert_eq!(syn.command, Command::Syn);
    assert!(tunnel.watchdog().is_none(), "编号 1 不武装看门狗");
    tunnel.accept(&server_settings_v2()).expect("协商 v2");
    tunnel.accept(&syn_ack(1, Vec::new())).expect("确认流 1");
    assert!(tunnel.stream_sendable(1));
    tunnel
}

#[test]
fn settings_frame_carries_v2_client_and_padding_md5_like_reference() {
    let mut tunnel = Tunnel::new(4).expect("容量合法");
    let settings = tunnel.send_settings().expect("发送 Settings");
    assert_eq!(settings.command, Command::Settings);
    assert_eq!(settings.stream_id, 0);
    let text = String::from_utf8(settings.data).expect("UTF-8");
    assert!(text.contains("v=2"), "参考 Run() 固定 v=2：{text}");
    assert!(text.contains("client="), "参考带 client 字段：{text}");
    assert_eq!(
        text.lines()
            .find_map(|line| line.strip_prefix("padding-md5="))
            .expect("含 padding-md5")
            .len(),
        32,
        "padding-md5 是 32 位十六进制"
    );
    assert!(
        text.contains("75cff2ad89aadf5e257059ee571ebe11"),
        "默认方案 md5"
    );
    assert!(matches!(
        tunnel.send_settings(),
        Err(TunnelError::SettingsAlreadySent)
    ));
}

/// 关键差异：编号 1 永不武装，编号 2 起且协商 v2 后武装。
/// 参考条件逐字为 `sid >= 2 && s.peerVersion >= 2`。
#[test]
fn watchdog_arms_only_from_the_second_stream_under_version_two() {
    let mut tunnel = handshaken();
    let now = t0();
    let (id, syn) = tunnel.open_stream(now).expect("开流 2");
    assert_eq!(id, 2);
    assert_eq!(syn.command, Command::Syn);
    let watchdog = tunnel.watchdog().expect("编号 2 武装看门狗");
    assert_eq!(watchdog.stream_id, 2);
    assert_eq!(
        watchdog.expiry,
        Expiry::Clock(now + SYNACK_TIMEOUT),
        "参考 NewDeadlineWatcher(time.Second*3, …)"
    );
}

#[test]
fn watchdog_does_not_arm_while_peer_is_still_version_one() {
    let mut tunnel = Tunnel::new(16).expect("容量合法");
    tunnel.send_settings().expect("发送 Settings");
    // 尚未收到 ServerSettings：peerVersion 仍是 1（参考默认值）。
    let (id, _) = tunnel.open_stream(t0()).expect("开流");
    assert_eq!(id, 1);
    let (id, _) = tunnel.open_stream(t0()).expect("开流");
    assert_eq!(id, 2);
    assert!(
        tunnel.watchdog().is_none(),
        "v1 下即便编号 >= 2 也不武装（参考 peerVersion >= 2）"
    );
}

#[test]
fn watchdog_rearms_on_every_new_stream_and_releases_the_previous_one() {
    let mut tunnel = handshaken();
    let (second, _) = tunnel.open_stream(t0()).expect("开流 2");
    assert_eq!(tunnel.watchdog().expect("武装").stream_id, second);
    let (third, _) = tunnel.open_stream(t0()).expect("开流 3");
    assert_eq!(
        tunnel.watchdog().expect("重新武装").stream_id,
        third,
        "参考在覆盖 synDone 前触发旧看门狗并换成新的"
    );
}

/// SYNACK 到达（无论成功或带错误文本）都解除看门狗——参考先 `synDone()` 再分支。
#[test]
fn synack_disarms_the_watchdog_before_any_error_branch() {
    let mut tunnel = handshaken();
    let (id, _) = tunnel.open_stream(t0()).expect("开流 2");
    assert!(tunnel.watchdog().is_some());
    let event = tunnel.accept(&syn_ack(id, Vec::new())).expect("确认");
    assert_eq!(event, Event::Ready(id));
    assert!(tunnel.watchdog().is_none(), "成功 SYNACK 解除看门狗");
    assert!(tunnel.stream_sendable(id));

    let (id2, _) = tunnel.open_stream(t0()).expect("开流 3");
    let event = tunnel
        .accept(&syn_ack(id2, b"dial failed".to_vec()))
        .expect("带错误的 SYNACK 不是协议违规");
    assert_eq!(event, Event::Rejected(id2));
    assert!(
        tunnel.watchdog().is_none(),
        "带错误文本的 SYNACK 也解除看门狗"
    );
    assert!(!tunnel.stream_sendable(id2), "被拒的流不可发送");
    assert!(tunnel.stream_sendable(1), "其他流不受影响");
}

/// 「SYNACK 迟到」= 看门狗已过期后才到达。参考此刻已 `Close()` 整条隧道，
/// 因此迟到帧必须被拒绝，而不是复活那条流。
#[test]
fn late_synack_after_expiry_is_rejected_and_tunnel_is_dead() {
    let mut tunnel = handshaken();
    let (id, _) = tunnel.open_stream(t0()).expect("开流 2");
    assert!(tunnel.expire_synack_watchdog(), "到期触发终止");
    assert!(tunnel.is_dead());
    assert_eq!(tunnel.watchdog(), None, "看门狗已消耗");
    assert!(!tunnel.expire_synack_watchdog(), "终止是幂等的");
    assert_eq!(
        tunnel.accept(&syn_ack(id, Vec::new())),
        Err(TunnelError::Dead)
    );
    assert_eq!(
        tunnel.open_stream(t0()).map(|pair| pair.0),
        Err(TunnelError::Dead),
        "死亡隧道不得再开流"
    );
}

#[test]
fn expiry_before_the_deadline_is_a_no_op_and_tunnel_stays_usable() {
    let mut tunnel = handshaken();
    let (id, _) = tunnel.open_stream(t0()).expect("开流 2");
    let watchdog = tunnel.watchdog().expect("武装");
    match watchdog.expiry {
        Expiry::Clock(deadline) => {
            assert!(!watchdog.expiry.is_due(deadline - Duration::from_millis(1)));
            assert!(watchdog.expiry.is_due(deadline));
            assert!(watchdog.expiry.is_due(deadline + Duration::from_secs(1)));
        }
        Expiry::Manual => panic!("武装时必须是挂了钟的"),
    }
    // 未到期时正常确认，隧道继续可用。
    tunnel.accept(&syn_ack(id, Vec::new())).expect("确认");
    assert!(!tunnel.is_dead());
}

/// 丢包：看门狗到期 → 隧道不可用 → 恢复必须换一条新隧道（参考回调只能 Close）。
#[test]
fn packet_loss_path_requires_a_fresh_tunnel_for_recovery() {
    let mut tunnel = handshaken();
    let (id, _) = tunnel.open_stream(t0()).expect("开流 2");
    assert!(tunnel.expire_synack_watchdog(), "SYNACK 丢失，看门狗到期");
    assert_eq!(
        tunnel.recover_needs_new_tunnel(t0() + Duration::from_secs(10)),
        Err(TunnelError::Dead)
    );

    // 重建：全新隧道从头握手，编号重新从 1 开始。
    let mut fresh = Tunnel::new(16).expect("容量合法");
    fresh.send_settings().expect("发送 Settings");
    let (first, _) = fresh.open_stream(t0()).expect("开流 1");
    assert_eq!(first, 1, "新隧道的编号空间是独立的");
    fresh.accept(&server_settings_v2()).expect("协商");
    fresh.accept(&syn_ack(1, Vec::new())).expect("确认");
    let (second, _) = fresh.open_stream(t0()).expect("开流 2");
    assert_eq!(second, 2);
    fresh.accept(&syn_ack(2, Vec::new())).expect("确认");
    assert!(fresh.stream_sendable(1) && fresh.stream_sendable(2));

    // 旧隧道已死，编号 2 的流不会再被承认。
    assert!(tunnel.accept(&syn_ack(id, Vec::new())).is_err());
}

/// 尚未武装看门狗时，`recover_needs_new_tunnel` 直接在原隧道开新流。
#[test]
fn recovery_without_a_pending_watchdog_just_opens_another_stream() {
    let mut tunnel = handshaken();
    let id = tunnel
        .recover_needs_new_tunnel(t0())
        .expect("无待决握手时可直接开流");
    assert_eq!(id, 2);
    assert!(!tunnel.is_dead());
}

/// 未就绪不得发送：v2 下必须等到成功 SYNACK（参考 `stream.Close()` 前的等待语义）。
#[test]
fn streams_are_not_sendable_before_a_successful_synack_in_version_two() {
    let mut tunnel = handshaken();
    let (id, _) = tunnel.open_stream(t0()).expect("开流 2");
    assert!(!tunnel.stream_sendable(id), "尚未收到 SYNACK");
    // 未就绪时服务器发数据是协议违规（沿用 client_state 的判定）。
    let push = Frame {
        command: Command::Push,
        stream_id: id,
        data: b"early".to_vec(),
    };
    assert!(tunnel.accept(&push).is_err());
}

#[test]
fn close_stream_releases_the_watchdog_for_that_stream() {
    let mut tunnel = handshaken();
    let (id, _) = tunnel.open_stream(t0()).expect("开流 2");
    assert!(tunnel.watchdog().is_some());
    let fin = tunnel.close_stream(id).expect("关闭该流");
    assert_eq!(fin.command, Command::Fin);
    assert_eq!(fin.stream_id, id);
    assert!(
        tunnel.watchdog().is_none(),
        "本端关闭后不再等待该流的 SYNACK"
    );
}

#[test]
fn server_fin_clears_readiness_without_touching_other_streams() {
    let mut tunnel = handshaken();
    let (second, _) = tunnel.open_stream(t0()).expect("开流 2");
    let (third, _) = tunnel.open_stream(t0()).expect("开流 3");
    tunnel.accept(&syn_ack(second, Vec::new())).expect("确认");
    tunnel.accept(&syn_ack(third, Vec::new())).expect("确认");
    let event = tunnel
        .accept(&Frame {
            command: Command::Fin,
            stream_id: second,
            data: Vec::new(),
        })
        .expect("服务器关闭");
    assert_eq!(event, Event::Closed(second));
    assert!(!tunnel.stream_sendable(second));
    assert!(tunnel.stream_sendable(third), "其他流不受影响");
    assert!(tunnel.stream_sendable(1));
}

#[test]
fn zero_capacity_and_missing_settings_are_reported_before_any_frame() {
    assert!(Tunnel::new(0).is_err(), "零容量非法");
    let mut tunnel = Tunnel::new(4).expect("容量合法");
    assert_eq!(
        tunnel.open_stream(t0()).map(|pair| pair.0),
        Err(TunnelError::State(
            lengsuo_anytls::client_state::ClientError::SettingsNotSent
        )),
        "参考把 Settings 缓冲在会话起点，未发出前不得开流"
    );
    assert!(tunnel.watchdog().is_none());
}
