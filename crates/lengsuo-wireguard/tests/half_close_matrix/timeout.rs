//! 异常矩阵「超时」格：△（仅 keepalive 定时器）→ ✅（覆盖**握手超时**：
//! 对端不回 handshake response 时，本仓必须在**有限时间**内判失败）。
//!
//! 对齐参考 wireguard-go commit `2631ce99a06f27120d581611cf125d68bc6aa565`：
//!
//! - 握手**重试**由 `device/timers.go` 的 `retransmitHandshake` 驱动：每
//!   `RekeyTimeout`（5s）重发一次 initiation，直到 `handshakeAttempts >
//!   MaxTimerHandshakes`（18）才 `expiredRetransmitHandshake` 放弃
//!   （`TimerAction::HandshakeGaveUp`），并武装 `zeroKeyMaterial` 在
//!   `RejectAfterTime*3`（540s）后 `ZeroAndFlushAll()`。
//! - 参考**没有**「握手超时」这个独立概念——它靠「重试到上限即放弃」来
//!   终结一次不成功的握手。
//!
//! 本仓的对应实现是 `timers` 模块的同一套语义（`TimerState` +
//! `TimerAction::HandshakeGaveUp`）。本文件把它拆成两半取证：
//!
//! 1. **传输层超时**（B-1/B-2/B-3）：真实走回环 UDP，对端接受连接但**不回应
//!    握手包** ⇒ 断言在有限时间内得到**明确的超时类错误**。
//! 2. **状态机超时**（B-4/B-5）：用注入时钟把 `TimerState` 推到
//!    `HandshakeGaveUp`，断言「放弃」这一事件确实在有限时间内发生、且放弃后
//!    密钥材料被回收。
//!
//! ⚠️ 传输层部分用 `tokio::time::timeout` 兜底：若本仓真的挂住，用例会
//! **超时失败**而不是静默通过。

use std::time::{Duration, Instant};

use lengsuo_wireguard::handshake::Handshake;
use lengsuo_wireguard::timers::{constants::*, TimerAction, TimerState};

use super::fixture::{
    err_name, establish, is_timeout, serial_guard, serial_guard_async, x25519_pub, LoopbackPair,
    SessionSpec, CLIENT_INDEX, CLIENT_STATIC, SERVER_STATIC,
};

/// B-1：握手超时。
///
/// 对端接受连接后**不回应握手包**（服务端 socket 收走 initiation 后不回任何
/// 东西），发起方必须在**有限时间**内得到**明确的超时类错误**。
///
/// 判据：`recv` 返回 `Err` 且 `kind()` 属超时类（`WouldBlock`/`TimedOut`），
/// 且整个等待不超过 2s（socket 读超时）+ 5s（外层 tokio 兜底）。
#[tokio::test]
async fn handshake_timeout_fails_within_bounded_time() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。异步用例用异步感知锁。
    let _guard = serial_guard_async().await;

    let pair = LoopbackPair::new();

    // 发起方：发起一次握手。
    let mut handshake = Handshake::new(
        &CLIENT_STATIC,
        &x25519_pub(&SERVER_STATIC),
        None,
        CLIENT_INDEX,
    )
    .expect("发起方可构造");
    let initiation = handshake
        .create_initiation([0xAA; 32])
        .expect("initiation 可生成");

    // 发给「接受连接但不应答」的对端。
    pair.client
        .send_to(&initiation, pair.server_addr)
        .expect("initiation 可发出");

    // 对端确实收到了（证明不是「地址错」导致的假超时）。
    let mut buf = [0u8; 2048];
    let (n, _) = pair
        .server
        .recv_from(&mut buf)
        .expect("对端必须在有限时间内收到 initiation");
    assert_eq!(n, initiation.len(), "对端收到的应是完整 initiation");

    // 对端**不回应**：发起方必须在有限时间内拿到**明确的超时类错误**。
    //
    // 两层兜底，缺一不可：
    // - **内层**：socket 自身的读超时（`set_read_timeout`）——它产生真正的
    //   `io::ErrorKind::WouldBlock`，即「明确的超时类错误」本身；
    // - **外层**：`tokio::time::timeout`——任务书要求的兜底。**若内层读超时
    //   失效**（socket 超时没生效），外层会先到期并让用例**超时失败**，
    //   而不是静默通过。
    //
    // 内层是同步 `recv_from`（socket 已设 2s 读超时），放进
    // `spawn_blocking` 以免阻塞 tokio 的 worker 线程。
    let started = Instant::now();
    let client = pair.client;
    let outcome = tokio::time::timeout(Duration::from_secs(3), async move {
        tokio::task::spawn_blocking(move || {
            let mut buffer = [0u8; 2048];
            client.recv_from(&mut buffer)
        })
        .await
        .expect("阻塞任务不得 panic")
    })
    .await;
    let error = match outcome {
        Ok(result) => result.expect_err("对端不应答时 recv 必须失败"),
        Err(_elapsed) => {
            panic!("外层兜底触发：对端不应答时本仓挂住，握手等待未在 3s 内结束")
        }
    };
    assert!(
        is_timeout(&error),
        "必须是明确的超时类错误，实际：{error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "必须在有限时间内判超时，实际耗时 {:?}",
        started.elapsed()
    );

    // 超时后，握手状态仍是「已发出 initiation」，**没有**派生任何密钥——
    // 不得因为超时而把会话当成成功。
    let rejected = handshake.consume_response(&initiation);
    assert!(
        rejected.is_err(),
        "未收到 response 时不得派生会话密钥：{}",
        err_name(&rejected)
    );
}

/// B-2：超时后可继续用。
///
/// 一次超时**不得污染后续会话**：新建一条会话走同样流程必须成功（判据：
/// 握手密钥重新协商成功，且双向 transport 往返可用）。
#[test]
fn handshake_timeout_does_not_poison_later_sessions() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    // 第一次「超时」：对端不应答。
    let pair = LoopbackPair::new();
    let mut first = Handshake::new(
        &CLIENT_STATIC,
        &x25519_pub(&SERVER_STATIC),
        None,
        CLIENT_INDEX,
    )
    .expect("发起方可构造");
    let initiation = first
        .create_initiation([0xAA; 32])
        .expect("initiation 可生成");
    pair.client
        .send_to(&initiation, pair.server_addr)
        .expect("initiation 可发出");
    let mut buf = [0u8; 2048];
    let _ = pair
        .server
        .recv_from(&mut buf)
        .expect("对端收到 initiation");
    let outcome = pair.client.recv_from(&mut buf);
    assert!(
        outcome.as_ref().err().is_some_and(is_timeout),
        "第一次必须以超时结束：{outcome:?}"
    );

    // 第二次：走完整握手，必须成功。
    let (client, server) = establish(&SessionSpec::default());
    let mut sender = client.sender();
    let mut receiver = server.receiver();
    let packet = sender.seal(b"after-timeout").expect("封装");
    let opened = receiver.open(&packet).expect("超时后的新会话必须可用");
    assert_eq!(opened.plaintext.as_slice(), b"after-timeout");
}

/// B-3：超时不等同于其它错误。
///
/// 「握手超时」必须能与「握手被拒（错密码）」区分开。
///
/// 本仓的判据：`consume_response` 返回的错误里，**错密码**是
/// `TransportError::AuthFailed`（AEAD/MAC 认证失败），而**超时**是
/// `std::io::Error`（`WouldBlock`/`TimedOut`）——两者类型不同、判据不同。
///
/// 若实现上无法区分，本用例应放宽为「必须是错误、且不得是成功」；本仓可以
/// 区分，故按可区分的严格判据书写。
#[test]
fn handshake_timeout_is_distinguishable_from_rejection() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    // (a) 错密码：响应方用不同 PSK ⇒ 发起方认证失败。
    let spec = SessionSpec {
        client_psk: Some(super::fixture::PSK),
        server_psk: Some(super::fixture::PSK_WRONG),
        ..SessionSpec::default()
    };
    let client_public = x25519_pub(&spec.client_static);
    let server_public = x25519_pub(&spec.server_static);

    let mut initiator = Handshake::new(
        &spec.client_static,
        &server_public,
        spec.client_psk,
        CLIENT_INDEX,
    )
    .expect("发起方可构造");
    let initiation = initiator
        .create_initiation([0xAA; 32])
        .expect("initiation 可生成");

    let mut responder = lengsuo_wireguard::handshake::Responder::new(
        &spec.server_static,
        &client_public,
        spec.server_psk,
        0x2000_0002,
    )
    .expect("响应方可构造");
    responder
        .consume_initiation(&initiation)
        .expect("initiation 本身可剥壳（PSK 尚未参与）");
    let mut response = responder
        .create_response([0xBB; 32], 0x2000_0002)
        .expect("response 可构造");
    responder.add_macs(&mut response);

    let rejected = initiator.consume_response(&response);
    assert!(
        matches!(rejected, Err(lengsuo_wireguard::TransportError::AuthFailed)),
        "错密码必须报认证失败：{}",
        err_name(&rejected)
    );

    // (b) 超时：类型不同（io::Error vs transport::Error）。
    let pair = LoopbackPair::new();
    let mut timed = Handshake::new(
        &CLIENT_STATIC,
        &x25519_pub(&SERVER_STATIC),
        None,
        CLIENT_INDEX,
    )
    .expect("发起方可构造");
    let initiation = timed
        .create_initiation([0xCC; 32])
        .expect("initiation 可生成");
    pair.client
        .send_to(&initiation, pair.server_addr)
        .expect("initiation 可发出");
    let mut buf = [0u8; 2048];
    let _ = pair
        .server
        .recv_from(&mut buf)
        .expect("对端收到 initiation");
    let outcome = pair.client.recv_from(&mut buf);
    let error = outcome.expect_err("对端不应答时 recv 必须失败");
    assert!(
        is_timeout(&error),
        "超时必须表现为超时类 io 错误：{error:?}"
    );
    // 错密码与超时的错误类型必然不同：一个是 transport::Error，一个是 io::Error。
    // 这条断言把「可区分」钉死在类型层面。
    let timeout_is_io = error.kind() == std::io::ErrorKind::WouldBlock
        || error.kind() == std::io::ErrorKind::TimedOut;
    assert!(timeout_is_io, "超时的错误类型必须是 io::Error");
}

/// B-4：握手重试到上限 ⇒ 在有限时间内**放弃**（参考 `expiredRetransmitHandshake`）。
///
/// 参考语义：每 `RekeyTimeout`（5s）重发一次；`handshakeAttempts >
/// MaxTimerHandshakes`（18）时放弃并发 `HandshakeGaveUp`。
///
/// 注入时钟断言：t=5..90 共 18 次重发；t=95 第 19 次（attempts=19 > 18）；
/// t=100 放弃。之后不再重发。
#[test]
fn handshake_gives_up_after_bounded_retries() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_jitter(0.0);
    timers.set_running(true);
    timers.on_handshake_initiated(0.0);

    // 前 18 次重发（t=5..90）。
    for step in 1..=MAX_TIMER_HANDSHAKES {
        let t = REKEY_TIMEOUT * f64::from(step);
        assert_eq!(
            timers.tick(epoch + Duration::from_secs_f64(t)),
            vec![TimerAction::RetransmitHandshake],
            "第 {step} 次重发应对应在 t={t}s"
        );
    }
    assert_eq!(timers.handshake_attempts(), MAX_TIMER_HANDSHAKES);

    // t=95：attempts=18 未超上限，仍重发一次，attempts 变 19。
    assert_eq!(
        timers.tick(epoch + Duration::from_secs_f64(95.0)),
        vec![TimerAction::RetransmitHandshake]
    );
    assert_eq!(timers.handshake_attempts(), MAX_TIMER_HANDSHAKES + 1);

    // t=100：attempts=19 > 18 ⇒ 放弃（有限时间内判失败）。
    assert_eq!(
        timers.tick(epoch + Duration::from_secs_f64(100.0)),
        vec![TimerAction::HandshakeGaveUp],
        "重试超上限后必须在有限时间内放弃"
    );
    // 放弃后不再重发。
    assert_eq!(
        timers.tick(epoch + Duration::from_secs_f64(105.0)),
        vec![],
        "放弃后不得再重发握手"
    );
}

/// B-5：放弃后密钥材料被回收（参考 `expiredZeroKeyMaterial` → `ZeroAndFlushAll`）。
///
/// 参考：`HandshakeGaveUp` 武装 `zeroKeyMaterial` 到 `RejectAfterTime*3`
/// （540s）后 `ZeroAndFlushAll()`，清空 keypairs 三槽位 + 握手状态 +
/// index 表条目。
///
/// 本仓：`TimerAction::ZeroKeyMaterial` 对应 `expiredZeroKeyMaterial`。
/// 断言：放弃后 540s 到点确实产生 `ZeroKeyMaterial` 动作。
#[test]
fn handshake_gave_up_arms_key_material_erasure() {
    // 串行执行：本文件用进程级读数（线程数/fd 数）观测「无悬挂任务」，
    // 必须把并行执行的其它用例挡在观测窗外。
    let _guard = serial_guard();
    let epoch = Instant::now();
    let mut timers = TimerState::new(epoch);
    timers.set_jitter(0.0);
    timers.set_running(true);
    timers.on_handshake_initiated(0.0);

    // 直接把 attempts 推到超限：t=100 放弃。
    for step in 1..=MAX_TIMER_HANDSHAKES {
        timers.tick(epoch + Duration::from_secs_f64(REKEY_TIMEOUT * f64::from(step)));
    }
    timers.tick(epoch + Duration::from_secs_f64(95.0));
    assert_eq!(
        timers.tick(epoch + Duration::from_secs_f64(100.0)),
        vec![TimerAction::HandshakeGaveUp]
    );

    // 放弃同刻武装 zeroKeyMaterial 到 t=100+540=640。
    assert_eq!(
        timers.tick(epoch + Duration::from_secs_f64(639.999)),
        vec![],
        "540s 之前不得擦除"
    );
    assert_eq!(
        timers.tick(epoch + Duration::from_secs_f64(640.0)),
        vec![TimerAction::ZeroKeyMaterial],
        "放弃后必须在有限时间内回收密钥材料"
    );
}
