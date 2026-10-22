//! C 组：**回收不误伤**。
//!
//! 判据（C6）：一条连接**异常结束**后，**其它并行连接**仍能正常往返 ⇒ 证明清理是
//! **按连接维度**的（不是全局一刀切：不是「一条出错就整体停摆」，也不是「把共享
//! 状态清空」）。
//!
//! 判据（C7）：relay 关闭（listener 停止接受新连接）后——
//!
//! - **已建立的连接按实现的真实语义收尾**：本端 `RelayHandle::shutdown` 会
//!   `JoinSet::shutdown` ⇒ **abort** 尚未完成的连接任务 ⇒ 在途连接被**立即中断**
//!   （不是排空）。**实现真实语义 = 立即中断**（详见报告与
//!   `docs/shadowsocks-status.md`）。
//! - **listener 关闭后不残留占用端口**：用 `/proc/net/tcp` 的 LISTEN 状态 + 同端口
//!   重新 bind 双重验证（仅 Linux；其它平台用「连接数归零」的可观测手段）。
//!
//! 与固定参考（Xray `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）的关系：参考的
//! `handleConnection` 在任一方向出错时 `common.Interrupt(link.Reader)` +
//! `common.Interrupt(link.Writer)`（`server.go:286-289`）——**只中断本连接**的
//! 上下游，不影响其它连接；本组 C6 断言的就是这一条「按连接维度」的语义。

use std::time::Duration;

use lengsuo_shadowsocks::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::common::{
    abort, local_set, read_one_chunk, roundtrip, start_relay, write_request, OBSERVE, WAIT,
};
use super::probe::{
    drain_events, next_event, port_has_listener, read_raw_until_end, spawn_target, Flavor,
    TargetEvent,
};
use super::proc::{
    assert_reclaimed, baseline, roundtrip_with_password, runtime_password, serial_guard,
    start_relay_with_password,
};

/// C6：一条连接异常结束（客户端 RST）后，另一条**并行**连接仍能正常往返。
#[test]
fn abnormal_close_of_one_connection_does_not_affect_others() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 连接 1：保持打开（不半关闭），并让它**异常结束**（RST）。
        let mut victim = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        write_request(&mut victim, &target, b"victim").await;
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::Accepted),
            "上游应看到第一条连接"
        );

        // 连接 2：正常建立并保持打开。
        let mut survivor = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        write_request(&mut survivor, &target, b"survivor").await;

        // 现在让连接 1 异常结束（RST，不发 EOF）。
        abort(victim);

        // ① 连接 2 仍能正常往返（**并行连接不受影响** ⇒ 清理是按连接维度的）。
        let reply = read_one_chunk(&mut survivor)
            .await
            .expect("并行连接必须仍能收到回程数据（清理不得误伤其它连接）");
        assert_eq!(reply, b"survivor".to_vec(), "并行连接的回程必须与载荷一致");

        // ② 中继仍然活着：再开一条**全新**连接也能正常往返。
        let reply = roundtrip(relay, &target, b"after-victim").await;
        assert_eq!(
            reply,
            b"after-victim".to_vec(),
            "一条连接异常结束后，全新连接必须仍能正常往返"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// C7：relay 关闭后，在途连接按**实现的真实语义**收尾，且 listener 端口不残留占用。
#[test]
fn relay_shutdown_interrupts_inflight_connections_and_frees_the_port() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let upstream = spawn_target(Flavor::Hold).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;
        let port = relay.port();

        // 建立一条在途连接：请求已交给上游，上游**持住**连接不返回。
        let mut inflight = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        write_request(&mut inflight, &target, b"inflight").await;

        // 关闭 relay：实现语义是**立即中断**在途连接（`JoinSet::shutdown` abort）。
        handle.shutdown().await.expect("中继应干净停止");

        // ① 在途连接必须**在有限时间内**结束（读到 EOF 或错误）——不能永远挂着。
        //    语义说明：本端不是「排空」，而是**立即中断**（与参考的
        //    `common.Interrupt` 方向一致）。
        let mut buffer = [0u8; 4096];
        let ended = tokio::time::timeout(OBSERVE, inflight.read(&mut buffer)).await;
        assert!(
            ended.is_ok(),
            "relay 关闭后，在途连接必须在 {OBSERVE:?} 内结束（实现语义：立即中断，不是排空）"
        );

        // ② listener 端口不再被占用：LISTEN 状态消失 + 同端口可重新 bind。
        if let Some(has_listener) = port_has_listener(port) {
            assert!(
                !has_listener,
                "relay 关闭后端口 {port} 上不应残留 LISTEN 套接字"
            );
        }
        let rebound = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(
            rebound.is_ok(),
            "relay 关闭后端口 {port} 应可重新 bind：{:?}",
            rebound.err()
        );
        drop(rebound);
    });
}

/// C8：relay 关闭后，**新连接**必须被拒（listener 已停止接受）⇒ 证明关闭是真的
/// 关了 listener，而不是「还在 accept 但不做事」。
#[test]
fn relay_shutdown_refuses_new_connections() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 关闭前：连接正常。
        let reply = roundtrip(relay, &target, b"before-shutdown").await;
        assert_eq!(reply, b"before-shutdown".to_vec(), "关闭前应能正常往返");

        handle.shutdown().await.expect("中继应干净停止");

        // 关闭后：新连接必须失败（连不上，或连上后立刻被关）。
        let outcome = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(relay)).await;
        match outcome {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(stream)) => {
                // 连上了也必须立刻结束（不得交付任何字节）。
                let got = read_raw_until_end(stream).await.unwrap_or_default();
                assert!(
                    got.is_empty(),
                    "relay 关闭后新连接不得拿到任何数据，实际 {got:?}"
                );
            }
        }
    });
}

/// C9：一条连接的异常结束**不得**清空共享的 salt 记忆池状态 ⇒ 另一条连接用**同一个
/// salt** 仍会被判重放（清理不误伤：不是「一刀切清空」）。
#[test]
fn abnormal_close_does_not_clear_shared_salt_pool_state() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let dir = super::common::TempDir::new("isolation-c9");
        let state = dir.path().join("salt-state.bin");
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(Some((64, Duration::from_secs(600))), Some(&state)).await;

        // 连接 1：用固定 salt 建立连接（记忆池记下它），然后**异常结束**。
        let salt = [0x71u8; 32];
        let wire = super::common::fixed_salt_request(&salt, &target, b"first").await;
        let mut victim = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        victim.write_all(&wire).await.expect("写中继");
        // 等上游看到连接 ⇒ 证明中继已经认证并记录了这个 salt（消除竞态）。
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::Accepted),
            "上游应看到第一条连接（中继已完成握手并记录 salt）"
        );
        abort(victim);

        // 连接 2：用**同一个 salt** ⇒ 必须仍被判重放（记忆池没被清空）。
        let wire = super::common::fixed_salt_request(&salt, &target, b"second").await;
        let stream = super::common::send_raw(relay, &wire).await;
        let got = read_raw_until_end(stream)
            .await
            .expect("重放连接应被干净关闭");
        assert!(
            got.is_empty(),
            "异常结束不得清空记忆池：同 salt 仍应被判重放（不得交付任何字节），实际 {got:?}"
        );

        // 且其它并行连接不受影响（用新 salt 的正常连接）。
        let reply = roundtrip(relay, &target, b"third").await;
        assert_eq!(reply, b"third".to_vec(), "异常结束后其它连接必须仍可用");

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// C10：多条连接**并发**正常往返后，**全部**收尾 ⇒ 上游侧每条连接都被回收
/// （会话资源按连接维度一一对应，不多不少）。
#[test]
fn all_connections_are_reclaimed_after_concurrent_roundtrips() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 三条连接依次完成完整往返。
        for index in 0..3u8 {
            let payload = format!("concurrent-{index}").into_bytes();
            let reply = roundtrip(relay, &target, &payload).await;
            assert_eq!(reply, payload, "第 {index} 条连接的回程应一致");
        }

        // 上游侧：恰好三次 Accepted、恰好三次 PeerEof（三条会话都被回收）。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        let accepted = events
            .iter()
            .filter(|event| **event == TargetEvent::Accepted)
            .count();
        let eofs = events
            .iter()
            .filter(|event| **event == TargetEvent::PeerEof)
            .count();
        assert_eq!(accepted, 3, "上游应恰好看到三条连接，实际事件：{events:?}");
        assert_eq!(
            eofs, 3,
            "三条连接都应被回收（上游各看到一次 EOF），实际事件：{events:?}"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// C11（**进程级资源回收**）：**多条连接**全部收尾后，fd 数与线程数回落到基线。
///
/// 为什么单列一条：A7 / B11 只覆盖**单条**连接的回收。这条证明**资源按连接
/// 维度**回收——N 条连接收尾后，残留的 fd 数**不随连接条数增长**（不是「每条
/// 连接漏一个 fd」：那样 4 条连接就会比基线多 4 个 fd，直接被断言抓住）。
///
/// 判据：基线（中继已启动、尚无本用例的连接）→ 4 条连接依次完整往返（每条都
/// 读到干净 EOF ⇒ 会话被回收）→ 再取读数 ⇒ fd 数 ≤ 基线 + 0、线程数 ≤ 基线 + 0。
#[test]
fn repeated_connections_reclaim_process_level_file_descriptors_and_threads() {
    let _guard = serial_guard();

    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        // 运行时生成的**假口令**（与任何生产凭据无关）。
        let password = runtime_password();
        let upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay_with_password(&password).await;

        // ① 基线：中继已在跑、本用例还没建连接。
        let base = baseline().await;

        // ② 四条连接依次完整往返（每条都读到干净 EOF ⇒ 会话被回收）。
        for index in 0..4u8 {
            let payload = format!("resource-{index}").into_bytes();
            let reply = roundtrip_with_password(relay, &target, &payload, &password).await;
            assert_eq!(reply, payload, "第 {index} 条连接的回程应一致");
        }

        // ③ 全部收尾 ⇒ 资源必须回落到基线（残留不随连接条数增长）。
        assert_reclaimed(base, "C11 多条连接收尾后").await;

        handle.shutdown().await.expect("中继应干净停止");
    });
}
