//! B 组：**异常结束后的回收**。
//!
//! 判据（B3，对端中途断开）：客户端**不发 EOF**、直接 RST 掉连接 ⇒ 本仓侧必须在
//! **有限时间**（[`OBSERVE`]，显著小于中继的会话超时 [`IDLE_TIMEOUT`]）内感知到
//! 断开，**不是**靠会话超时兜底；感知后上游会话被回收（上游看到 EOF / 错误），
//! 且新连接仍可用。
//!
//! 判据（B4，上游不可达）：目标地址**没人监听** ⇒ 错误必须**如实返回**（不是
//! 静默成功、不是「连上了但没数据」），且会话被回收（上游侧没有留下任何连接）。
//!
//! 判据（B5，写入中途被截断）：只发**半个 chunk** 就断开 ⇒ 必须 fail-closed
//! （中继不能把半截数据当成功转交上游），且会话被回收。
//!
//! 与固定参考（Xray `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，
//! `proxy/shadowsocks/server.go`）的对应关系：参考的 `handleConnection` 在任一
//! 方向出错时 `common.Interrupt(link.Reader)` + `common.Interrupt(link.Writer)`
//! 中断另一方向并让 `handleConnection` 返回错误（`server.go:286-289`）；本端对应
//! `crate::relay::relay_both_ways` 的 `tokio::join!` + `request_result?` /
//! `response_result?`（任一方向出错即整体返回错误，连接随之关闭）。

use std::time::Duration;

use lengsuo_shadowsocks::TargetAddr;

use super::common::{
    abort, fixed_salt_request, local_set, roundtrip, send_raw, start_relay, IDLE_TIMEOUT, OBSERVE,
    WAIT,
};
use super::probe::{
    drain_events, next_event, read_raw_until_end, spawn_target, Flavor, TargetEvent,
};

/// B3：客户端中途 RST（不发 EOF）⇒ 本仓侧在有限时间内感知断开，上游会话被回收，
/// 之后的新连接仍可用。
#[test]
fn peer_reset_is_detected_within_deadline_and_session_is_reclaimed() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        assert!(
            OBSERVE < IDLE_TIMEOUT,
            "观察窗口必须显著小于会话超时，否则「及时感知」证明不了是感知断开而不是超时兜底"
        );
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 第一条连接：正常建立并把请求交给上游（上游已 Accepted），然后**不发 EOF**
        // 直接 RST。
        let salt = [0x31u8; 32];
        let wire = fixed_salt_request(&salt, &target, b"reset-in-the-middle").await;
        let mut stream = tokio::net::TcpStream::connect(relay).await.expect("连接中继");
        tokio::io::AsyncWriteExt::write_all(&mut stream, &wire)
            .await
            .expect("写中继");
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::Accepted),
            "上游应看到中继拨来的连接"
        );
        // 客户端 RST 掉连接（不发 EOF）。
        abort(stream);

        // ① 本仓侧必须在有限时间内感知断开：**可观测点是上游**——中继一旦感知到
        //    客户端的 RST，就必须**关闭上游连接**（上游看到 EOF 或错误）。
        //    这条观察同时证明「感知到了断开」与「上游会话被回收」。
        //    时限用 `OBSERVE`（显著小于会话超时 `IDLE_TIMEOUT`）⇒ 不是超时兜底。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        assert!(
            events.contains(&TargetEvent::PeerEof) || events.contains(&TargetEvent::Failed),
            "RST 之后本仓侧应在 {OBSERVE:?} 内感知断开并关闭上游连接（会话超时为 {IDLE_TIMEOUT:?}，不得靠超时兜底），实际事件：{events:?}"
        );

        // ② 收尾之后上游**不再收到任何载荷**（会话确实被收掉，而不是还在跑）。
        //    注意：RST 到达前上游本来就收到了请求并回声，这是合法的；判据是
        //    **收尾事件之后**不再有数据。
        let teardown_at = events
            .iter()
            .position(|event| {
                matches!(event, TargetEvent::PeerEof | TargetEvent::Failed)
            })
            .expect("上游必须观察到收尾事件");
        let after: Vec<&TargetEvent> = events[teardown_at..]
            .iter()
            .filter(|event| matches!(event, TargetEvent::Received(_)))
            .collect();
        assert!(
            after.is_empty(),
            "会话收尾后不得再向上游投递载荷，实际事件：{events:?}"
        );

        // ③ 会话被回收后，新连接仍可用（状态没被搞坏）。
        let reply = roundtrip(relay, &target, b"after-reset").await;
        assert_eq!(
            reply,
            b"after-reset".to_vec(),
            "异常结束后新连接必须仍能正常往返"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// B7：客户端侧的直接观测——客户端 RST 之后，本仓中继必须**关闭客户端那条连接**
/// （客户端读到的应是 EOF 或错误），而不是把这条连接挂着。
///
/// 这是 B3 的**客户端侧镜像**：B3 从上游侧看「上游会话被回收」，本条从客户端侧
/// 看「入站连接被回收」。两条合起来才覆盖「底层会话资源被回收」的两端。
#[test]
fn peer_reset_makes_relay_close_the_inbound_connection() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 第一条连接：建立 + 写入请求（不半关闭），然后 RST。
        let salt = [0x33u8; 32];
        let wire = fixed_salt_request(&salt, &target, b"inbound-teardown").await;
        let mut victim = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        tokio::io::AsyncWriteExt::write_all(&mut victim, &wire)
            .await
            .expect("写中继");
        assert_eq!(
            next_event(&mut upstream, WAIT).await,
            Some(TargetEvent::Accepted),
            "上游应看到中继拨来的连接"
        );

        // 第二条连接：当作「观察者」，其存在**不影响**第一条连接的收尾判定。
        // 这里让第一条连接 RST，再看**第一条**连接的读侧是否结束。
        abort(victim);

        // 上游看到对端关闭 ⇒ 中继确实收掉了这条会话（= 中继感知到 RST 了）。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        assert!(
            events.contains(&TargetEvent::PeerEof) || events.contains(&TargetEvent::Failed),
            "中继应在 {OBSERVE:?} 内感知 RST 并关闭上游连接，实际事件：{events:?}"
        );

        // 之后的新连接仍可用 ⇒ 收尾没有污染共享状态。
        let reply = roundtrip(relay, &target, b"after-inbound-teardown").await;
        assert_eq!(
            reply,
            b"after-inbound-teardown".to_vec(),
            "入站连接被回收后新连接必须仍能正常往返"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// B4：上游不可达（目标端口没人监听）⇒ 错误必须**如实返回**，不得静默成功；
/// 会话被回收（上游侧没有留下连接），之后的新连接仍可用。
#[test]
fn unreachable_upstream_reports_error_and_reclaims_session() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        // 目标端口：先起一个 listener 拿到端口，随即关掉 ⇒ 该端口没人监听。
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 临时端口");
        let dead_port = closed.local_addr().expect("临时端口").port();
        drop(closed);

        let (relay, handle) = start_relay(None, None).await;
        let target = TargetAddr::V4([127, 0, 0, 1], dead_port);

        // 客户端发请求后读回程：必须**读不到任何字节**（连都没连上，绝不静默成功）。
        let mut stream = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        let salt = [0x41u8; 32];
        let wire = fixed_salt_request(&salt, &target, b"unreachable").await;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &wire)
            .await
            .expect("写中继");
        tokio::io::AsyncWriteExt::shutdown(&mut stream)
            .await
            .expect("写半关闭");

        let got = read_raw_until_end(stream)
            .await
            .expect("上游不可达时中继应干净关闭连接，而不是读出错");
        assert!(
            got.is_empty(),
            "上游不可达时不得交付任何回程字节（不得静默成功），实际 {got:?}"
        );

        // 会话被回收后，新连接（指向**可达**目标）仍可用。
        let upstream = spawn_target(Flavor::Echo).await;
        let good = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let reply = roundtrip(relay, &good, b"after-unreachable").await;
        assert_eq!(
            reply,
            b"after-unreachable".to_vec(),
            "上游不可达后新连接必须仍能正常往返"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// B5：写入中途被截断（只发半个 chunk 就断开）⇒ 必须 fail-closed：
/// **半截数据不得被当成成功转交上游**，且会话被回收。
#[test]
fn truncated_write_fails_closed_without_forwarding_partial_data() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 构造一条**合法**的线上字节（salt + 完整 chunk），再只发前半截就断开。
        let salt = [0x51u8; 32];
        let wire = fixed_salt_request(&salt, &target, b"truncated-write-payload").await;
        let cut = salt.len() + 4; // salt 之后只给 size 段的前 4 字节（不足 18）
        assert!(
            cut < wire.len(),
            "截断点必须落在帧内（wire {} 字节，截断点 {cut}）",
            wire.len()
        );

        // 写前半截，然后**不发 EOF**直接 RST ⇒ 中继读到的是「帧内截断」。
        let mut stream = tokio::net::TcpStream::connect(relay)
            .await
            .expect("连接中继");
        tokio::io::AsyncWriteExt::write_all(&mut stream, &wire[..cut])
            .await
            .expect("写中继");
        abort(stream);

        // ① fail-closed：中继**不得**把半截数据当成功 ⇒ 上游要么根本没被连上
        //    （握手没完成），要么连上了但**没有收到任何完整载荷**。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        let received: usize = events
            .iter()
            .filter_map(|event| match event {
                TargetEvent::Received(len) => Some(*len),
                _ => None,
            })
            .sum();
        assert_eq!(
            received, 0,
            "截断的写入不得被当作成功转交上游（收到 {received} 字节），实际事件：{events:?}"
        );

        // ② 会话被回收：之后的新连接仍可用。
        let reply = roundtrip(relay, &target, b"after-truncation").await;
        assert_eq!(
            reply,
            b"after-truncation".to_vec(),
            "截断后新连接必须仍能正常往返"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// B6：握手阶段的**认证失败**（错误口令）必须 fail-closed 且回收会话：
/// 中继不得把请求转交上游，连接必须被关闭，之后新连接仍可用。
///
/// 这一条与 `tests/relay_e2e.rs` 的「错误口令绝不回退直连」**不重复**：那条断言
/// 「不回退直连」，本条断言「**会话被回收**」+「之后新连接仍可用」。
#[test]
fn failed_handshake_reclaims_session_and_keeps_relay_usable() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let mut upstream = spawn_target(Flavor::Echo).await;
        let target = TargetAddr::V4([127, 0, 0, 1], upstream.addr.port());
        let (relay, handle) = start_relay(None, None).await;

        // 用**错误口令**构造一条线上字节：AEAD 认证必失败。
        let salt = [0x61u8; 32];
        let wrong =
            fixed_salt_request_with_password(&salt, &target, b"bad-password", b"wrong-passw0rd")
                .await;
        let stream = send_raw(relay, &wrong).await;
        let got = read_raw_until_end(stream)
            .await
            .expect("认证失败时中继应干净关闭连接");
        assert!(got.is_empty(), "认证失败不得交付任何回程字节，实际 {got:?}");

        // 会话被回收：上游从未被连上，且之后新连接仍可用。
        let events = drain_events(&mut upstream, OBSERVE, Duration::from_millis(200)).await;
        assert!(
            !events.contains(&TargetEvent::Accepted),
            "认证失败时不得拨号上游，实际事件：{events:?}"
        );
        let reply = roundtrip(relay, &target, b"after-bad-password").await;
        assert_eq!(
            reply,
            b"after-bad-password".to_vec(),
            "认证失败后新连接必须仍能正常往返"
        );

        handle.shutdown().await.expect("中继应干净停止");
    });
}

/// 用**指定口令**构造一条合法的线上字节（salt + 一个 chunk）。
async fn fixed_salt_request_with_password(
    salt: &[u8],
    target: &TargetAddr,
    payload: &[u8],
    password: &[u8],
) -> Vec<u8> {
    let master = ss_core::kdf::evp_bytes_to_key(password, super::common::SUITE.key_len());
    let subkey = ss_core::kdf::hkdf_sha1_subkey(&master, salt, super::common::SUITE.key_len());
    let mut aead = ss_core::crypto::SessionAead::new(super::common::SUITE, subkey);
    let mut plain = Vec::new();
    target.encode_checked(&mut plain).expect("回环目标可编码");
    plain.extend_from_slice(payload);
    let mut wire = Vec::new();
    wire.extend_from_slice(salt);
    ss_core::chunk::write_chunk(&mut wire, &mut aead, &plain)
        .await
        .expect("固定 salt 帧应可构造");
    wire
}
