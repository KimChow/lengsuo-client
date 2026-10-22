//! VLESS **XEL 记录层**与 **Mux 承载**接进 node 出站产品路径的**实跑取证**
//! （Rust↔Rust 回环）。
//!
//! 对端是**本仓**协议 crate 的服务端原语（`lengsuo_vless::xel_wire` /
//! `lengsuo_vless::mux::worker`，编排见 `vless_xel_mux_loopback/support.rs`），
//! 客户端是 **node 的 VLESS 出口**（`lengsuo_node::outbound_vless::dial_vless`，
//! 走新加的 `xel` / `mux` 配置段）。
//!
//! ```text
//! node 侧：NodeConfig.xel  → XelStream（记录层）→ VLESS 请求头 + 成功响应头 → 载荷往返
//!        NodeConfig.mux  → MuxSessionIo（承载）  → 先发 mux 帧 → 读帧流时消费响应头
//! 服务端：TLS → 解 VLESS 请求头 → 写响应头 → 回环写下行
//! ```
//!
//! 覆盖八组：
//! 1. **XEL 正例**：握手成功 + 拿到成功响应头 + 载荷往返逐字节一致（**双向**）。
//! 2. **XEL 负例**：错密钥 ⇒ AEAD 认证失败 ⇒ 拨号失败（fail-closed，**不得**
//!    回落到明文、不得静默成功）。
//! 3. **XEL 负例**：配置非法 ⇒ **在建立 TCP/TLS 之前**就失败（**一条字节都不发**）。
//! 4. **XEL 负例**：载荷篡改（**记录层**里翻一个字节）⇒ 对端必须检出并断连。
//! 5. **Mux 正例**：单会话往返。
//! 6. **Mux 正例**：多会话隔离（同一条承载开两条会话，互不串扰）。
//! 7. **Mux 负例**：承载断开 ⇒ 所有逻辑会话必须失败（**不得**静默挂住）。
//! 8. **Mux 顺序**：承载上**先发 mux 帧**、再在读帧流时消费响应头（参考的
//!    `SetFlushNext()` 时序；先阻塞等响应头就是死锁）。
//!
//! **本文件只覆盖 Rust↔Rust 回环**，⛔ 不声称与参考实现互通。参考侧（固定版本
//! Xray）在**库层**已有真实对端证据（`crates/lengsuo-vless/tests/xray_vision.rs`）；
//! **node 侧**与参考对端的互通**尚未验证**（见本卡报告偏离清单）。

#[path = "vless_xel_mux_loopback/support.rs"]
mod support;

use std::time::Duration;

use lengsuo_node::outbound_vless::{dial_vless, VlessStream};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use support::{
    accept_only_watcher, server_fixture, spawn_mux_peer, vless_node, xel_section, DEADLINE, KEY,
    PAYLOAD, TAMPER_OFFSET, WAIT, XEL_DOWNLINK_HEX, XEL_SERVER_DOWNLINK_HEX, XEL_SERVER_UPLINK_HEX,
    XEL_UPLINK_HEX, XEL_WRONG_HEX,
};

/// 多会话隔离用例的 A 会话载荷（与 B 会话载荷互不相同且互不含对方）。
const PAYLOAD_A: &[u8] = b"session-A-marker-payload";
/// 多会话隔离用例的 B 会话载荷。
const PAYLOAD_B: &[u8] = b"session-B-marker-payload";

/// **1. XEL 正例**：node 的 VLESS 出口经 XEL 记录层连上本仓 XEL 服务端，
/// 握手成功、拿到成功响应头（`[0, 0]`）、载荷往返逐字节一致（**双向**）。
///
/// 认证判据与 Vision 侧**一致**：只有拿到成功响应头才算认证完成。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_roundtrip_to_own_server() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(
            port,
            &ca_pem,
            Some(xel_section(XEL_UPLINK_HEX, XEL_DOWNLINK_HEX)),
            false,
        );
        assert!(node.validate().is_ok(), "配置应通过校验");

        let (client, server) = tokio::join!(
            async {
                let mut outbound = dial_vless(&node, WAIT)
                    .await
                    .expect("XEL 建流 + 握手应成功");
                assert!(
                    matches!(outbound.stream, VlessStream::Xel(_)),
                    "承载应是 XEL 记录层"
                );
                outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
                let mut received = vec![0u8; PAYLOAD.len()];
                timeout(WAIT, outbound.stream.read_exact(&mut received))
                    .await
                    .expect("读回环载荷超时")
                    .expect("读回环载荷失败");
                received
            },
            support::serve_xel(
                fixture,
                KEY,
                XEL_SERVER_UPLINK_HEX,
                XEL_SERVER_DOWNLINK_HEX,
                PAYLOAD.len(),
                None,
            ),
        );
        assert_eq!(client, PAYLOAD, "下行回环载荷必须逐字节一致");
        assert_eq!(
            server.expect("服务端"),
            PAYLOAD,
            "服务端解出的上行明文必须逐字节一致"
        );
        println!("VLESS+XEL 记录层贯通：{} 字节逐字节一致", client.len());
    })
    .await
    .expect("用例总超时");
}

/// **2. XEL 负例**：错密钥 ⇒ 记录层 AEAD 认证失败 ⇒ 拨号失败（fail-closed）。
///
/// 客户端的上行密钥与服务端的下行密钥不匹配 ⇒ 服务端解不开请求头 ⇒ 服务端
/// 断开、**不**回成功响应头 ⇒ node 侧拨号必须失败；⛔ **不得**回落到明文、
/// **不得**把没认证的连接交出去。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_wrong_key_fails_closed() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        // 客户端上行密钥用错的 ⇒ 与服务端下行密钥不匹配。
        let node = vless_node(
            port,
            &ca_pem,
            Some(xel_section(XEL_WRONG_HEX, XEL_DOWNLINK_HEX)),
            false,
        );

        let (result, server) = tokio::join!(
            async { dial_vless(&node, WAIT).await.map(|_| ()) },
            support::serve_xel(
                fixture,
                KEY,
                XEL_SERVER_UPLINK_HEX,
                XEL_SERVER_DOWNLINK_HEX,
                PAYLOAD.len(),
                None,
            ),
        );
        assert!(
            result.is_err(),
            "错密钥必须失败（不得静默成功、不得回落到明文）"
        );
        assert!(
            server.is_err(),
            "服务端必须因 AEAD 认证失败而拒绝：{:?}",
            server.err()
        );
    })
    .await
    .expect("用例总超时");
}

/// **3. XEL 负例**：XEL 配置非法（密钥长度不符）⇒ **在建立 TCP/TLS 之前**失败。
///
/// 判据：`outbound_vless_xel::precheck` 先失败 ⇒ **一条字节都不发**（连 TCP
/// 都不拨）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_bad_config_fails_closed_without_connect() {
    timeout(DEADLINE, async {
        let (port, accepted, watcher) = accept_only_watcher().await;
        // 16 字节密钥 ⇒ 长度非法（AEAD 记录密钥要求 32 字节）。
        let node = vless_node(
            port,
            "",
            Some(xel_section("0011223344556677", XEL_DOWNLINK_HEX)),
            false,
        );
        assert!(
            node.validate().is_err(),
            "非法密钥长度必须在配置校验层就被拒"
        );

        let error = dial_vless(&node, WAIT).await.expect_err("坏配置必须失败");
        assert!(
            error.to_string().contains("xel"),
            "错误应点名 xel 配置非法：{error}"
        );
        let outcome = timeout(Duration::from_secs(2), watcher).await;
        assert!(
            outcome.is_err(),
            "坏配置下不该建立连接（已被 accept {} 次）",
            accepted.load(std::sync::atomic::Ordering::SeqCst)
        );
    })
    .await
    .expect("用例总超时");
}

/// **4. XEL 负例**：载荷篡改被拒 —— 在**记录层**里翻一个字节 ⇒ 对端必须检出
/// 并断连（AEAD 认证失败）。
///
/// 篡改点插在**记录层与传输层之间** ⇒ 线上被改的是记录层密文 ⇒ 对端是**记录层
/// 的 AEAD** 抓到失败（不是 TLS 的 MAC 先抓到）。
///
/// 判据：客户端读载荷必须**报错**（⛔ 不是干净的 EOF、⛔ 不是静默的坏数据）；
/// 之后再读也必须仍报错（fail-closed：记录层被永久 poison）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_tampered_payload_is_rejected() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(
            port,
            &ca_pem,
            Some(xel_section(XEL_UPLINK_HEX, XEL_DOWNLINK_HEX)),
            false,
        );
        let payload_len = support::BIG_PAYLOAD_LEN;

        let (client, server) = tokio::join!(
            async {
                let mut outbound = dial_vless(&node, WAIT)
                    .await
                    .expect("XEL 建流 + 握手应成功");
                outbound
                    .stream
                    .write_all(&vec![0x5au8; payload_len])
                    .await
                    .expect("写载荷");
                let mut received = vec![0u8; payload_len];
                let first = timeout(WAIT, outbound.stream.read_exact(&mut received)).await;
                // 第一次读必须失败（AEAD 认证失败）。
                let first = first
                    .expect("读载荷超时（篡改后必须立刻失败，不得挂住）")
                    .expect_err("载荷被篡改后必须失败，不得返回数据");
                // 记录层 fail-closed：之后再读也必须失败（不得变成干净 EOF）。
                let mut again = vec![0u8; 1];
                let second = timeout(WAIT, outbound.stream.read_exact(&mut again))
                    .await
                    .expect("第二次读超时")
                    .expect_err("记录层被篡改后必须永久失败，不得回落到干净 EOF");
                format!("{first} / {second}")
            },
            support::serve_xel(
                fixture,
                KEY,
                XEL_SERVER_UPLINK_HEX,
                XEL_SERVER_DOWNLINK_HEX,
                payload_len,
                Some(TAMPER_OFFSET),
            ),
        );
        assert!(
            client.contains("XEL") || client.contains("认证"),
            "错误应点名记录层认证失败：{client}"
        );
        // 服务端侧不受影响：篡改发生在记录层与传输层之间，服务端照样把载荷写出去了。
        assert_eq!(
            server.expect("服务端"),
            vec![0x5au8; payload_len],
            "服务端读到的上行载荷应逐字节一致"
        );
        println!("XEL 载荷篡改被拒：{client}");
    })
    .await
    .expect("用例总超时");
}

/// **5. Mux 正例**：承载建立 + 单会话往返。
///
/// 承载上**先发 mux 帧**（`New`），服务端才把滞留的响应头连同首个回程帧一起
/// flush（参考 `common/buf/writer.go` 的 `SetFlushNext()` 时序）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_single_session_roundtrip() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        assert!(node.validate().is_ok(), "配置应通过校验");
        let mut peer = spawn_mux_peer(fixture, KEY);

        let mut outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        let session_id = match &outbound.stream {
            VlessStream::Mux(session) => session.id(),
            _ => panic!("承载应是 mux"),
        };
        outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
        let mut received = vec![0u8; PAYLOAD.len() + 2];
        timeout(WAIT, outbound.stream.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        // 服务端回显带会话标签（会话 ID ‖ 载荷）⇒ 路由串扰会立刻暴露。
        assert_eq!(
            &received[..2],
            &session_id.to_be_bytes(),
            "回显必须落在本会话上"
        );
        assert_eq!(&received[2..], PAYLOAD, "回环载荷必须逐字节一致");

        // 承载断开 ⇒ 服务端任务收尾（顺带验证服务端确实收到了载荷）。
        peer.close.take().expect("关闭句柄").send(()).ok();
        let outcome = peer.task.await.expect("服务端任务").expect("服务端");
        assert_eq!(outcome.received.len(), 1, "服务端应只收到一条会话的载荷");
        assert_eq!(outcome.received[0].1, PAYLOAD, "服务端收到的载荷应一致");
    })
    .await
    .expect("用例总超时");
}

/// **6. Mux 正例**：多会话隔离 —— 同一条承载开**两条**逻辑会话（不同目标、
/// 不同载荷），断言两条**互不串扰**（A 的字节不能出现在 B 里，反之亦然）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_two_sessions_are_isolated() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        let mut peer = spawn_mux_peer(fixture, KEY);

        let outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        let VlessStream::Mux(mut session_a) = outbound.stream else {
            panic!("承载应是 mux");
        };
        // 第二条逻辑会话：同一条承载、不同目标。
        let mut session_b = session_a
            .open_session(TargetAddr::Domain("b.example.test".to_owned(), 80))
            .await
            .expect("开第二条逻辑会话");
        assert_ne!(session_a.id(), session_b.id(), "两条会话的 ID 必须不同");

        session_a.write_all(PAYLOAD_A).await.expect("写 A 载荷");
        session_b.write_all(PAYLOAD_B).await.expect("写 B 载荷");

        let mut got_a = vec![0u8; PAYLOAD_A.len() + 2];
        timeout(WAIT, session_a.read_exact(&mut got_a))
            .await
            .expect("读 A 载荷超时")
            .expect("读 A 载荷");
        let mut got_b = vec![0u8; PAYLOAD_B.len() + 2];
        timeout(WAIT, session_b.read_exact(&mut got_b))
            .await
            .expect("读 B 载荷超时")
            .expect("读 B 载荷");

        assert_eq!(
            &got_a[..2],
            &session_a.id().to_be_bytes(),
            "A 的回显必须落在 A 会话上"
        );
        assert_eq!(
            &got_b[..2],
            &session_b.id().to_be_bytes(),
            "B 的回显必须落在 B 会话上"
        );
        assert_eq!(&got_a[2..], PAYLOAD_A, "A 的载荷必须逐字节一致");
        assert_eq!(&got_b[2..], PAYLOAD_B, "B 的载荷必须逐字节一致");
        assert!(
            !got_a.windows(PAYLOAD_B.len()).any(|w| w == PAYLOAD_B),
            "A 的回显里不得出现 B 的字节"
        );
        assert!(
            !got_b.windows(PAYLOAD_A.len()).any(|w| w == PAYLOAD_A),
            "B 的回显里不得出现 A 的字节"
        );

        peer.close.take().expect("关闭句柄").send(()).ok();
        let outcome = peer.task.await.expect("服务端任务").expect("服务端");
        assert_eq!(outcome.received.len(), 2, "服务端应收到两条会话的载荷");
    })
    .await
    .expect("用例总超时");
}

/// **7. Mux 负例**：承载断开 ⇒ **所有**逻辑会话必须失败（⛔ 不得静默挂住）。
///
/// 承载断开的判定：承载连接被关闭 ⇒ 读循环收尾 ⇒ 所有会话的收件箱被关闭 ⇒
/// 会话读必须**返回错误**（EOF ⇒ `read_exact` 报 `UnexpectedEof`），而不是
/// 永远 pending。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_carrier_close_fails_all_sessions() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        let mut peer = spawn_mux_peer(fixture, KEY);

        let outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        let VlessStream::Mux(mut session_a) = outbound.stream else {
            panic!("承载应是 mux");
        };
        let mut session_b = session_a
            .open_session(TargetAddr::Domain("b.example.test".to_owned(), 80))
            .await
            .expect("开第二条逻辑会话");

        // 先做一次成功往返，确认承载确实通着。
        session_a.write_all(PAYLOAD_A).await.expect("写 A 载荷");
        let mut got = vec![0u8; PAYLOAD_A.len() + 2];
        timeout(WAIT, session_a.read_exact(&mut got))
            .await
            .expect("读 A 载荷超时")
            .expect("读 A 载荷");
        assert_eq!(&got[2..], PAYLOAD_A, "A 的载荷必须逐字节一致");

        // 承载断开。
        peer.close.take().expect("关闭句柄").send(()).ok();
        peer.task.await.expect("服务端任务").expect("服务端");

        // 两条会话都必须失败，且不得挂住。
        let mut buf = vec![0u8; 8];
        let a = timeout(WAIT, session_a.read_exact(&mut buf)).await;
        assert!(a.is_ok(), "承载断开后 A 会话必须结束（不得静默挂住）");
        assert!(a.expect("已结束").is_err(), "承载断开后 A 会话必须失败");
        let b = timeout(WAIT, session_b.read_exact(&mut buf)).await;
        assert!(b.is_ok(), "承载断开后 B 会话必须结束（不得静默挂住）");
        assert!(b.expect("已结束").is_err(), "承载断开后 B 会话必须失败");
    })
    .await
    .expect("用例总超时");
}

/// **8. Mux 顺序**：承载上**先发 mux 帧**、再在读帧流时消费响应头。
///
/// 参考把 VLESS 响应头滞留到**首个 mux 帧写出**才 flush
/// （`proxy/vless/inbound/inbound.go:618-621` 写进 `buf.BufferedWriter`，之后
/// 才 `SetFlushNext()`；`common/buf/writer.go:165` 的 `flushNext` 只在**下一次
/// Write** 时触发）⇒ 若 node「先阻塞等响应头、再发 mux 帧」，承载两端互锁。
///
/// 判据：服务端在**收到客户端的 mux 帧之后**才把响应头 flush 出来 ⇒
/// `frames_before_header ≥ 1` 即证明客户端**先发了帧**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_sends_frames_before_waiting_for_response_header() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        let mut peer = spawn_mux_peer(fixture, KEY);

        let mut outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
        let mut received = vec![0u8; PAYLOAD.len() + 2];
        timeout(WAIT, outbound.stream.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        assert_eq!(&received[2..], PAYLOAD, "回环载荷必须逐字节一致");

        peer.close.take().expect("关闭句柄").send(()).ok();
        let outcome = peer.task.await.expect("服务端任务").expect("服务端");
        assert!(
            outcome.frames_before_header >= 1,
            "客户端必须先发 mux 帧再拿响应头（实际收到 {} 帧后才 flush 响应头）",
            outcome.frames_before_header
        );
        println!(
            "mux 承载顺序正确：响应头在客户端发出 {} 帧之后才 flush",
            outcome.frames_before_header
        );
    })
    .await
    .expect("用例总超时");
}
