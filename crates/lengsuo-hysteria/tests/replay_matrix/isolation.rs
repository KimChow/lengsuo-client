//! **隔离格**：重放不得污染后续会话。
//!
//! 任务书第 4 条：「一条连接被判重放/异常后，**新会话必须能正常往返**」。
//!
//! # 语义基线
//!
//! 参考实现（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! - `proxy/hysteria/server.go:153` `ReadTCPRequest` 失败 ⇒ 只结束**那一条
//!   QUIC 流**（`Process` 返回错误），**不动连接、不动其它流**；
//! - `transport/internet/hysteria/hub.go:269` `handleClient` 里每条连接
//!   一个 `httpHandler`，`h.auth` 是**连接内**状态；连接结束才
//!   `CloseWithError(closeErrCodeOK)`。
//!
//! ⇒ 结论：**单条流上的异常/重放不得升级为连接级或进程级故障**；新会话
//! 必须照常往返。本仓对齐点：`src/h3_server.rs:123` 的 `accept_bi` 循环
//! 里，`serve_tcp_stream_paced` 出错只结束该协程（`src/h3_server.rs:142`），
//! 连接仍在 `accept_bi` 循环里继续服务。

use super::support::{
    client_config, connect_with, encode_tcp_request, pattern, spawn_tcp_target, start_server,
    RawStream, RECLAIM_DEADLINE,
};

/// 重放用的固定 padding。
const REPLAY_PADDING: &[u8] = b"lengsuo-replay-fixed-padding-0123456789";

/// 帧级重放之后：**新会话**必须能正常往返（完整收发）。
///
/// 这条直接钉住「重放不得污染后续会话」。
///
/// 重放方式：**两条流**（跨流重放）⇒ 服务端把重放帧当成**新请求**
/// （参考 `proxy/hysteria/server.go:153` 每条流只读一次 TCPRequest）。
#[tokio::test]
async fn replay_does_not_pollute_a_fresh_session() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("iso-fresh").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        // 会话 1：发送 + 重放（协议层被接受，但这一步只是制造「脏」状态）。
        let payload = pattern(64);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut dirty = RawStream::open(&client).await.expect("开流失败");
        dirty.write_raw(&framed).await.expect("写失败");
        dirty.finish();
        let mut replay = RawStream::open(&client).await.expect("开流失败");
        replay.write_raw(&framed).await.expect("重放写失败");
        replay.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(got, "重放未按预期发生（前置条件不满足）");

        // 会话 2：**全新连接**（新端点 ⇒ 新 QUIC 连接 ⇒ 新会话 ID）。
        let client2 = connect_with(&server, &server.auth)
            .await
            .expect("新会话建连失败");
        let mut stream = RawStream::open(&client2).await.expect("开流失败");
        let payload2 = pattern(128);
        let mut framed2 = encode_tcp_request(&addr, REPLAY_PADDING);
        framed2.extend_from_slice(&payload2);
        stream.write_raw(&framed2).await.expect("新会话写失败");
        stream.finish();

        let got2 = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2 + payload2.len()
        })
        .await;
        assert!(
            got2,
            "重放后新会话未完成往返（received={}）",
            target.received().len()
        );
        let received = target.received();
        assert_eq!(
            &received[payload.len() * 2..],
            &payload2[..],
            "新会话的回程数据必须逐字节正确"
        );
    })
    .await;
}

/// 畸形帧（截断的 TCPRequest）之后：**新会话**必须能正常往返。
///
/// 与重放同属「异常路径」：服务端必须只丢弃该流，不得升级为连接/进程级
/// 故障（参考 `proxy/hysteria/server.go:161`：`ReadTCPRequest` 出错 ⇒
/// `Process` 返回错误，只影响那一条流）。
#[tokio::test]
async fn malformed_frame_does_not_pollute_a_fresh_session() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("iso-malformed").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        // 会话 1：发一个**截断**的 TCPRequest（长度前缀说有 200 字节，
        // 但只给 2 字节）⇒ 服务端读不满 ⇒ 该流被判协议错误。
        let mut truncated = super::support::varint_bytes(super::support::FRAME_TYPE_TCP_REQUEST);
        truncated.extend_from_slice(&super::support::varint_bytes(200));
        truncated.extend_from_slice(b"ab");
        let mut bad = RawStream::open(&client).await.expect("开流失败");
        bad.write_raw(&truncated).await.expect("写失败");
        bad.finish();

        // 会话 2：新连接必须照常往返。
        let client2 = connect_with(&server, &server.auth)
            .await
            .expect("新会话建连失败");
        let mut stream = RawStream::open(&client2).await.expect("开流失败");
        let payload = pattern(256);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        stream.write_raw(&framed).await.expect("新会话写失败");
        stream.finish();

        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(
            got,
            "畸形帧后新会话未完成往返（received={}）",
            target.received().len()
        );
        assert_eq!(target.received(), payload, "新会话的数据必须逐字节正确");
        assert_eq!(
            target.accepts(),
            1,
            "畸形帧不得建立任何出站连接（fail-closed：残帧不得被当干净 EOF 放行）"
        );
    })
    .await;
}

/// 认证失败（错口令）之后：**新会话**（正确口令）必须能正常往返。
///
/// 认证失败必须 fail-closed（`src/h3_auth.rs:200-202`：认证失败 ⇒ 以
/// 0x101 关闭**该连接**），且不得影响服务端整体（参考 `hub.go:230`
/// masquerade 分支只回 404）。
#[tokio::test]
async fn failed_auth_does_not_pollute_a_fresh_session() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("iso-auth").await;
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        // 会话 1：错口令 ⇒ 认证被拒（masquerade 404）。
        let err = match connect_with(&server, "definitely-wrong-password").await {
            Err(e) => e,
            Ok(_) => panic!("错误口令不应建连成功"),
        };
        let status = err
            .rejected_status()
            .unwrap_or_else(|| panic!("应表现为认证被拒（HTTP 状态），实际: {err:?}"));
        assert_eq!(status, 404, "masquerade 缺省应回 404");

        // 会话 2：正确口令 ⇒ 必须能正常往返。
        let client = connect_with(&server, &server.auth)
            .await
            .expect("新会话建连失败");
        let mut stream = RawStream::open(&client).await.expect("开流失败");
        let payload = pattern(512);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        stream.write_raw(&framed).await.expect("写失败");
        stream.finish();

        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(
            got,
            "认证失败后新会话未完成往返（received={}）",
            target.received().len()
        );
        assert_eq!(target.received(), payload, "新会话的数据必须逐字节正确");
    })
    .await;
}

/// 同一**连接**上：一条流被重放后，同连接的**后续**新流仍必须正常往返。
///
/// 隔离的粒度是「流」还是「连接」？参考给出答案：`hub.go:269`
/// `handleClient` 每连接一个 `httpHandler`，其 `accept_bi` 循环里每条流
/// 独立分派（`hub.go:233` `StreamDispatcher`）⇒ **流级隔离**。
#[tokio::test]
async fn replay_on_one_stream_does_not_break_sibling_stream() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("iso-sibling").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        // 流 1：首帧；流 1'：重放（**跨流** ⇒ 重放帧被当成新请求）。
        let payload = pattern(32);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut dirty = RawStream::open(&client).await.expect("开流失败");
        dirty.write_raw(&framed).await.expect("写失败");
        dirty.finish();
        let mut replay = RawStream::open(&client).await.expect("开流失败");
        replay.write_raw(&framed).await.expect("重放写失败");
        replay.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(got, "重放未按预期发生（前置条件不满足）");

        // 流 2：**同一连接**上的新流 ⇒ 必须正常往返。
        let mut sibling = RawStream::open(&client).await.expect("开流失败");
        let payload2 = pattern(96);
        let mut framed2 = encode_tcp_request(&addr, REPLAY_PADDING);
        framed2.extend_from_slice(&payload2);
        sibling.write_raw(&framed2).await.expect("写失败");
        sibling.finish();

        let got2 = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2 + payload2.len()
        })
        .await;
        assert!(
            got2,
            "同连接的兄弟流未完成往返（received={}）",
            target.received().len()
        );
        let received = target.received();
        assert_eq!(
            &received[payload.len() * 2..],
            &payload2[..],
            "兄弟流的数据必须逐字节正确"
        );
        assert_eq!(
            target.accepts(),
            3,
            "重放流（1 次接入）+ 重放帧的新请求（1 次接入）+ 兄弟流（1 次接入）"
        );
    })
    .await;
}

/// 服务端**连接表**不得因重放而膨胀：重放不新建 QUIC 连接。
#[tokio::test]
async fn replay_does_not_create_new_connections() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("iso-conn").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let before = server.open_connections();
        assert!(before >= 1, "服务端应至少有一条连接");

        let payload = pattern(16);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);
        let mut dirty = RawStream::open(&client).await.expect("开流失败");
        dirty.write_raw(&framed).await.expect("写失败");
        dirty.finish();
        let mut replay = RawStream::open(&client).await.expect("开流失败");
        replay.write_raw(&framed).await.expect("重放写失败");
        replay.finish();
        let got = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(got, "重放未按预期发生（前置条件不满足）");

        let after = server.open_connections();
        assert_eq!(
            after, before,
            "帧级重放不得新建 QUIC 连接（重放发生在既有连接的新流上）"
        );
        // 连接仍然健康：后续新流必须可用。
        let mut later = RawStream::open(&client).await.expect("开流失败");
        let payload2 = pattern(24);
        let mut framed2 = encode_tcp_request(&addr, REPLAY_PADDING);
        framed2.extend_from_slice(&payload2);
        later.write_raw(&framed2).await.expect("写失败");
        later.finish();
        let got2 = super::support::wait_until(RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2 + payload2.len()
        })
        .await;
        assert!(got2, "重放后同连接的新流未完成往返");
    })
    .await;
}

/// 客户端配置工厂（供本模块自检，避免依赖其它模块的私有实现）。
#[allow(dead_code)]
fn client_cfg(server: &super::support::Server, auth: &str) -> lengsuo_hysteria::quic::ClientConfig {
    client_config(server, auth)
}
