//! **帧级重放**：同一段应用层字节被再次投递时，发生了什么。
//!
//! 对应审计 §3 矩阵的 Hysteria「重放」格。分两条：
//!
//! 1. `same_session_frame_replay_is_accepted_as_new_request`
//!    —— **同会话内**逐字节重放已成功传输的 TCPRequest 帧。
//! 2. `cross_session_frame_replay_is_accepted_as_new_request`
//!    —— **跨会话**（会话 A 的数据打到会话 B）。
//!
//! # 语义基线（参考实现，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//!
//! 参考的 TCPRequest 帧格式（`proxy/hysteria/protocol.go:28-62`）是
//! **地址长度 + 地址 + padding 长度 + padding** —— **没有序号、没有
//! 时间戳、没有随机数、没有 nonce**。服务端 `proxy/hysteria/server.go:153`
//! 直接 `ReadTCPRequest(conn)` 后 `net.ParseDestination("tcp:"+addr)`，
//! **没有任何重放检查**。
//!
//! ⇒ **结论（参考行为）**：常规会话的应用层帧重放**不被拒绝**，被当成
//! **一条全新的请求**处理。本仓必须与之一致（见 `src/proxy.rs:317`
//! `serve_tcp_stream_paced` → `server_read_tcp_request`，同样无重放检查）。
//!
//! 这与「传输层（QUIC 包级）重放被丢弃」是**两件事**：后者见
//! `packet_level.rs`。

use super::support::{
    connect_with, encode_tcp_request, pattern, spawn_tcp_target, start_server, RawStream,
    IO_TIMEOUT,
};

/// 重放用的固定 padding（重放要求字节**完全一致**，不能用随机 padding）。
const REPLAY_PADDING: &[u8] = b"lengsuo-replay-fixed-padding-0123456789";

/// 同会话内逐字节重放 ⇒ 服务端**接受**（当成新请求），目标被接入两次。
///
/// 判据（与参考一致）：
/// - 重放后目标收到**两份**同样的字节（`received()` 长度翻倍）；
/// - 目标被**接入两次**（`accepts() == 2`）⇒ 服务端确实把重放帧当成
///   一条独立请求建立了新的出站连接。
#[tokio::test]
async fn same_session_frame_replay_is_accepted_as_new_request() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("frame-same").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        // 第一次：正常发送 TCPRequest 帧 + 载荷。
        let payload = pattern(64);
        let frame = encode_tcp_request(&addr, REPLAY_PADDING);
        let mut first = super::support::RawStream::open(&client)
            .await
            .expect("开流失败");
        let mut framed = frame.clone();
        framed.extend_from_slice(&payload);
        first.write_raw(&framed).await.expect("首写失败");
        first.finish();

        // 目标必须先收到第一份（确保「重放」发生在成功传输之后）。
        // ⇒ 必须**轮询等待**，不能「写完立刻断言」（否则是竞态）。
        let first_ok = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(
            first_ok,
            "首帧未完整到达目标（received={}）",
            target.received().len()
        );

        // 第二次：把**完全相同**的字节重放一遍（同一会话，另一条 QUIC 流）。
        let mut second = super::support::RawStream::open(&client)
            .await
            .expect("开流失败");
        second.write_raw(&framed).await.expect("重放写失败");
        second.finish();

        // 目标最终应收到两份。
        let got = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(
            got,
            "重放后目标未收到第二份数据（received={}）",
            target.received().len()
        );
        assert_eq!(
            target.received(),
            [payload.clone(), payload.clone()].concat(),
            "重放字节应与首帧逐字节一致（参考不校验，故服务端原样转发）"
        );
        assert_eq!(
            target.accepts(),
            2,
            "重放帧必须被当成新请求 ⇒ 目标被接入两次（参考无重放检查）"
        );
    })
    .await;
}

/// 跨会话重放：会话 A 的数据打到会话 B ⇒ 同样被**接受**（当成新请求）。
///
/// 语义基线：参考的会话身份由 **QUIC 连接**承载（`hub.go` 的
/// `httpHandler` 每连接一个，`h.auth`/`h.user` 是**连接内**状态），
/// 应用层帧里**没有**会话标识 ⇒ 跨会话重放在协议层不可见。
#[tokio::test]
async fn cross_session_frame_replay_is_accepted_as_new_request() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("frame-cross").await;
        let client_a = connect_with(&server, &server.auth)
            .await
            .expect("会话 A 建连失败");
        let client_b = connect_with(&server, &server.auth)
            .await
            .expect("会话 B 建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let payload = pattern(48);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);

        // 会话 A：发送一次。
        let mut a = super::support::RawStream::open(&client_a)
            .await
            .expect("开流失败");
        a.write_raw(&framed).await.expect("会话 A 写失败");
        a.finish();
        let got_a = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(got_a, "会话 A 的数据未到达目标");

        // 会话 B：重放 A 的**同一段字节**。
        let mut b = super::support::RawStream::open(&client_b)
            .await
            .expect("开流失败");
        b.write_raw(&framed).await.expect("会话 B 重放写失败");
        b.finish();

        let got_b = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(
            got_b,
            "跨会话重放未被接受（received={}）",
            target.received().len()
        );
        assert_eq!(
            target.received(),
            [payload.clone(), payload.clone()].concat(),
            "跨会话重放的字节应与原帧逐字节一致"
        );
        assert_eq!(
            target.accepts(),
            2,
            "跨会话重放必须被当成新请求（参考无跨会话重放检查）"
        );
    })
    .await;
}

/// 同一会话内**在同一条 QUIC 流上**重放 ⇒ **不是**新请求，而是目标数据。
///
/// 语义基线（参考 `proxy/hysteria/server.go:153` `ReadTCPRequest`）：
/// 参考在一条 QUIC 流上**只读一次** TCPRequest（帧类型 + 地址 + padding），
/// 随后的字节**全部**当作目标数据转发（`buf.NewReader(conn)` →
/// `DispatchLink`）。⇒ 在同一条流上重放请求帧 ⇒ 第二遍的**每一个字节**
/// 都成了目标数据。
///
/// 精确的字节账（首写 = 帧 + 载荷，重写 = 帧 + 载荷）：
/// - 首写的**帧**被服务端解析掉（不转发给目标）；
/// - 首写的**载荷**转发给目标（帧后的残余字节）；
/// - 重写的**整段**（帧 + 载荷）都转发给目标。
///
/// 这与「跨流重放」是**两件事**：跨流时服务端重新读一次 TCPRequest，
/// 于是帧被**解析**成新请求（见
/// `same_session_frame_replay_is_accepted_as_new_request`）。
///
/// ⚠️ 这里断言的是**字节级**事实（目标收到的内容），不是「重放被接受
/// 为新请求」——后者只对**跨流**成立。
#[tokio::test]
async fn same_stream_frame_replay_is_forwarded_as_target_data() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("frame-samestream").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let payload = pattern(32);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);

        let mut stream = super::support::RawStream::open(&client)
            .await
            .expect("开流失败");
        stream.write_raw(&framed).await.expect("首写失败");
        // 同一流上重放同一段字节（不 finish，让服务端继续读）。
        stream.write_raw(&framed).await.expect("重放写失败");
        stream.finish();

        // 期望总量 = 首写载荷（32）+ 重写整段（帧 + 载荷）。
        let expect_len = payload.len() + framed.len();
        let got = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= expect_len
        })
        .await;
        assert!(
            got,
            "同流重放未被转发（received={}，期望 >= {expect_len}）",
            target.received().len()
        );
        // 目标收到 = 首写的载荷 ++ 重写的整段（帧字节在同流上属于目标数据）。
        assert_eq!(
            target.received(),
            [payload.clone(), framed.clone()].concat(),
            "同流重放：首写帧被解析掉、重写整段成为目标数据"
        );
        assert_eq!(
            target.accepts(),
            1,
            "同一条 QUIC 流 ⇒ 只有一次出站接入（参考每流只读一次 TCPRequest）"
        );
    })
    .await;
}

/// 重放的**帧级**判据：帧里没有序号/随机数 ⇒ 重放字节与原字节完全等价。
///
/// 这条把「协议格式本身不携带防重放信息」钉成字节级断言：把重放帧逐
/// 字节与原帧比较，必须**完全相同**（否则下面的「重放被接受」就没有
/// 说服力 —— 可能只是因为编码不同）。
#[test]
fn tcp_request_frame_carries_no_replay_nonce() {
    let frame = encode_tcp_request("127.0.0.1:9", REPLAY_PADDING);
    // 帧 = varint(0x401) ‖ varint(addr_len) ‖ addr ‖ varint(pad_len) ‖ padding
    //
    // ⚠️ 0x401 = 1025 > 63 ⇒ QUIC varint 必须用 **2 字节**形式：
    // 首字节 = 0x40 | (0x401 >> 8) = 0x44，次字节 = 0x401 & 0xff = 0x01。
    // （参考 `transport/internet/hysteria/config.go:29`
    // `FrameTypeTCPRequest = 0x401`，同样按 varint 编码。）
    assert_eq!(&frame[..2], &[0x44, 0x01], "帧类型必须是 varint(0x401)");
    assert_eq!(
        frame,
        encode_tcp_request("127.0.0.1:9", REPLAY_PADDING),
        "同一输入必须编码出完全相同的字节（可逐字节重放）"
    );
    // 帧里除地址与 padding 外没有任何随机数/序号字段：
    // 去掉地址与 padding 后，剩下的部分就是两个长度前缀。
    let addr = "127.0.0.1:9".as_bytes();
    let tail = &frame[2 + 1 + addr.len()..];
    assert_eq!(
        tail.len(),
        1 + REPLAY_PADDING.len(),
        "尾部只剩 padding 长度 + padding"
    );
    assert_eq!(
        tail[0] as usize,
        REPLAY_PADDING.len(),
        "padding 长度前缀正确"
    );
}

/// **重放与 QUIC 流 ID 的关系**（任务书第 3 条）：重放**不依赖**流 ID。
///
/// 观测点（全部是既有可观测点，不自造 API）：
/// - `RawStream::stream_id`：本条 QUIC 双向流的流 ID（`SendStream::id`）；
/// - `RawStream::read_response_frame`：服务端回的 `TCPResponse` 帧的
///   status 字节（对齐参考 `proxy/hysteria/server.go:179`
///   `WriteTCPResponse(bufferedWriter, true, "")` ⇒ status = 0 = OK）。
///
/// 结论（取证）：重放帧被放在**另一条流**（流 ID 不同）上，服务端照样
/// 接受（回 status=0 并建立新的出站连接）⇒ **流 ID 不参与防重放**。
///
/// 依据：参考的 `transport/internet/hysteria/hub.go:233`
/// `StreamDispatcher` 只 peek 帧类型 `0x401`，随后 `addConn(&interConn{...})`
/// —— 流 ID 只用于**路由**到哪个 `interConn`，不参与任何重放判定。
#[tokio::test]
async fn replay_does_not_depend_on_quic_stream_id() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("frame-streamid").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let payload = pattern(40);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);

        // 流 1：首帧。
        let mut first = RawStream::open(&client).await.expect("开流失败");
        let first_id = first.stream_id;
        first.write_raw(&framed).await.expect("首写失败");
        // 服务端回 TCPResponse(status=0)。
        let (status, _msg) = first
            .read_response_frame()
            .await
            .expect("读 TCPResponse 失败");
        assert_eq!(status, 0, "服务端应回 TCPResponse(status=OK)");
        first.finish();

        // 流 2：重放（**不同的流 ID**）。
        let mut second = RawStream::open(&client).await.expect("开流失败");
        let second_id = second.stream_id;
        assert_ne!(
            first_id, second_id,
            "两条流的 QUIC 流 ID 必须不同（客户端双向流 ID 单调递增）"
        );
        second.write_raw(&framed).await.expect("重放写失败");
        let (status2, _msg2) = second
            .read_response_frame()
            .await
            .expect("读 TCPResponse 失败");
        assert_eq!(
            status2, 0,
            "重放帧在**另一条流**上仍被接受（status=OK）⇒ 流 ID 不参与防重放"
        );
        second.finish();

        // 目标确实被再接入一次 ⇒ 重放不是被静默丢弃。
        let got = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(got, "重放后目标未收到第二份数据");
        assert_eq!(target.accepts(), 2, "重放帧必须建立新的出站连接");
    })
    .await;
}

/// 重放（帧级）**不得**导致服务端把目标连接当成非法而静默丢弃载荷：
/// 服务端必须**完整**转发第二份字节（否则「被接受」只是半截接受）。
///
/// 用**两条流**（跨流重放）：服务端在每条流上重新读一次 TCPRequest，
/// 于是重放帧被当成新请求，第二份载荷走**新的出站连接**。
#[tokio::test]
async fn replayed_frame_payload_is_fully_forwarded() {
    super::support::case_within(super::support::CASE_DEADLINE, async {
        let server = start_server("frame-full").await;
        let client = connect_with(&server, &server.auth).await.expect("建连失败");
        let target = spawn_tcp_target().await;
        let addr = target.addr.to_string();

        let payload = pattern(1024);
        let mut framed = encode_tcp_request(&addr, REPLAY_PADDING);
        framed.extend_from_slice(&payload);

        // 流 1：首帧。
        let mut first = super::support::RawStream::open(&client)
            .await
            .expect("开流失败");
        first.write_raw(&framed).await.expect("首写失败");
        first.finish();
        let ok = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len()
        })
        .await;
        assert!(ok, "首份载荷未到达目标");

        // 流 2：逐字节重放同一段字节。
        let mut second = super::support::RawStream::open(&client)
            .await
            .expect("开流失败");
        second.write_raw(&framed).await.expect("重放写失败");
        second.finish();

        let got = super::support::wait_until(super::support::RECLAIM_DEADLINE, || {
            target.received().len() >= payload.len() * 2
        })
        .await;
        assert!(got, "重放载荷未完整转发");
        let received = target.received();
        assert_eq!(received.len(), payload.len() * 2, "重放载荷长度不符");
        assert_eq!(&received[..payload.len()], &payload[..], "首份载荷不符");
        assert_eq!(
            &received[payload.len()..],
            &payload[..],
            "重放载荷未逐字节一致"
        );
        // 外层 timeout 兜底（本用例无网络等待，但统一口径）。
        let _ = tokio::time::timeout(IO_TIMEOUT, async {}).await;
    })
    .await;
}
