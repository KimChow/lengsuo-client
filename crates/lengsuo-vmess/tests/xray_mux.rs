//! Rust 客户端 ↔ 真实 Xray VMess 入站的 Mux（`v1.mux.cool`）互通（ignored）。
//!
//! 运行方式（缺 `LENGSUO_XRAY` 时每个用例明确打印原因并 return，不静默通过）：
//! ```text
//! LENGSUO_XRAY=/path/to/xray cargo test -p lengsuo-vmess --test xray_mux --locked -- --ignored --nocapture
//! ```
//!
//! 对照参考固定 commit `d2758a02`：
//! - 请求头命令 `RequestCommandMux` 且**不写地址**
//!   （`proxy/vmess/encoding/client.go:79-84`）；本仓 `request::Command` 无 Mux
//!   变体（`request.rs:40-67`），故明文头由 `xray_mux_helpers` 按
//!   `client.go:63-94` 手工拼装（测试侧代码，不改 `src/`）。
//! - 服务端把 Mux 请求的目的地固定为 `v1.mux.cool:0`
//!   （`proxy/vmess/encoding/server.go:207-211`）；`common/mux/server.go:42,63`
//!   只比较地址，不看端口；mux server 无条件挂载
//!   （`app/proxyman/inbound/always.go:83,119,141`）。
//! - 帧布局与四态：`common/mux/frame.go`、`common/mux/writer.go`；
//!   `New` 帧带 `network|port|address`，`Keep/End` 只带 4 字节元数据。
//! - 服务端分派：`common/mux/server.go:158-334`；客户端分派：
//!   `common/mux/client.go:333-419`。
//! - VMess 体分帧：AES-128-GCM 在 `encoding/server.go:280-298` 无条件走
//!   `AuthenticationReader`，与 `RequestOptionChunkStream` 位无关；回程
//!   `EncodeResponseBody`（`server.go:402-...`）同理。故本文件用
//!   `option = 0x01(ChunkStream)`、**不开** chunk masking（0x04），走明文长度段。
//!
//! 关键时序（参考 `proxy/vmess/inbound/inbound.go:187-223`）：响应头写在
//! `buf.NewBufferedWriter` 里，直到首次 `input.ReadMultiBuffer()` 返回后才
//! `SetBuffered(false)` 刷出——因此客户端必须先把 mux 帧写出去，再读响应头。
//!
//! 实测记录（2026-10-20，详见 docs/vmess-status.md「Mux 参考互通」）：
//! 首轮实跑暴露 `StreamSender::send_new(None)` 误置 `OptionData`
//! （Xray 报 `unknown status: 108`），已按参考 `writer.go:62-69` 最小修正。

#[path = "xray_mux_helpers/mod.rs"]
mod helpers;
#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use helpers::{
    fail, open_session, pump_until, spawn_counting_listener, spawn_udp_echo, start_fixture,
    xray_bin, MuxConn, RESPONSE_TIMEOUT,
};
use lengsuo_vmess::muxframe::{
    FrameMetadata, SessionStatus, TargetNetwork, MAX_META_LEN, OPTION_DATA, OPTION_ERROR,
};
use lengsuo_vmess::muxsession::{
    encode_frame_with_payload, ClientSession, SessionStrategy, StreamSender,
};
use lengsuo_vmess::request::KeySource;
use ss_core::target::TargetAddr;

use support::codec;

// ---------------------------------------------------------------------------
// 用例 A：TCP over mux（含「首包 100ms 超时 → 只发 New 元数据」路径与 8KiB
// 分片边界）。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_tcp_single_session() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, _echo_task) = codec::spawn_echo().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    let mut client = ClientSession::new(SessionStrategy::default());
    let (id, capture) = open_session(&mut client, TargetNetwork::Tcp, target.clone());
    assert_eq!(id, 1, "参考 `SessionManager.Allocate` 从 count=1 起分配");
    assert_eq!(client.table().ids(), vec![id], "首个会话 id 必须从 1 开始");

    // 1) 模拟 `writeFirstPayload` 的 100ms 超时：New 只写元数据（无 OptionData）。
    let mut sender = StreamSender::new(id, TargetNetwork::Tcp, target.clone());
    let mut wire = Vec::new();
    sender.send_new(&mut wire, None).expect("New 元数据帧");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 New 元数据帧", e));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 2) 首个 Keep 帧携带首包；此时服务端才会以首个回程数据刷出响应头。
    let first = b"hello-mux-tcp";
    wire.clear();
    sender.send_keep(&mut wire, first).expect("Keep 首包");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 Keep 首包", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));

    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= first.len(),
        "TCP 首包回程",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "TCP 首包回程", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        first,
        "TCP 首包必须逐字节回显\n{}",
        fixture.report()
    );

    // 3) 跨 8KiB 分片：参考 `Writer.WriteMultiBuffer` 对 Stream 按 8KiB 切帧。
    let large: Vec<u8> = (0..9000).map(|i| (i % 251) as u8).collect();
    wire.clear();
    sender.send_keep(&mut wire, &large).expect("Keep 大载荷");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写大载荷", e));

    let expected_len = first.len() + large.len();
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= expected_len,
        "TCP 大载荷回程",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "TCP 大载荷回程", e));
    let got = capture.snapshot();
    assert_eq!(got.len(), expected_len, "回程字节数不一致");
    assert_eq!(&got[..first.len()], first, "首段逐字节不一致");
    assert_eq!(&got[first.len()..], &large[..], "大载荷段逐字节不一致");

    // 4) 本地 End：发 End 帧，服务端应回 End 帧并回收该 session。
    let end = client.close_local(id, false);
    conn.send_wire(&end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 End 帧", e));
    let mut remote_end = None;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    while remote_end.is_none() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("等待服务端 End 帧超时");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("等待服务端 End 帧超时")
            .unwrap_or_else(|e| fail(&fixture, "等待服务端 End 帧", e));
        if meta.status == SessionStatus::End && meta.session_id == id {
            remote_end = Some(meta.option);
        }
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理 End 帧", e.to_string()));
    }
    // 参考 `server.go:111-120`：handleStatusEnd → `s.Close(false)` 中断
    // `s.input`，`handle()` 的 `buf.Copy` 报错并置 `writer.hasError`
    // （`writer.go:122-135`）→ 客户端主动 End 时回程 End 带 OptionError。
    assert_eq!(
        remote_end,
        Some(OPTION_ERROR),
        "客户端主动 End 后，参考实现回程 End 带 OptionError"
    );
    assert!(
        client.table().ids().is_empty(),
        "本地会话表必须回收干净: {:?}",
        client.table().ids()
    );
    eprintln!("OK: 用例 A TCP over mux（含首包超时/8KiB 分片/End 回收）通过。");
}

// ---------------------------------------------------------------------------
// 用例 B：UDP over mux（mux 内 UDP 会话，`TransferTypePacket`）。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_udp_single_session() {
    let Some(bin) = xray_bin() else { return };
    let echo_addr = spawn_udp_echo().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    let mut client = ClientSession::new(SessionStrategy::default());
    let (id, capture) = open_session(&mut client, TargetNetwork::Udp, target.clone());

    let mut sender = StreamSender::new(id, TargetNetwork::Udp, target.clone());
    let first = b"udp-mux-datagram-1";
    let mut wire = Vec::new();
    sender
        .send_new(&mut wire, Some(first))
        .expect("New + 首数据报");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 New + 首数据报", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= first.len(),
        "UDP 第 1 个数据报",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "UDP 第 1 个数据报", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        first,
        "第 1 个数据报必须逐字节回显\n{}",
        fixture.report()
    );

    let second = b"udp-mux-datagram-2-with-different-len";
    wire.clear();
    sender
        .send_keep(&mut wire, second)
        .expect("Keep 第 2 个数据报");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写第 2 个数据报", e));
    let expected_len = first.len() + second.len();
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= expected_len,
        "UDP 第 2 个数据报",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "UDP 第 2 个数据报", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        [first.as_slice(), second.as_slice()].concat(),
        "两个数据报必须逐字节回显且不串包\n{}",
        fixture.report()
    );

    let end = client.close_local(id, false);
    conn.send_wire(&end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 End 帧", e));
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("等待服务端 End 帧超时");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("等待服务端 End 帧超时")
            .unwrap_or_else(|e| fail(&fixture, "等待服务端 End 帧", e));
        let is_end = meta.status == SessionStatus::End && meta.session_id == id;
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理 End 帧", e.to_string()));
        if is_end {
            break;
        }
    }
    assert!(client.table().ids().is_empty(), "UDP 会话必须回收");
    eprintln!("OK: 用例 B UDP over mux（2 个数据报逐字节）通过。");
}

// ---------------------------------------------------------------------------
// 用例 C：同一 mux 会话表内 TCP/UDP 两条并发 session，不串包。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_multi_session_parallel() {
    let Some(bin) = xray_bin() else { return };
    let (tcp_echo_addr, _tcp_task) = codec::spawn_echo().await;
    let udp_echo_addr = spawn_udp_echo().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");

    let tcp_target = TargetAddr::V4([127, 0, 0, 1], tcp_echo_addr.port());
    let udp_target = TargetAddr::V4([127, 0, 0, 1], udp_echo_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    let mut client = ClientSession::new(SessionStrategy::default());
    let (tcp_id, tcp_capture) = open_session(&mut client, TargetNetwork::Tcp, tcp_target.clone());
    let (udp_id, udp_capture) = open_session(&mut client, TargetNetwork::Udp, udp_target.clone());
    assert_eq!((tcp_id, udp_id), (1, 2), "id 必须按分配顺序自增");
    assert_eq!(
        client.table().ids(),
        vec![1, 2],
        "两条会话必须同时登记在表内"
    );
    assert_eq!(client.table().count(), 2, "累计分配数必须为 2");

    let tcp_marker = b"tcp-session-marker".to_vec();
    let udp_marker = b"udp-session-marker".to_vec();

    let mut tcp_sender = StreamSender::new(tcp_id, TargetNetwork::Tcp, tcp_target.clone());
    let mut udp_sender = StreamSender::new(udp_id, TargetNetwork::Udp, udp_target.clone());
    let mut wire = Vec::new();
    tcp_sender
        .send_new(&mut wire, Some(&tcp_marker))
        .expect("TCP New");
    udp_sender
        .send_new(&mut wire, Some(&udp_marker))
        .expect("UDP New");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写两条 New", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));

    pump_until(
        &mut conn,
        &mut client,
        || tcp_capture.len() >= tcp_marker.len() && udp_capture.len() >= udp_marker.len(),
        "双会话回程",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "双会话回程", e));

    assert_eq!(
        tcp_capture.snapshot(),
        tcp_marker,
        "TCP 会话不得收到 UDP 回程\n{}",
        fixture.report()
    );
    assert_eq!(
        udp_capture.snapshot(),
        udp_marker,
        "UDP 会话不得收到 TCP 回程\n{}",
        fixture.report()
    );

    let tcp_end = client.close_local(tcp_id, false);
    let udp_end = client.close_local(udp_id, false);
    conn.send_wire(&tcp_end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 TCP End", e));
    conn.send_wire(&udp_end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 UDP End", e));

    let mut ended = BTreeSet::new();
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    while ended.len() < 2 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("等待两条 End 帧超时");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("等待两条 End 帧超时")
            .unwrap_or_else(|e| fail(&fixture, "等待 End 帧", e));
        if meta.status == SessionStatus::End {
            ended.insert(meta.session_id);
        }
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理 End 帧", e.to_string()));
    }
    assert_eq!(
        ended,
        BTreeSet::from([tcp_id, udp_id]),
        "服务端必须逐条回 End"
    );
    assert!(client.table().ids().is_empty(), "两条会话必须全部回收");
    assert_eq!(
        client.table().count(),
        2,
        "回收不得重置累计分配数（参考 Count()）"
    );
    eprintln!("OK: 用例 C 双会话（TCP+UDP）并行、无串包、id 分配/回收断言通过。");
}

// ---------------------------------------------------------------------------
// 用例 D①：未知 session id 的 Keep 帧 → 不得 panic、不得投递到错误 session。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_unknown_session_keep_is_isolated() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, _echo_task) = codec::spawn_echo().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    let mut client = ClientSession::new(SessionStrategy::default());
    let (id, capture) = open_session(&mut client, TargetNetwork::Tcp, target.clone());
    let mut sender = StreamSender::new(id, TargetNetwork::Tcp, target.clone());

    let alive = b"alive-session";
    let mut wire = Vec::new();
    sender.send_new(&mut wire, Some(alive)).expect("New");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 New", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= alive.len(),
        "存活会话首包",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "存活会话首包", e));

    // 未知 id 的 Keep：参考 `server.go:300-312` 回 End 并丢弃数据。
    let ghost = encode_frame_with_payload(
        0xFFFF,
        SessionStatus::Keep,
        OPTION_DATA,
        None,
        Some(b"ghost-payload"),
    )
    .expect("构造未知会话 Keep");
    conn.send_wire(&ghost)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写未知会话 Keep", e));

    let mut saw_end = false;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    while !saw_end {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("未知会话未回 End（超时）");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("未知会话未回 End（超时）")
            .unwrap_or_else(|e| fail(&fixture, "读未知会话响应", e));
        if meta.status == SessionStatus::End && meta.session_id == 0xFFFF {
            saw_end = true;
        }
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理未知会话帧", e.to_string()));
    }
    assert!(
        !capture
            .snapshot()
            .windows(b"ghost-payload".len())
            .any(|w| w == b"ghost-payload"),
        "未知会话的数据不得投递到存活会话\n{}",
        fixture.report()
    );

    // 存活会话必须仍可用。
    let still = b"-still-alive";
    wire.clear();
    sender.send_keep(&mut wire, still).expect("Keep");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写存活会话 Keep", e));
    let expected_len = alive.len() + still.len();
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= expected_len,
        "存活会话续传",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "存活会话续传", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        [alive.as_slice(), still.as_slice()].concat(),
        "存活会话回程必须完整\n{}",
        fixture.report()
    );
    eprintln!("OK: 用例 D① 未知 session id Keep 被隔离（回 End、无串包、无 panic）。");
}

// ---------------------------------------------------------------------------
// 用例 D②：帧 length 字段超限 → 本端 fail-closed；Xray 侧断整条 mux 连接。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_oversized_meta_is_rejected() {
    let Some(bin) = xray_bin() else { return };

    // 本地判据：`FrameMetadata::decode_from` 对 metaLen > 512 必须拒绝
    // （参考 `frame.go:119-121`）。
    let mut oversized = (MAX_META_LEN as u16 + 1).to_be_bytes().to_vec();
    oversized.extend_from_slice(&vec![0u8; MAX_META_LEN + 1]);
    let local = FrameMetadata::decode_from(&mut &oversized[..], false);
    assert!(
        matches!(local, Err(lengsuo_vmess::muxframe::FrameError::MetaTooLong)),
        "本端必须 fail-closed 拒绝超限 metaLen，实际 {local:?}"
    );

    // 互通判据：把同一条超限帧封进 VMess chunk 发给 Xray，参考
    // `frame.go:119-121` 报 invalid metalen → `server.go:363-384` 退出并断连接。
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    conn.send_wire(&oversized)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写超限帧", e));
    conn.expect_peer_close("超限 metaLen")
        .await
        .unwrap_or_else(|e| fail(&fixture, "超限 metaLen", e));
    eprintln!("OK: 用例 D② 超限 metaLen 本端拒绝且 Xray 关闭连接（读侧 EOF/RST）。");
}

// ---------------------------------------------------------------------------
// 用例 D③：写半个帧后关流 → 服务端关闭且无残留数据（未拨号目标）。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_truncated_frame_closes_stream() {
    let Some(bin) = xray_bin() else { return };
    let (target_addr, accepted, received) = spawn_counting_listener().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], target_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));

    // 完整 New 帧（含数据段）截成两半，只写前半段后 FIN。
    let mut sender = StreamSender::new(1, TargetNetwork::Tcp, target);
    let mut frame = Vec::new();
    sender
        .send_new(&mut frame, Some(b"must-not-arrive"))
        .expect("New 帧");
    let half = frame.len() / 2;
    assert!(half >= 2, "截断点必须落在帧长度字段之后");
    conn.send_wire(&frame[..half])
        .await
        .unwrap_or_else(|e| fail(&fixture, "写半帧", e));
    conn.shutdown_write().await;

    conn.expect_peer_close("截断帧")
        .await
        .unwrap_or_else(|e| fail(&fixture, "截断帧", e));

    // 截断点 = 完整 New 元数据 + 数据长度前缀（14+2=16 字节），载荷本体缺失。
    // 参考会先 dispatch 再读数据，故允许拨号；但半截载荷绝不能写到后端。
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        received.load(Ordering::Relaxed),
        0,
        "截断帧的数据段不得有任何字节到达后端\n{}",
        fixture.report()
    );
    assert!(
        accepted.load(Ordering::Relaxed) <= 1,
        "半帧最多触发一次拨号，不得重复派发\n{}",
        fixture.report()
    );
    eprintln!("OK: 用例 D③ 半帧 + FIN 后服务端关闭（EOF/RST），后端零字节。");
}

// ---------------------------------------------------------------------------
// 用例 D④：会话上限触顶 → 按 SessionStrategy 拒绝，而非无限分配。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_session_limit_rejects_not_unbounded() {
    let Some(_bin) = xray_bin() else { return };

    // 参考 `session.go:54-73` Allocate：MaxConcurrency 限并发、
    // MaxConnection 限累计，0 表示不限。
    let mut client = ClientSession::new(SessionStrategy {
        max_concurrency: 1,
        max_connection: 2,
    });
    let target = TargetAddr::V4([127, 0, 0, 1], 9);

    let first = client
        .open(TargetNetwork::Tcp, target.clone())
        .expect("第 1 条应分配成功");
    assert_eq!(first.id, 1);
    assert!(
        client.open(TargetNetwork::Tcp, target.clone()).is_none(),
        "并发上限 1 时第 2 条必须被拒"
    );
    assert_eq!(client.table().size(), 1);
    assert_eq!(client.table().count(), 1, "被拒的分配不得递增 count");

    client.close_local(first.id, false);
    assert_eq!(client.table().size(), 0);

    let second = client
        .open(TargetNetwork::Tcp, target.clone())
        .expect("释放并发后应可再分配");
    assert_eq!(second.id, 2);
    assert!(
        client.open(TargetNetwork::Tcp, target.clone()).is_none(),
        "累计上限 2 时第 3 条必须被拒"
    );
    assert_eq!(client.table().count(), 2);
    eprintln!("OK: 用例 D④ 会话上限按 SessionStrategy 拒绝（concurrency/connection 双限）。");
}
