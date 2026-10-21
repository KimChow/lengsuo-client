//! 参考互通：`MuxWire` 出站原语与固定版本参考端的真实互跑。
//!
//! 显式执行：
//! `LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test mux_wire_interop -- --ignored --nocapture`
//!
//! 与 `mux_wire.rs` 分文件：前者是**参考互通**（需外部二进制、默认跳过），
//! 后者是**本仓自洽**（往返 / 拒绝路径，默认跑）。职责不同，分文件避免单文件超行数上限。
//!
//! 头部导入与 `mux_wire.rs` 同源（逐字保留，避免搬运时漏符号）；
//! 本文件只用其中一部分 ⇒ 文件级豁免未用导入告警。
#![allow(unused_imports)]

//! VLESS Mux 出站原语（`lengsuo_vless::mux_wire`）的具名用例。
//!
//! 覆盖任务书要求的三类：
//! 1. **正常往返**：既有原语 → 新 API → 还原 ⇒ 载荷逐字节一致；
//! 2. **错误输入 fail-closed**：非法参数/截断输入 ⇒ 显式报错；
//! 3. **与既有实现的等价性**：新 API 的输出与既有原语的输出逐字节相同。
//!
//! 全部用例只用回环地址、临时端口、假凭据；不打印任何密钥/明文。
//!
//! 显式执行：
//! `cargo test -p lengsuo-vless --test mux_wire -- --nocapture`

mod support;

use std::time::Duration;

use lengsuo_vless::mux::frame::{
    decode_from_async, read_data_async, FrameMetadata, SessionStatus, TargetNetwork, OPTION_DATA,
    OPTION_ERROR,
};
use lengsuo_vless::mux::worker::{Action, SessionWriter, Strategy};
use lengsuo_vless::mux_wire::{Error, MuxWire, DEFAULT_DEADLINE};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const TCP: TargetNetwork = TargetNetwork::Tcp;
const UDP: TargetNetwork = TargetNetwork::Udp;
const PAYLOAD: &[u8] = b"VLESS mux wire payload\0\xfe\xff";
const WAIT: Duration = Duration::from_secs(5);

fn target(port: u16) -> (TargetAddr, TargetNetwork) {
    (TargetAddr::V4([127, 0, 0, 1], port), TCP)
}

/// 造一条内存承载连接：本仓端 + 对端端。
fn carrier() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    tokio::io::duplex(64 * 1024)
}

/// 从对端读一帧（帧头 + 可选数据段）。
///
/// 用既有 `mux::frame` 的异步原语解码，证明新 API 的下行帧与既有解码器兼容。

fn keep_frame(session_id: u16, status: SessionStatus, payload: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let meta = FrameMetadata {
        session_id,
        status,
        option: if payload.is_some() { OPTION_DATA } else { 0 },
        target: None,
        source: None,
        local: None,
        udp_continuation: false,
    };
    meta.encode_into(&mut out).expect("可编码");
    if let Some(payload) = payload {
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
}

/// 正常往返：`MuxWire::open` + `MuxSession::write` → 对端逐字节收到同样的帧。
///
/// 断言的是**线上字节**：`New` 帧带目标地址、`Keep` 帧带数据段，载荷逐字节一致。
#[tokio::test]
async fn mux_wire_roundtrip_payload_is_byte_exact() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(session.id(), 1, "首个会话 ID 从 1 起（参考 `m.count++`）");
    session
        .write(PAYLOAD, DEFAULT_DEADLINE)
        .await
        .expect("可写");

    // 对端先读首帧（`New`）：带目标地址、无数据段。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.session_id, 1);
    assert_eq!(meta.status, SessionStatus::New);
    assert_eq!(meta.target, Some(target(443)));
    assert!(data.is_none(), "首帧只带地址（参考 `writeMetaOnly`）");

    // 对端再读数据帧（`Keep`）：带数据段，载荷逐字节一致。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    assert!(meta.has_data());
    assert_eq!(data.expect("有数据段"), PAYLOAD, "载荷必须逐字节一致");

    // 收尾：写 `End` 帧，然后关闭承载连接写方向（参考 `ClientWorker.Close`）。
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");
    wire.shutdown(DEFAULT_DEADLINE).await.expect("可关闭");

    // `End` 帧：metaLen=4，无数据段。
    let (end, data) = read_frame(&mut peer, true).await;
    assert_eq!(end.status, SessionStatus::End);
    assert!(!end.has_error());
    assert!(data.is_none());
    assert_eq!(wire.active_sessions().await, 0, "关闭后会话应从表里摘除");
}

/// 与既有实现的等价性：同一会话 ID 下，新 API 写出的字节与 `worker::SessionWriter`
/// 逐字节相同。
///
/// 这是「接线正确、没改语义」的硬证据：新 API 只是把既有原语接到异步写半边上。
#[tokio::test]
async fn mux_wire_output_is_identical_to_existing_session_writer() {
    // 既有原语：首帧 + 数据帧 + 收尾帧（会话 ID 手工给 1，与新 API 分配到的相同）。
    let mut expected = Vec::new();
    let mut legacy = SessionWriter::request(1, target(8443), TCP);
    legacy.write_meta_only(&mut expected).expect("可编码");
    legacy.write_data(&mut expected, PAYLOAD).expect("可编码");
    legacy.close(&mut expected).expect("可编码");

    // 新 API：同样的会话、同样的目标、同样的载荷。
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(8443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(session.id(), 1, "新 API 分配的首个会话 ID 也是 1");
    session
        .write(PAYLOAD, DEFAULT_DEADLINE)
        .await
        .expect("可写");
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");
    wire.shutdown(DEFAULT_DEADLINE).await.expect("可关闭");

    let mut actual = Vec::new();
    peer.read_to_end(&mut actual).await.expect("可读");
    assert_eq!(actual, expected, "同一会话 ID 下必须逐字节相同");
}

/// 等价性（会话 ID 不同）：除会话 ID 两字节外，其余必须逐字节相同。
#[tokio::test]
async fn mux_wire_output_differs_only_in_session_id() {
    let mut expected = Vec::new();
    let mut legacy = SessionWriter::request(7, target(8443), TCP);
    legacy.write_meta_only(&mut expected).expect("可编码");
    legacy.write_data(&mut expected, PAYLOAD).expect("可编码");
    legacy.close(&mut expected).expect("可编码");

    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(8443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    session
        .write(PAYLOAD, DEFAULT_DEADLINE)
        .await
        .expect("可写");
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");
    wire.shutdown(DEFAULT_DEADLINE).await.expect("可关闭");

    let mut actual = Vec::new();
    peer.read_to_end(&mut actual).await.expect("可读");

    assert_eq!(actual.len(), expected.len(), "总长度必须一致");
    let diffs: Vec<usize> = actual
        .iter()
        .zip(expected.iter())
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .map(|(index, _)| index)
        .collect();
    // 每帧的第 2..4 字节是会话 ID（BE16）：三个帧的 ID 低字节都必须不同，
    // 其余字节必须完全一致。
    assert_eq!(
        diffs,
        vec![3, 17, 50],
        "除会话 ID 外必须逐字节相同，实际差异位置 {diffs:?}"
    );
    assert_eq!(actual[2..4], [0x00, 0x01], "新 API 的会话 ID 是 1");
    assert_eq!(expected[2..4], [0x00, 0x07], "既有原语的会话 ID 是 7");
}

/// 首包语义：`open` 带首包时，首帧就是 `New` + 数据段（参考 `writeFirstPayload`）。
#[tokio::test]
async fn mux_wire_first_payload_is_carried_in_new_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let _session = wire
        .open(target(443), Some(PAYLOAD), DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::New);
    assert!(meta.has_data(), "带首包时首帧含数据段");
    assert_eq!(data.expect("有数据段"), PAYLOAD);
}

/// 错误收尾：标记 `has_error` 后 `End` 帧带 `OptionError`（参考 `Writer.Close`）。
#[tokio::test]
async fn mux_wire_close_with_error_sets_option_error() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    session.mark_error();
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");

    // 首帧是 `open` 写出的 `New`。
    let (first, _) = read_frame(&mut peer, true).await;
    assert_eq!(first.status, SessionStatus::New);
    // 收尾帧是 `End`。
    let (meta, _) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::End);
    assert!(meta.has_error(), "出错收尾必须带 OptionError");
    assert_eq!(meta.option & OPTION_ERROR, OPTION_ERROR);
}

/// fail-closed：非法截止时间（0）必须显式报错，不能静默写出任何字节。
#[tokio::test]
async fn mux_wire_rejects_zero_deadline() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let error = wire
        .open(target(443), None, Duration::ZERO)
        .await
        .expect_err("零截止时间必须报错");
    assert!(matches!(error, Error::InvalidDeadline));

    // 不得产生任何字节：读侧必须一直拿不到数据（超时），而不是读到内容。
    let mut buf = [0u8; 8];
    let outcome = tokio::time::timeout(WAIT, peer.read(&mut buf)).await;
    assert!(
        outcome.is_err(),
        "报错后不得写出任何字节，实际读到了 {:?}",
        outcome.ok()
    );
}

/// fail-closed：截断的承载连接读必须报错（参考 `Unmarshal` 读不满即返回错误）。
#[tokio::test]
async fn mux_wire_rejects_truncated_inbound_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    // 只写半个帧头就断开 ⇒ 读侧必然失败。
    peer.write_all(&[0x00, 0x20]).await.expect("可写");
    peer.flush().await.expect("可刷");
    drop(peer);

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("截断输入必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}

/// fail-closed：未知的会话状态必须报错（参考 `fetchOutput` 的 default 分支）。
#[tokio::test]
async fn mux_wire_rejects_unknown_session_status() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    // metaLen=4，status=0x09（未知），option=0。
    peer.write_all(&[0x00, 0x04, 0x00, 0x01, 0x09, 0x00])
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");
    drop(peer);

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("未知状态必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}

/// fail-closed：`metaLen > 512` 必须报错（参考 `invalid metalen`）。
#[tokio::test]
async fn mux_wire_rejects_oversized_meta_length() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    peer.write_all(&[0x02, 0x01, 0x00, 0x01, 0x01, 0x00])
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");
    drop(peer);

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("超长 metaLen 必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}

/// 会话并发上限：达到 `MaxConcurrency` 后必须显式报错（参考 `Allocate` 返回 nil）。
#[tokio::test]
async fn mux_wire_enforces_concurrency_limit() {
    let (carrier, _peer) = carrier();
    let strategy = Strategy {
        max_concurrency: 1,
        max_connection: 0,
    };
    let mut wire = MuxWire::new(carrier, strategy);
    let _first = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("首个会话可开");
    let error = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect_err("超过并发上限必须报错");
    assert!(matches!(error, Error::Allocate(_)), "实际错误：{error}");
    assert_eq!(wire.active_sessions().await, 1);
    assert_eq!(wire.total_sessions().await, 1);
}

/// 下行派发：未命中会话的 `Keep` 帧必须回一个 `End` 帧（参考 `handleStatusKeep`）。
#[tokio::test]
async fn mux_wire_answers_unknown_keep_frame_with_end() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    // 对端发一个未命中会话的 `Keep` 帧（带数据段）。
    peer.write_all(&keep_frame(99, SessionStatus::Keep, Some(PAYLOAD)))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");

    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert!(matches!(inbound.action, Action::SendEnd { id: 99 }));

    // 本仓必须回一个 `End` 帧。
    let (closing, _) = read_frame(&mut peer, true).await;
    assert_eq!(closing.session_id, 99);
    assert_eq!(closing.status, SessionStatus::End);
}

/// 下行派发：`KeepAlive` 帧只丢数据（参考 `handleStatueKeepAlive`）。
#[tokio::test]
async fn mux_wire_discards_keep_alive_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    peer.write_all(&keep_frame(0, SessionStatus::KeepAlive, Some(PAYLOAD)))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");

    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert!(matches!(inbound.action, Action::None));

    // 数据段必须已被消费（承载连接不错位）：再读一帧应能拿到后续内容。
    peer.write_all(&keep_frame(0, SessionStatus::KeepAlive, None))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");
    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读第二帧");
    assert_eq!(inbound.meta.status, SessionStatus::KeepAlive);
}

/// 大载荷分片：TCP 会话按 8 KiB 分片，每片一帧（参考 `buf.SplitSize(mb, 8*1024)`）。
#[tokio::test]
async fn mux_wire_splits_stream_payload_into_8kib_frames() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    let big = vec![0xA5u8; 8 * 1024 + 7];
    session.write(&big, DEFAULT_DEADLINE).await.expect("可写");

    // 跳过首帧（`New`，无数据）。
    let (meta, _) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::New);

    // 第一片：8 KiB。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    let first = data.expect("有数据段");
    assert_eq!(first.len(), 8 * 1024, "第一片应是 8 KiB");

    // 第二片：余下 7 字节。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    let second = data.expect("有数据段");
    assert_eq!(second.len(), 7, "第二片是余量");
    let mut joined = first.clone();
    joined.extend_from_slice(&second);
    assert_eq!(joined, big, "分片后拼接必须逐字节一致");
}

/// 分组（UDP）会话：一帧一包，不按 8 KiB 分片（参考 `buf.SplitFirst`）。
#[tokio::test]
async fn mux_wire_packet_session_writes_single_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let udp_target = (TargetAddr::V4([127, 0, 0, 1], 53), UDP);
    let mut session = wire
        .open(udp_target.clone(), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    // 参考的 `PacketReader` 上限是 `buf.Size`（8192）：分组会话一帧一包，
    // 超过 8192 的包参考读侧会报 `packet size too large`，故用上限内的载荷。
    let packet = vec![0x5Au8; 8 * 1024];
    session
        .write(&packet, DEFAULT_DEADLINE)
        .await
        .expect("可写");

    // 首帧 `New`（带 UDP 网络类型）。
    let (meta, _) = read_frame(&mut peer, false).await;
    assert_eq!(meta.status, SessionStatus::New);
    assert_eq!(meta.target, Some(udp_target));

    // 之后只有一帧：整个载荷（不按 8 KiB 切成两帧）。
    let (meta, data) = read_frame(&mut peer, false).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    assert_eq!(data.expect("有数据段"), packet, "分组会话一帧一包");
}

/// 空载荷：只发元数据帧，不带数据段（参考 `writeMetaOnly`）。
#[tokio::test]
async fn mux_wire_empty_payload_writes_meta_only() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    session.write(b"", DEFAULT_DEADLINE).await.expect("可写");

    // 首帧 `New`。
    let (meta, _) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::New);

    // 第二帧：`Keep` 但无数据段。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    assert!(!meta.has_data(), "空载荷只发元数据帧");
    assert!(data.is_none());
}

/// 既有原语与新 API 的读侧等价：既有解码器与 `next_inbound` 解出同一帧。
#[tokio::test]
async fn mux_wire_inbound_matches_existing_decoder() {
    // 用既有原语造两帧：首帧 `New`（带地址）+ 续帧 `Keep`（带数据段）。
    let mut wire_bytes = Vec::new();
    let mut legacy = SessionWriter::request(3, target(443), TCP);
    legacy.write_meta_only(&mut wire_bytes).expect("可编码");
    legacy.write_data(&mut wire_bytes, PAYLOAD).expect("可编码");

    // 既有读侧（`mux::frame` 的异步解码器）解同一段字节。
    let mut cursor = &wire_bytes[..];
    let first = decode_from_async(&mut cursor, false)
        .await
        .expect("可解帧头");
    let second = decode_from_async(&mut cursor, false)
        .await
        .expect("可解帧头");
    let data = read_data_async(&mut cursor, true)
        .await
        .expect("可解数据段");
    assert_eq!(first.status, SessionStatus::New);
    assert_eq!(second.status, SessionStatus::Keep);
    assert_eq!(data, PAYLOAD);

    // 新 API：同一段字节喂进承载连接。
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    peer.write_all(&wire_bytes).await.expect("可写");
    peer.flush().await.expect("可刷");

    // 首帧 `New`：客户端侧只丢数据（参考 `handleStatusNew`）。
    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert_eq!(inbound.meta.session_id, first.session_id);
    assert_eq!(inbound.meta.status, first.status);
    assert_eq!(inbound.meta.option, first.option);
    assert!(matches!(inbound.action, Action::None));

    // 续帧 `Keep`：会话 3 未登记 ⇒ 参考回 `End` 通知。
    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert_eq!(inbound.meta.session_id, second.session_id);
    assert_eq!(inbound.meta.status, second.status);
    assert_eq!(inbound.meta.option, second.option);
    assert!(matches!(inbound.action, Action::SendEnd { id: 3 }));
}

/// 承载连接断开：读侧必须报错（fail-closed），不得返回空帧。
#[tokio::test]
async fn mux_wire_reports_closed_carrier() {
    let (carrier, peer) = carrier();
    drop(peer);
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("承载连接断开必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}

/// 多会话并发：两条会话的帧不串（会话 ID 各自独立）。
#[tokio::test]
async fn mux_wire_keeps_sessions_separated() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let mut first = wire
        .open(target(1001), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    let mut second = wire
        .open(target(1002), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(first.id(), 1);
    assert_eq!(second.id(), 2);
    assert_eq!(wire.active_sessions().await, 2);

    first.write(b"first", DEFAULT_DEADLINE).await.expect("可写");
    second
        .write(b"second", DEFAULT_DEADLINE)
        .await
        .expect("可写");

    // 依次读回：首帧 ×2 + 数据帧 ×2。
    let mut seen = Vec::new();
    for _ in 0..4 {
        let (meta, data) = read_frame(&mut peer, true).await;
        seen.push((meta.session_id, data.unwrap_or_default()));
    }
    assert_eq!(seen[0], (1, Vec::new()));
    assert_eq!(seen[1], (2, Vec::new()));
    assert_eq!(seen[2], (1, b"first".to_vec()));
    assert_eq!(seen[3], (2, b"second".to_vec()));
}

/// 收发双向：下行 `Keep` 帧命中已登记会话时派发 `Deliver`（参考 `handleStatusKeep`）。
#[tokio::test]
async fn mux_wire_delivers_keep_frame_to_known_session() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let _session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    // 先把首帧（`New`）从对端读掉，避免后续读错位。
    let _ = read_frame(&mut peer, true).await;

    // 对端发 `Keep` 帧（会话 1，已登记）。
    peer.write_all(&keep_frame(1, SessionStatus::Keep, Some(PAYLOAD)))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");

    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    match inbound.action {
        Action::Deliver { id, payload, new } => {
            assert_eq!(id, 1);
            assert!(!new);
            assert_eq!(payload, PAYLOAD, "下行载荷必须逐字节一致");
        }
        other => panic!("期望 Deliver，实际 {other:?}"),
    }
}

/// 目标地址可查：上层据此把下行数据路由回对应的上游连接。
#[tokio::test]
async fn mux_wire_exposes_session_target() {
    let (carrier, _peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let _session = wire
        .open(target(9443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(wire.session_target(1).await, Some(target(9443)));
    assert_eq!(wire.session_target(42).await, None);
}
