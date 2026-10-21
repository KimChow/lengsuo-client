//! UDP 环回收发往返用例。
//!
//! 覆盖任务书六·1–3：
//! 1. 环回往返：发出的帧在对面逐字节还原（类型 / 序号 / 载荷）；
//! 2. 零长 keepalive：空载荷帧能正常发出与接收；
//! 3. 超大载荷被拒：`encode` 明确报错，**不截断、不发出**。
//!
//! 另附两条边界用例：满帧（正好一个 MTU 预算）往返、keepalive 任务按
//! **上层给定的间隔**发零长 keepalive。
//!
//! 纪律：每个异步用例都带硬超时，不许挂死。

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_link_core::frame::{
    Frame, FrameError, FrameType, FRAME_HEADER_LEN, MAX_FRAME_LEN, MAX_FRAME_PAYLOAD_LEN,
};
use lengsuo_tunnel::udp::{Cancel, KeepaliveConfig, UdpEndpoint, UdpError};

/// 异步用例的硬超时。
const TIMEOUT: Duration = Duration::from_secs(5);
/// 「确认没有收到」用的短超时。
const QUIET: Duration = Duration::from_millis(300);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("回环地址可解析")
}

async fn endpoint() -> UdpEndpoint {
    UdpEndpoint::bind(loopback())
        .await
        .expect("绑定回环端口应当成功")
}

/// 建一对互指的对端：各自 `connect` 到对方的实际地址。
async fn pair() -> (UdpEndpoint, UdpEndpoint) {
    let mut a = endpoint().await;
    let mut b = endpoint().await;
    a.set_peer_endpoint(b.local_addr().expect("取本端地址"))
        .await
        .expect("设置对端地址应当成功");
    b.set_peer_endpoint(a.local_addr().expect("取本端地址"))
        .await
        .expect("设置对端地址应当成功");
    (a, b)
}

/// 一块足以放下「一个满帧 + 1 字节」的接收缓冲。
fn buffer() -> Vec<u8> {
    vec![0u8; MAX_FRAME_LEN + 1]
}

// ---------------------------------------------------------------- 1. 环回往返

#[tokio::test]
async fn frame_roundtrip_over_loopback_preserves_bytes() {
    let (a, b) = pair().await;

    let payload = b"\x00\x01\x02ACP-frame-payload\xff\x7f".to_vec();
    let frame = Frame::new(FrameType::Data, 42, payload.clone());

    let sent = a.send_frame(&frame).await.expect("发送应当成功");
    assert_eq!(
        sent,
        FRAME_HEADER_LEN + payload.len(),
        "发出的字节数必须是帧头 + 载荷（不多不少）"
    );

    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b.recv_frame(&mut buf))
        .await
        .expect("回环往返必须在超时内完成")
        .expect("对面应当收到一个合法帧");

    assert_eq!(got.frame_type, frame.frame_type, "帧类型必须一致");
    assert_eq!(got.seq, frame.seq, "帧序号必须一致");
    assert_eq!(got.payload, payload, "载荷必须逐字节相同");
}

// --------------------------------------------------- 2. 零长载荷 keepalive

#[tokio::test]
async fn zero_length_keepalive_roundtrips() {
    let (a, b) = pair().await;

    let frame = Frame::new(FrameType::Keepalive, 0, Vec::new());
    let sent = a.send_frame(&frame).await.expect("发送应当成功");
    assert_eq!(sent, FRAME_HEADER_LEN, "零长载荷的帧只有帧头");

    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b.recv_frame(&mut buf))
        .await
        .expect("keepalive 必须在超时内到达")
        .expect("应当收到一个合法帧");

    assert_eq!(
        got.frame_type,
        FrameType::Keepalive,
        "帧类型必须是 keepalive"
    );
    assert_eq!(got.seq, 0);
    assert!(got.payload.is_empty(), "keepalive 的载荷必须零长");
}

// ----------------------------------------------------- 3. 超大载荷被拒

#[tokio::test]
async fn oversized_payload_is_rejected_without_sending() {
    let (a, b) = pair().await;

    let frame = Frame::new(FrameType::Data, 1, vec![0u8; MAX_FRAME_PAYLOAD_LEN + 1]);

    // (a) 编码器明确报错，不截断。
    match frame.encode() {
        Err(FrameError::PayloadTooLong { declared, limit }) => {
            assert_eq!(declared, MAX_FRAME_PAYLOAD_LEN + 1, "不得截断成上限长度");
            assert_eq!(limit, MAX_FRAME_PAYLOAD_LEN);
        }
        other => panic!("期望 PayloadTooLong，实际 {other:?}"),
    }

    // (b) 发送侧同样拒绝，且**一个字节都不发**。
    match a.send_frame(&frame).await {
        Err(UdpError::Encode(FrameError::PayloadTooLong { .. })) => {}
        other => panic!("期望 UdpError::Encode，实际 {other:?}"),
    }

    // (c) 对面确实什么都没收到。
    let mut buf = buffer();
    let received = tokio::time::timeout(QUIET, b.recv_frame(&mut buf)).await;
    assert!(received.is_err(), "超限帧不允许被发出");
}

// ------------------------------------------------------ 4. 满帧往返（MTU 预算）

#[tokio::test]
async fn max_size_frame_roundtrips_in_one_datagram() {
    let (a, b) = pair().await;

    let payload = vec![0xA5u8; MAX_FRAME_PAYLOAD_LEN];
    let frame = Frame::new(FrameType::Data, u64::MAX, payload.clone());

    let sent = a.send_frame(&frame).await.expect("发送应当成功");
    assert_eq!(sent, MAX_FRAME_LEN, "满帧正好是单帧总长上限");

    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b.recv_frame(&mut buf))
        .await
        .expect("满帧必须在超时内到达")
        .expect("应当收到一个合法帧");
    assert_eq!(got.payload, payload, "满帧载荷必须逐字节相同");
}

// ------------------------------------------- 5. keepalive 任务（间隔由上层给）

#[tokio::test]
async fn keepalive_task_emits_zero_length_keepalive_frames() {
    let (a, b) = pair().await;

    let cancel = Cancel::new();
    let handle = lengsuo_tunnel::udp::spawn_keepalive(
        a.clone(),
        KeepaliveConfig {
            interval: Some(Duration::from_millis(50)),
        },
        cancel.clone(),
    )
    .expect("给了间隔就应当启动 keepalive 任务");

    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b.recv_frame(&mut buf))
        .await
        .expect("keepalive 必须在超时内到达")
        .expect("应当收到一个合法帧");

    assert_eq!(got.frame_type, FrameType::Keepalive);
    assert!(got.payload.is_empty(), "keepalive 的载荷必须零长");

    let outcome = tokio::time::timeout(TIMEOUT, handle.stop())
        .await
        .expect("keepalive 任务必须在超时内退出");
    assert!(
        matches!(outcome, lengsuo_tunnel::udp::KeepaliveOutcome::Cancelled),
        "取消后应当以 Cancelled 收场，实际 {outcome:?}"
    );
}

#[tokio::test]
async fn keepalive_config_without_interval_is_disabled() {
    let (a, _b) = pair().await;
    let handle =
        lengsuo_tunnel::udp::spawn_keepalive(a, KeepaliveConfig { interval: None }, Cancel::new());
    assert!(handle.is_none(), "没有间隔就等于关闭 keepalive");
}
