//! UDP 收发循环的失败路径用例。
//!
//! 覆盖任务书六·4–7：
//! 4. 坏包只丢一包：非法帧字节灌进去，收发循环**继续**跑，后续合法帧仍能收到；
//! 5. socket 错误上报：向未监听端口发包并等回包 ⇒ 得到**连接级**错误，不是静默丢弃；
//! 6. 循环可结束：取消 / 关闭后，收发循环**确定退出**（带硬超时）；
//! 7. peer endpoint 可更新：`set_peer_endpoint` 之后收发打到**新地址**。
//!
//! 关键断言：**两级错误必须可区分**——单包坏是 `UdpEvent::BadDatagram`（循环继续），
//! 连接坏是 `UdpError::Socket`（上报并结束）。

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_link_core::frame::{Frame, FrameType, MAX_FRAME_LEN};
use lengsuo_tunnel::udp::{
    Cancel, ErrorSeverity, LoopOutcome, UdpEndpoint, UdpError, UdpEvent,
    DEFAULT_RECV_QUEUE_CAPACITY,
};

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

/// 建一对互指的对端。
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

/// 下一个事件（带超时）。
async fn next_event(rx: &mut tokio::sync::mpsc::Receiver<UdpEvent>) -> UdpEvent {
    tokio::time::timeout(TIMEOUT, rx.recv())
        .await
        .expect("事件必须在超时内到达")
        .expect("事件通道不应关闭")
}

// ------------------------------------------------ 4. 坏包只丢一包（链路不死）

#[tokio::test]
async fn malformed_datagram_is_dropped_but_loop_keeps_running() {
    let (a, b) = pair().await;

    let cancel = Cancel::new();
    let (mut events, handle) = lengsuo_tunnel::udp::spawn_recv_loop(
        a.clone(),
        DEFAULT_RECV_QUEUE_CAPACITY,
        cancel.clone(),
    );

    // 灌一个**非法帧字节**（魔数不对 ⇒ 解码必然失败）。
    b.send_raw(b"not-a-frame-at-all-just-garbage")
        .await
        .expect("发出坏包应当成功");

    // 循环**没有**死：紧接着的合法帧仍能收到。
    b.send_frame(&Frame::new(FrameType::Data, 7, b"good-payload".to_vec()))
        .await
        .expect("发送合法帧应当成功");

    // 第一个事件是坏包（单包级）。
    let first = next_event(&mut events).await;
    match &first {
        UdpEvent::BadDatagram { source, reason } => {
            assert_eq!(*source, b.local_addr().expect("取对端地址"));
            assert!(
                matches!(
                    reason,
                    lengsuo_link_core::frame::FrameError::BadMagic { .. }
                ),
                "坏包的失败原因应当是帧层解码失败，实际 {reason:?}"
            );
        }
        other => panic!("第一个事件应当是坏包，实际 {other:?}"),
    }
    assert_eq!(
        first.severity(),
        Some(ErrorSeverity::Packet),
        "解码失败必须是单包级：只丢这一包"
    );
    assert!(!first.is_fatal(), "单包级错误不致命：链路必须继续");

    // 第二个事件是合法帧 ⇒ 循环**继续**跑。
    let second = next_event(&mut events).await;
    match second {
        UdpEvent::Frame(frame) => {
            assert_eq!(frame.seq, 7);
            assert_eq!(frame.payload, b"good-payload");
        }
        other => panic!("第二个事件应当是合法帧，实际 {other:?}"),
    }

    let outcome = tokio::time::timeout(TIMEOUT, handle.stop())
        .await
        .expect("循环必须在超时内退出");
    assert!(matches!(outcome, LoopOutcome::Cancelled));
}

// ------------------------------------------------ 5. socket 错误上报（连接级）

#[tokio::test]
async fn unreachable_peer_yields_connection_level_error() {
    // 取一个「已关闭」的端口：绑了再放，端口即无人监听。
    let dead = endpoint().await;
    let dead_addr = dead.local_addr().expect("取本端地址");
    drop(dead);

    let mut a = UdpEndpoint::bind(loopback()).await.expect("绑定应当成功");
    a.set_peer_endpoint(dead_addr)
        .await
        .expect("设置对端地址应当成功");

    // 向未监听端口发包。
    let mut send_error = None;
    if let Err(err) = a
        .send_frame(&Frame::new(FrameType::Data, 1, b"ping".to_vec()))
        .await
    {
        send_error = Some(err);
    }

    // 等回包 ⇒ 必须拿到**明确的连接级错误**。
    let mut buf = vec![0u8; MAX_FRAME_LEN + 1];
    let recv_result = tokio::time::timeout(TIMEOUT, a.recv_frame(&mut buf)).await;

    let observed = match recv_result {
        Ok(Err(err)) => Some(err),
        Ok(Ok(_)) => panic!("未监听端口不可能回包"),
        Err(_) => None, // 超时：改看发送侧是否已经报错
    };

    let err = observed
        .or(send_error)
        .expect("向未监听端口发包并等回包，必须得到连接级错误，而不是静默丢弃");

    match err {
        UdpError::Socket { .. } => {
            assert_eq!(
                err.severity(),
                ErrorSeverity::Connection,
                "socket 级错误必须判为连接级：应当上报并结束"
            );
        }
        other => panic!("期望连接级错误，实际 {other:?}"),
    }
}

// ---------------------------------------------------- 6. 循环可结束（可取消）

#[tokio::test]
async fn recv_loop_stops_on_cancel() {
    let (a, _b) = pair().await;
    let cancel = Cancel::new();
    let (_events, handle) =
        lengsuo_tunnel::udp::spawn_recv_loop(a, DEFAULT_RECV_QUEUE_CAPACITY, cancel.clone());

    cancel.cancel();

    let outcome = tokio::time::timeout(TIMEOUT, handle.stop())
        .await
        .expect("循环必须在超时内退出，不许挂死");
    assert!(
        matches!(outcome, LoopOutcome::Cancelled),
        "取消后应当以 Cancelled 收场，实际 {outcome:?}"
    );
}

#[tokio::test]
async fn recv_loop_stops_when_event_channel_is_closed() {
    let (a, _b) = pair().await;
    let cancel = Cancel::new();
    let (events, handle) =
        lengsuo_tunnel::udp::spawn_recv_loop(a, DEFAULT_RECV_QUEUE_CAPACITY, cancel.clone());

    // 上层关掉接收端 ⇒ 循环应当**自己**结束（不靠主动取消）。
    drop(events);

    let outcome = tokio::time::timeout(TIMEOUT, handle.join())
        .await
        .expect("循环必须在超时内退出，不许挂死");
    assert!(
        matches!(outcome, LoopOutcome::ChannelClosed),
        "上层关闭后应当以 ChannelClosed 收场，实际 {outcome:?}"
    );
}

// -------------------------------------------- 7. peer endpoint 可更新（漫游口）

#[tokio::test]
async fn set_peer_endpoint_retargets_traffic() {
    let mut a = endpoint().await;
    let mut b = endpoint().await;
    let mut c = endpoint().await;

    // 初始对端是 b。
    a.set_peer_endpoint(b.local_addr().expect("取本端地址"))
        .await
        .expect("设置对端地址应当成功");
    b.set_peer_endpoint(a.local_addr().expect("取本端地址"))
        .await
        .expect("设置对端地址应当成功");

    // 漫游：把对端换成 c。
    a.set_peer_endpoint(c.local_addr().expect("取本端地址"))
        .await
        .expect("更新对端地址应当成功");
    c.set_peer_endpoint(a.local_addr().expect("取本端地址"))
        .await
        .expect("设置对端地址应当成功");

    assert_eq!(
        a.peer_endpoint().expect("应当有对端地址"),
        c.local_addr().expect("取本端地址"),
        "对端地址必须已经更新"
    );

    // 收：从新地址 c 来。
    a.send_frame(&Frame::new(FrameType::Data, 9, b"roamed".to_vec()))
        .await
        .expect("发送应当成功");
    let mut buf = vec![0u8; MAX_FRAME_LEN + 1];
    let got = tokio::time::timeout(TIMEOUT, c.recv_frame(&mut buf))
        .await
        .expect("新对端必须在超时内收到")
        .expect("新对端应当收到合法帧");
    assert_eq!(got.payload, b"roamed");
    assert_eq!(got.seq, 9);

    // 发：新对端 c 的回包也应当打到 a。
    c.send_frame(&Frame::new(FrameType::Data, 10, b"back".to_vec()))
        .await
        .expect("发送应当成功");
    let got = tokio::time::timeout(TIMEOUT, a.recv_frame(&mut buf))
        .await
        .expect("本端必须在超时内收到")
        .expect("本端应当收到合法帧");
    assert_eq!(got.payload, b"back");

    // 旧对端 b 不再收到（对端确实换了）。
    let quiet = tokio::time::timeout(QUIET, b.recv_frame(&mut buf)).await;
    assert!(quiet.is_err(), "旧对端不应再收到数据");
}
