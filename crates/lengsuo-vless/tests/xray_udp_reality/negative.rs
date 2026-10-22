//! ② 用例：异常路径必须 fail-closed。
//!
//! 三类异常：截断的 XUDP 包封、篡改的目标地址、超长报文。每条都断言：
//!
//! - 服务端**没有产出任何包封**（没有把残缺/非法字节当成普通载荷）；
//! - 服务端**没有发起任何 UDP 拨号**（没有静默直连）；
//! - **没有任何 TCP 连接落到探针上**（没有回落成 TCP 拨号）。
//!
//! 探针与 UDP 目标**同端口号**（TCP/UDP 是不同协议空间，可以共存），所以任何
//! 「改用 TCP 连同一个目标」的行为都会被探针当场抓到。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::support::*;
use lengsuo_vless::{
    reality::udp::{self, Error as UdpError, UdpSession},
    stream,
};
use ss_core::target::TargetAddr;
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time::timeout};

/// 一条负例会话：探针 + 回显目标 + REALITY 服务端 + 已握手的客户端。
struct Negative {
    /// TCP 探针：端口号与 UDP 目标相同，任何 TCP 回落都会落到这里。
    probe: TcpListener,
    /// 拨号记录：任何 UDP 回落／静默直连都会留痕。
    dials: DialLog,
    /// 服务端会话任务。
    task: JoinHandle<Served>,
    /// 客户端已握手的 REALITY 连接。
    stream: lengsuo_vless::reality_link::RealityStream,
    /// 目标地址（与探针同端口号）。
    target: TargetAddr,
    /// 目标端口号。
    port: u16,
}

impl Negative {
    /// 断言 fail-closed：没有包封、没有 UDP 拨号、没有 TCP 回落。
    async fn assert_fail_closed(self) -> Served {
        let Negative {
            probe,
            dials,
            task,
            stream,
            ..
        } = self;
        // 客户端连接必须活到服务端判定之后，否则服务端看到的是提前的 EOF。
        let _keep_alive = stream;
        let served = task.await.unwrap();
        assert!(
            served.packets.is_empty(),
            "异常路径不得产出任何包封：{:?}",
            served.packets
        );
        assert!(
            dials.lock().unwrap().is_empty(),
            "异常路径不得发起任何 UDP 拨号（不得静默直连）"
        );
        assert!(
            timeout(Duration::from_millis(300), probe.accept())
                .await
                .is_err(),
            "异常路径不得回落成 TCP 拨号"
        );
        served
    }
}

/// 起一条负例会话。
async fn negative_session() -> Negative {
    // TCP 探针先占端口：端口号与 UDP 目标相同 —— 任何 TCP 回落都会落到这里。
    let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = probe.local_addr().unwrap().port();
    let (echo_addr, _echo) = start_echo(SocketAddr::from(([127, 0, 0, 1], port))).await;
    assert_eq!(echo_addr.port(), port, "UDP 目标与 TCP 探针必须同端口号");
    let target = TargetAddr::V4([127, 0, 0, 1], port);

    let server = Arc::new(Server::new());
    let server_port = reserve_port();
    let dials = DialLog::default();
    let tasks = start_servers(server.clone(), server_port, dials.clone(), 1, NEGATIVE_STEP).await;
    let stream = connect_client(&server.client_config(), server_port)
        .await
        .unwrap();

    Negative {
        probe,
        dials,
        task: tasks.into_iter().next().unwrap(),
        stream,
        target,
        port,
    }
}

/// **截断的 XUDP 包封**：服务端必须拒绝，不得把残缺字节当普通载荷，也不得拨号。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncated_xudp_envelope_fails_closed() {
    timeout(DEADLINE, async {
        // 三个截断点：长度前缀的一半、元数据中间、载荷中间。
        for cut in [2usize, 8, 16] {
            let mut session = negative_session().await;
            let mut envelope = valid_envelope(&session.target).await;
            assert!(envelope.len() > cut, "包封长度不足以截断");
            envelope.truncate(cut);
            session
                .stream
                .write_all(&envelope)
                .await
                .expect("写截断包封");
            let served = session.assert_fail_closed().await;
            // 截断的包封：服务端读不满一帧 → 只能等到截止时间，绝不能把残缺
            // 字节当成一个完整包封处理。
            assert!(
                matches!(&served.stop, Stop::Failed(reason) if reason.contains("超时")),
                "截断的包封必须被拒绝：{:?}",
                served.stop
            );
        }
    })
    .await
    .expect("用例总超时");
}

/// **篡改的目标地址**：地址类型字节非法、域名长度越界 —— 都必须被拒绝。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_target_address_fails_closed() {
    timeout(DEADLINE, async {
        // 篡改地址类型字节（IPv4=1 → 非法类型 9）。
        {
            let mut session = negative_session().await;
            let mut envelope = valid_envelope(&session.target).await;
            // 线格式：[2B 元数据长度][元数据][2B 载荷长度][载荷]；元数据第 7 字节是地址类型。
            let type_offset = 2 + 7;
            assert_eq!(envelope[type_offset], 1, "地址类型字节位置不对");
            envelope[type_offset] = 9;
            session
                .stream
                .write_all(&envelope)
                .await
                .expect("写篡改包封");
            let served = session.assert_fail_closed().await;
            // 非法地址类型：必须**当场解析失败**（不是等超时）。
            assert!(
                matches!(&served.stop, Stop::Failed(reason) if reason.contains("协议字段无效")),
                "非法地址类型必须被拒绝：{:?}",
                served.stop
            );
        }
        // 篡改域名长度字节（域名目标：元数据第 8 字节是域名长度）。
        {
            let mut session = negative_session().await;
            let domain = TargetAddr::Domain(FAKE_DOMAIN.to_owned(), session.port);
            let mut envelope = valid_envelope(&domain).await;
            assert_eq!(envelope[2 + 7], 2, "域名目标的地址类型应为 2");
            assert_eq!(envelope[2 + 8], FAKE_DOMAIN.len() as u8, "域名长度位置不对");
            envelope[2 + 8] = 255;
            session
                .stream
                .write_all(&envelope)
                .await
                .expect("写篡改包封");
            let served = session.assert_fail_closed().await;
            // 越界的域名长度：同样必须当场解析失败。
            assert!(
                matches!(&served.stop, Stop::Failed(reason) if reason.contains("协议字段无效")),
                "越界的域名长度必须被拒绝：{:?}",
                served.stop
            );
        }
    })
    .await
    .expect("用例总超时");
}

/// **超长报文**：超过 `u16` 长度上限必须报 `FrameTooLarge`，不得截断后静默发出。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_datagram_is_rejected() {
    timeout(DEADLINE, async {
        let mut session = negative_session().await;
        let huge = vec![0x5a; 65536];

        // XUDP 包封入口：超长必须报 FrameTooLarge，且不得写出任何字节。
        let mut udp = UdpSession::client(session.target.clone());
        let error = udp
            .send(&mut session.stream, &huge, STEP)
            .await
            .expect_err("超长报文必须被拒绝");
        assert!(
            matches!(error, UdpError::Stream(stream::Error::FrameTooLarge)),
            "{error:?}"
        );

        // 裸数据报入口：同样语义。
        let error = udp::send_datagram(&mut session.stream, &huge, STEP)
            .await
            .expect_err("超长报文必须被拒绝");
        assert!(
            matches!(error, UdpError::Stream(stream::Error::FrameTooLarge)),
            "{error:?}"
        );

        session.stream.shutdown().await.unwrap();
        let served = session.assert_fail_closed().await;
        assert!(
            matches!(served.stop, Stop::Closed),
            "客户端关闭后服务端应正常结束：{:?}",
            served.stop
        );
    })
    .await
    .expect("用例总超时");
}

/// **UDP 目标不可达**：网络失败**不得**回落成 TCP 拨号。
///
/// 这里目标地址是**已知**的（包封本身合法），所以「回落成 TCP 连同一个
/// 目标」是完全可能的错误实现——TCP 探针就监听在同一个端口号上
/// （TCP/UDP 是不同协议空间），任何回落都会被当场抓到。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_udp_target_does_not_fall_back_to_tcp() {
    timeout(DEADLINE, async {
        // TCP 探针占端口 P；UDP 侧刻意**不**监听 P —— UDP 目标不可达。
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        let target = TargetAddr::V4([127, 0, 0, 1], port);

        let server = Arc::new(Server::new());
        let server_port = reserve_port();
        let dials = DialLog::default();
        let tasks =
            start_servers(server.clone(), server_port, dials.clone(), 1, NEGATIVE_STEP).await;
        let mut stream = connect_client(&server.client_config(), server_port)
            .await
            .unwrap();
        let mut udp = UdpSession::client(target.clone());
        udp.send(&mut stream, b"probe", STEP).await.unwrap();

        // 服务端会真去拨这个 UDP 目标（目标合法）；随后必须**失败收场**，
        // 而不是改用 TCP 再连一次。
        let served = tasks.into_iter().next().unwrap().await.unwrap();
        assert!(
            matches!(&served.stop, Stop::Failed(reason) if !reason.is_empty()),
            "UDP 目标不可达时必须失败收场：{:?}",
            served.stop
        );
        assert_eq!(dials.lock().unwrap().len(), 1, "只允许 UDP 目标那一次拨号");
        assert!(
            timeout(Duration::from_millis(300), probe.accept())
                .await
                .is_err(),
            "UDP 不可达时不得回落成 TCP 拨号"
        );
    })
    .await
    .expect("用例总超时");
}
