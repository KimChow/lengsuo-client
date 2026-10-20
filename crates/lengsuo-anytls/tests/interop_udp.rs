//! UDP-over-TCP v2 与官方 anytls-server v0.0.13 的真实互通（客户端方向）。
//! 默认 `#[ignore]`，需要 `LENGSUO_ANYTLS_SERVER` 与 `openssl`。
//!
//! 链路：本仓 UDP-over-TCP v2 编码 → anytls 流 → 官方 server 的
//! `proxyOutboundUoT`（`uot.ReadRequest` + `uot.Conn`）→ 本机 UDP echo。
//! 官方 server 的 UoT 实现是回程的**唯一对手方**，因此本用例不是自家 roundtrip：
//! 两边各自独立实现了 `uot` 线格式，字节不一致就会立刻失败。
//!
//! 只绑 127.0.0.1、假口令、随机端口；UDP echo 服务端只回显，不解释 anytls。
#[path = "interop_client/harness.rs"]
mod harness;
#[path = "interop/support.rs"]
mod support;
#[path = "interop_client/tls.rs"]
mod tls;

use lengsuo_anytls::frame::{Command, Frame};
use lengsuo_anytls::stream::{
    socks::SocksAddr, Address, Association, Datagram, UdpVersion, UotRequest, MAGIC_ADDRESS_V2,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WAIT: Duration = Duration::from_secs(10);

/// 本机 UDP echo：回显每个数据报，不解释内容，也不属于 anytls。
async fn spawn_udp_echo() -> std::net::SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP echo 绑定失败");
    let addr = socket.local_addr().expect("UDP echo 地址");
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((count, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            if socket.send_to(&buffer[..count], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// 把 UDP 目标编码成 anytls 流的 SOCKS 首字节（魔域），这是请求 UDP 的唯一方式。
fn magic_socks_addr() -> Vec<u8> {
    SocksAddr::Fqdn(MAGIC_ADDRESS_V2.to_owned(), 0)
        .encode()
        .expect("魔域地址可编码")
}

/// 流建立时的 UoT 握手：SOCKS 魔域 + UoT 请求头，只发送一次。
async fn udp_handshake<S>(
    stream: &mut S,
    stream_id: u32,
    association: &Association,
) -> Result<(), String>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut header = Vec::new();
    header.extend_from_slice(&magic_socks_addr());
    header.extend_from_slice(
        &association
            .request
            .encode()
            .map_err(|err| err.to_string())?,
    );
    Frame {
        command: Command::Push,
        stream_id,
        data: header,
    }
    .write(stream, WAIT)
    .await
    .map_err(|err| format!("写 UoT 握手失败：{err}"))?;
    Ok(())
}

/// 单个 UDP 报文的收发：写 `请求头 + 报文`，读回程报文并逐字节比对。
/// `is_connect=true`（参考 `DialEarlyConn(conn, true, destination)` 的同义用法）。
#[allow(clippy::too_many_arguments)]
async fn udp_roundtrip<S>(
    stream: &mut S,
    state: &mut lengsuo_anytls::client_state::ClientState,
    stream_id: u32,
    association: &Association,
    target: std::net::SocketAddr,
    payloads: &[Vec<u8>],
    is_connect: bool,
) -> Result<Vec<Vec<u8>>, String>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // 请求头只在流建立时发送一次（服务端 `uot.ReadRequest` 每条流只读一遍）。
    // 后续每个往返只发报文，重复发请求头会把字节流错位。
    let mut outbound = Vec::new();
    for payload in payloads {
        let datagram = Datagram {
            address: if is_connect {
                None
            } else {
                Some(uot_address(target))
            },
            payload: payload.clone(),
        };
        outbound.extend_from_slice(
            &association
                .encode_datagram(&datagram)
                .map_err(|err| err.to_string())?,
        );
    }

    // 单条 PUSH 送出（UoT 是字节流，允许一条 PUSH 里含多个报文）。
    Frame {
        command: Command::Push,
        stream_id,
        data: outbound,
    }
    .write(stream, WAIT)
    .await
    .map_err(|err| format!("写 UDP 载荷失败：{err}"))?;

    // 逐条读回程报文：回程同样是 UoT 字节流，按同一线格式切分。
    let mut echo = Vec::new();
    let mut buffer = Vec::new();
    while echo.len() < payloads.len() {
        let frame = Frame::read(stream, u16::MAX, WAIT)
            .await
            .map_err(|err| format!("读回程帧失败：{err}"))?;
        match frame.command {
            Command::Push => {
                if frame.stream_id != stream_id {
                    return Err(format!(
                        "回程流编号异常：{}（期望 {stream_id}）",
                        frame.stream_id
                    ));
                }
                buffer.extend_from_slice(&frame.data);
                // 尽量把已缓冲字节切成完整报文。
                loop {
                    match association.decode_datagram(&buffer) {
                        Ok((datagram, consumed)) => {
                            buffer.drain(..consumed);
                            echo.push(datagram.payload);
                        }
                        Err(lengsuo_anytls::stream::StreamError::Incomplete) => break,
                        Err(err) => return Err(format!("回程报文解码失败：{err}")),
                    }
                }
            }
            // 协议控制帧先于数据到达属正常时序（官方 server 会下发
            // ServerSettings、SYNACK，必要时还有 UpdatePadding）。
            // 用状态机核对它们，而不是把它们当异常——否则会掩盖真实协议违规。
            Command::Waste
            | Command::ServerSettings
            | Command::SynAck
            | Command::UpdatePadding
            | Command::HeartRequest => {
                let event = state
                    .accept(&frame)
                    .map_err(|err| format!("回程控制帧被状态机拒绝：{err}"))?;
                println!("回程控制帧 {:?} -> {event:?}", frame.command);
            }
            // Alert 与方向违规必须立刻失败（fail-closed）。
            other => return Err(format!("回程出现非预期命令：{other:?}")),
        }
    }
    Ok(echo)
}

fn socks_target(target: std::net::SocketAddr) -> SocksAddr {
    match target {
        std::net::SocketAddr::V4(v4) => SocksAddr::Ipv4(v4.ip().octets(), v4.port()),
        std::net::SocketAddr::V6(v6) => SocksAddr::Ipv6(v6.ip().octets(), v6.port()),
    }
}

fn uot_address(target: std::net::SocketAddr) -> Address {
    match target {
        std::net::SocketAddr::V4(v4) => Address::Ipv4(v4.ip().octets(), v4.port()),
        std::net::SocketAddr::V6(v6) => Address::Ipv6(v6.ip().octets(), v6.port()),
    }
}

/// 变长载荷矩阵：单报文、多报文（含空报文）、以及接近 16 位长度上限的报文。
fn payload_matrix() -> Vec<Vec<Vec<u8>>> {
    vec![
        vec![b"single".to_vec()],
        vec![b"a".to_vec(), Vec::new(), b"ccc".to_vec()],
        vec![vec![0x5au8; 1400], vec![0x00u8], vec![0xffu8; 8]],
        vec![vec![0xabu8; 8192], b"tail".to_vec()],
    ]
}

async fn run_case(label: &str, is_connect: bool, version: UdpVersion) {
    use crate::harness::Fixture;
    use crate::support;

    let Some(mut fixture) = Fixture::start(label).await else {
        println!("SKIP: {label} 缺少官方 anytls-server 或 openssl");
        return;
    };

    let udp_target = spawn_udp_echo().await;
    println!("udp echo {udp_target}");

    let connector = fixture.connector().expect("构造校验型 connector");
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server");
    let server_name =
        rustls::pki_types::ServerName::try_from(tls::EXPECTED_NAME).expect("合法 server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS 握手失败");

    // 认证 + Settings，与既有客户端方向用例同构。
    let credential = lengsuo_anytls::auth::Credential::new(support::PASSWORD.as_bytes());
    credential
        .send(&mut tls, &[0u8; 30], WAIT)
        .await
        .expect("认证发送失败");
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: lengsuo_anytls::tunnel::Tunnel::settings_text_bytes(),
    }
    .write(&mut tls, WAIT)
    .await
    .expect("写 Settings 失败");

    // 状态机校验回程方向的控制帧（ServerSettings/SYNACK/Waste 等）。
    let mut state = lengsuo_anytls::client_state::ClientState::new(16).expect("客户端状态机");
    state.mark_settings_sent().expect("标记 Settings 已发送");

    // SYN 打开编号 1 的流（经状态机分配，回程帧才能被它正确归属）；
    // 随后 PUSH 里带 SOCKS 魔域 + UoT 请求头 + 报文。
    let stream_id = state.open_stream().expect("分配流编号");
    assert_eq!(stream_id, 1, "参考的编号空间从 1 开始");
    Frame {
        command: Command::Syn,
        stream_id,
        data: Vec::new(),
    }
    .write(&mut tls, WAIT)
    .await
    .expect("写 SYN 失败");

    // UoT 关联握手只做一次：SOCKS 魔域 + 请求头（connect 模式固定目的地）。
    let association = Association::new(
        version,
        UotRequest {
            is_connect,
            destination: socks_target(udp_target),
        },
    );
    udp_handshake(&mut tls, stream_id, &association)
        .await
        .expect("写 UoT 握手失败");
    println!("UoT v{} connect={is_connect}", version.to_byte());

    let mut total_datagrams = 0usize;
    for (n, payloads) in payload_matrix().into_iter().enumerate() {
        let echo = udp_roundtrip(
            &mut tls,
            &mut state,
            stream_id,
            &association,
            udp_target,
            &payloads,
            is_connect,
        )
        .await
        .unwrap_or_else(|err| {
            let log = support::read_log(fixture.log_path());
            panic!("{label} 往返失败：{err}\n--- server 日志 ---\n{log}");
        });
        assert_eq!(echo.len(), payloads.len(), "{label} 报文条数不符");
        for (index, (sent, got)) in payloads.iter().zip(&echo).enumerate() {
            assert_eq!(sent, got, "{label} 第 {index} 个报文未逐字节回显");
        }
        println!("{label} 第 {n} 组 {} 个报文全部回显", payloads.len());
        total_datagrams += payloads.len();
    }
    println!("{label} 逐字节回显 {total_datagrams} 个报文");

    // 干净收尾：FIN + TLS close_notify。
    Frame {
        command: Command::Fin,
        stream_id,
        data: Vec::new(),
    }
    .write(&mut tls, WAIT)
    .await
    .expect("写 FIN 失败");
    let _ = tls.shutdown().await;

    let (code, log) = fixture.finish();
    println!("server exit code={code:?}");
    assert!(
        !log.contains(support::PASSWORD),
        "{label} server 日志泄露口令"
    );
}

/// 主用例：connect 模式（报文不带地址）——参考 `DialEarlyConn(conn, true, dest)`。
/// **Windows 上不编译本用例**：官方 anytls-go v0.0.13 服务端在该平台**自身崩溃**
/// （上游缺陷，非本仓偏差）——`cmd/server/outbound_tcp.go:39` 用
/// `net.ListenPacket("udp", "")`（空本地地址）在 Windows 上非法，随后 sing
/// `common/uot` 路径解引用空指针（`panic: ... nil pointer dereference` +
/// `[signal 0xc0000005]`）。Linux 上同一点由 Go 的 `recover()` 兜住；Windows 的
/// 内存访问违例**不可恢复**，官方服务端进程直接崩溃，回程读帧随即报
/// `os error 10054`。本仓客户端侧首组载荷的逐字节回显**已成功**，崩溃发生在
/// 官方服务端侧 ⇒ 责任在参考实现。
/// 用 `cfg` 排除而不是「跑完再跳过」：这样 Windows 上的**实际通过数更少**，
/// 门禁的 `expected_passed` 按平台如实登记，**不冒充通过**。
/// 详见 `docs/anytls-status.md` 偏离清单「平台差异」条。
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl（UDP-over-TCP v2 真实互通）"]
async fn udp_over_tcp_v2_connect_mode_echoes_every_datagram() {
    run_case("udp-connect", true, UdpVersion::V2).await;
}

/// 非 connect 模式（每个报文自带地址）——参考 `DialEarlyConn(conn, false, dest)`。
///
/// Windows 上不编译，原因同 `udp_over_tcp_v2_connect_mode_echoes_every_datagram`
/// （官方 anytls-go v0.0.13 服务端在该平台崩溃的上游缺陷）。
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl（UDP-over-TCP v2 真实互通）"]
async fn udp_over_tcp_v2_non_connect_mode_echoes_every_datagram() {
    run_case("udp-nonconnect", false, UdpVersion::V2).await;
}
