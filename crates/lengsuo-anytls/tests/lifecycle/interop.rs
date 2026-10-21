//! 与官方 anytls-server 的**真实互通**重放用例（`#[ignore]`，需参考二进制）。
//!
//! 用途：把「参考 anytls-go 本身**不防**重放」这一结论从**源码阅读**升级为
//! **实跑证据**——本用例对着**真实官方 server 二进制**重放同一个 PUSH 帧，
//! 观察官方 server 的实际反应。
//!
//! 判据（与本仓 Rust↔Rust 用例 `replay::replayed_push_frame_is_not_specially_guarded`
//! 同口径）：
//! 1. 官方 server **不**拒绝重放（不回 Alert、不断开）；
//! 2. 重放字节**被再次转发**给目标（回显回来）⇒ 参考**不防**重放。
//!
//! 安全边界：本用例只证明「官方 server 对重放帧的实际反应」，
//! 不据此声称任何 TLS 信任链结论；官方 server 证书是启动时现生成的自签叶子，
//! 由本仓 tokio-rustls 以 **pin + 证书链校验 + 名称校验** 完成真实握手。
//! 口令为运行时假凭据，日志与断言均不回显。
use super::interop_harness;
use super::support;
use super::tls;
use lengsuo_anytls::auth::Credential;
use lengsuo_anytls::frame::{Command, Frame};
use std::time::Duration;

/// 单流回程载荷。
const PAYLOAD: &[u8] = b"lifecycle-official-replay-probe";

/// 官方 server 对重放帧的实际反应：**不拒绝、照常转发**（= 不防重放）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn official_server_does_not_guard_replay() {
    let Some(mut fixture) = interop_harness::Fixture::start("lifecycle-replay").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let echo = interop_harness::spawn_echo().await;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut stream = tls::client_handshake(&connector, tls::EXPECTED_NAME, tcp, support::WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    // 认证 → Settings(v=2)。
    Credential::new(support::PASSWORD.as_bytes())
        .send(&mut stream, b"", support::WAIT)
        .await
        .expect("认证发送");
    let settings = Frame {
        command: Command::Settings,
        stream_id: 0,
        data: "v=2\nclient=lengsuo-anytls\npadding-md5=75cff2ad89aadf5e257059ee571ebe11"
            .as_bytes()
            .to_vec(),
    };
    settings
        .write(&mut stream, support::WAIT)
        .await
        .expect("写 Settings");

    // 收 ServerSettings（确认协商到 v2）。
    let server_settings = read_frame(&mut stream, support::WAIT)
        .await
        .expect("收 ServerSettings");
    assert_eq!(
        server_settings.command,
        Command::ServerSettings,
        "应先收到 ServerSettings"
    );

    // 开流：SYN(1) + 首帧 PUSH（SOCKS 地址 + 载荷）。
    Frame {
        command: Command::Syn,
        stream_id: 1,
        data: Vec::new(),
    }
    .write(&mut stream, support::WAIT)
    .await
    .expect("写 SYN");
    let push = Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(echo, PAYLOAD),
    };
    let push_bytes = push.encode().expect("PUSH 编码");
    push.write(&mut stream, support::WAIT)
        .await
        .expect("写 PUSH");

    // 首帧回程：SYNACK + PUSH（只有载荷，地址前缀被官方 server 消费）。
    let ack = read_frame(&mut stream, support::WAIT)
        .await
        .expect("收 SYNACK");
    assert_eq!(ack.command, Command::SynAck, "应收到 SYNACK");
    assert!(ack.data.is_empty(), "成功 SYNACK 无载荷");
    let first_echo = read_frame(&mut stream, support::WAIT)
        .await
        .expect("收首帧回程");
    assert_eq!(first_echo.command, Command::Push, "应收到回程 PUSH");
    assert_eq!(first_echo.data, PAYLOAD, "首帧回程只有载荷");

    // **重放**：把同一个 PUSH 帧逐字节原样再发一次。
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(support::WAIT, async {
        stream.write_all(&push_bytes).await.expect("写重放帧");
        stream.flush().await.expect("刷新");
    })
    .await
    .expect("写重放帧超时");

    // 判据 1：官方 server **不**用 Alert 拒绝重放。
    // 判据 2：重放字节**被再次转发**给目标（回显回来）⇒ 参考不防重放。
    let replay_echo = read_frame(&mut stream, support::WAIT).await;
    match replay_echo {
        Some(frame) => {
            assert_ne!(
                frame.command,
                Command::Alert,
                "官方 server 不应用 Alert 拒绝重放（若拒绝则参考防护，需重写结论）"
            );
            assert_eq!(frame.command, Command::Push, "重放应被再次转发为 PUSH");
            assert_eq!(
                frame.data, push.data,
                "重放字节被官方 server 再次转发到目标（参考不防重放）"
            );
            println!("官方 server 对重放帧的反应：照常转发（未拒绝）");
        }
        None => {
            panic!("官方 server 在重放后断开连接：参考防护了重放，结论需重写");
        }
    }

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(!log.contains(support::PASSWORD), "server 日志不得出现口令");
}

/// 读下一帧；跳过 Waste/心跳等填充帧；`None` = 传输层 EOF（对端断连）。
async fn read_frame<S>(stream: &mut S, wait: Duration) -> Option<Frame>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        match tokio::time::timeout(wait, Frame::read(stream, u16::MAX, wait)).await {
            Ok(Ok(frame)) => match frame.command {
                Command::Waste | Command::HeartResponse | Command::HeartRequest => continue,
                _ => return Some(frame),
            },
            Ok(Err(_)) => return None,
            Err(_) => return None,
        }
    }
}

/// 目标地址 + 载荷拼成首帧 PUSH（参考：地址是 SOCKS5 格式）。
fn push_with_target(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        panic!("测试固定 IPv4 回环");
    };
    let mut data = vec![0x01];
    data.extend_from_slice(&v4.octets());
    data.extend_from_slice(&addr.port().to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// 官方 server 在收到一条流的 `cmdFIN` 后**会话继续存活**：同一条连接上还能
/// 开新流并正常收发。
///
/// 这条直接验证参考 anytls-go 的**半关闭/关流语义**：
/// - `proxy/session/session.go:251-259`（cmdFIN）：从 `s.streams` 删除该流并
///   `stream.closeLocally()`，**不回复 FIN、也不关闭会话**（`recvLoop` 继续循环）；
/// - `proxy/session/stream.go:68-81`（`closeLocally`）：只关本地读半，
///   注释明写「don't notify remote peer」；
/// - `proxy/session/session.go:367-376`（`streamClosed`）：本地主动关流才补发
///   `cmdFIN`，且**只删这一条流**。
///
/// 判据：
/// 1. 客户端发 `cmdFIN` 后**收不到**该流的 FIN（参考不回复 FIN）；
/// 2. 同一条 TLS 连接上开**新流**仍能正常收发（会话未销毁）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn official_server_keeps_session_alive_after_stream_fin() {
    let Some(mut fixture) = interop_harness::Fixture::start("lifecycle-halfclose").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let echo = interop_harness::spawn_echo().await;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut stream = tls::client_handshake(&connector, tls::EXPECTED_NAME, tcp, support::WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    Credential::new(support::PASSWORD.as_bytes())
        .send(&mut stream, b"", support::WAIT)
        .await
        .expect("认证发送");
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: "v=2\nclient=lengsuo-anytls\npadding-md5=75cff2ad89aadf5e257059ee571ebe11"
            .as_bytes()
            .to_vec(),
    }
    .write(&mut stream, support::WAIT)
    .await
    .expect("写 Settings");
    let _ = read_frame(&mut stream, support::WAIT)
        .await
        .expect("收 ServerSettings");

    // 第一条流：开流 + 载荷 + 回程。
    let first = b"lifecycle-official-first-stream";
    open_and_echo(&mut stream, echo, 1, first, support::WAIT).await;

    // 半关闭第一条流：只发 `cmdFIN`（不关传输层）。
    Frame {
        command: Command::Fin,
        stream_id: 1,
        data: Vec::new(),
    }
    .write(&mut stream, support::WAIT)
    .await
    .expect("写 FIN");

    // 判据 2：同一条连接上开**新流**仍能正常收发（会话未因关流而销毁）。
    let second = b"lifecycle-official-second-stream";
    open_and_echo(&mut stream, echo, 2, second, support::WAIT).await;

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(!log.contains(support::PASSWORD), "server 日志不得出现口令");
}

/// 开一条流并断言回程逐字节一致（顺带断言 SYNACK 绑定本流）。
async fn open_and_echo<S>(
    stream: &mut S,
    target: std::net::SocketAddr,
    sid: u32,
    payload: &[u8],
    wait: Duration,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    Frame {
        command: Command::Syn,
        stream_id: sid,
        data: Vec::new(),
    }
    .write(stream, wait)
    .await
    .expect("写 SYN");
    Frame {
        command: Command::Push,
        stream_id: sid,
        data: push_with_target(target, payload),
    }
    .write(stream, wait)
    .await
    .expect("写 PUSH");

    let ack = read_frame(stream, wait).await.expect("收 SYNACK");
    assert_eq!(ack.command, Command::SynAck, "应收到 SYNACK");
    assert_eq!(ack.stream_id, sid, "SYNACK 必须绑定本流");
    let echoed = read_frame(stream, wait).await.expect("收回程");
    assert_eq!(echoed.command, Command::Push, "应收到回程 PUSH");
    assert_eq!(echoed.stream_id, sid, "回程必须绑定本流");
    assert_eq!(echoed.data, payload, "回程逐字节一致");
}
