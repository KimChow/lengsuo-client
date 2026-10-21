//! 官方 anytls-server v0.0.13 的**篡改实跑证据**（`#[ignore]`，需参考二进制）。
//!
//! ## 用途
//!
//! 本卡把帧层篡改（载荷 / 帧头命令字节 / 长度字段 / 认证块）的判据钉在**本仓服务端**上。
//! 但「参考实现本身会怎样反应」必须有**实跑**证据，不能只靠源码阅读，
//! 故本模块对着**真实官方 server 二进制**逐格实跑，记录它的**实际反应**。
//!
//! ## 参考源码口径（anytls-go v0.0.13，commit `9666872`）
//!
//! - `proxy/session/session.go:174-368`（`recvLoop`）：帧分发。
//!   **未知命令走 `default:` 分支——静默忽略**（`:358-360`），且**不读载荷**；
//!   `cmdWaste` 只丢弃不校验（`:260-268`）。
//! - `proxy/session/frame.go:37-49`：帧头 `cmd(1) | sid(4) | len(2)`，**无帧级 MAC**。
//! - `cmd/server/inbound_tcp.go:38-52`：认证块 = `SHA256(口令)` + BE16 padding 长度 +
//!   padding；摘要不等即走 `fallback`（`:86-89`，**空实现 = 直接断连**）。
//! - `cmd/server/inbound_tcp.go:27`：**无条件** `tls.Server` ⇒ 载荷级篡改由 AEAD 检出。
//!
//! ## 三格的**实跑**结论（源码读不出来的那两格以实跑为准）
//!
//! | 篡改面 | 参考的实况 | 本仓的实况 | 关系 |
//! |---|---|---|---|
//! | 认证块摘要改 1 bit | 摘要不等 ⇒ 空 `fallback` ⇒ **断连** | `Error::Authentication` ⇒ 断连 | ✅ 一致 |
//! | 长度字段改大 | 读不满字节 ⇒ **永久阻塞**（参考**无读超时**）⇒ 不回应也不断连 | 读超时 ⇒ `Error::Timeout` ⇒ 断连 | ⚠️ **本仓更严**（参考不 fail-closed，只是挂住） |
//! | 帧头命令字节改未知值 | `default:` **静默忽略且不消费载荷** ⇒ **帧流失步** ⇒ 后续流再也建不起来 | `Error::Invalid` ⇒ 断连 | ⚠️ **本仓更严**（参考靠「失步」偶然地断了功能性，不是校验） |
//!
//! ⚠️ 最后两行是**本仓比参考更严**，登记在 `docs/anytls-tamper.md` 的偏离清单里。
//! 本模块如实断言**参考的实况**（阻塞 / 失步），**不**把参考写成「也拒绝」——
//! 篡改格的口径是「逐面记录两侧行为」，不是「证明参考更严」。
//!
//! ## 为什么失步能观察得到
//!
//! 参考的 `default:` 分支**不读载荷**：篡改帧的载荷字节仍留在流里，
//! 下一次 `io.ReadFull(hdr[:])` 会把**载荷开头**当成下一帧的帧头
//! （本用例的载荷前缀是 SOCKS5 地址 `0x01|127.0.0.1|port` ⇒ 被读成
//! `cmd=0x01`（SYN）、sid=`127.0.0.1`、len=端口）⇒ 流编号与长度全乱。
//! 这是**结构性失步**，不是校验拒绝。
#![allow(dead_code)]

use crate::harness::{push_with_target, spawn_target};
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    Error,
};
use std::time::Duration;

/// 官方 server 认证用的假口令（与 `interop/support.rs` 的 `PASSWORD` 同值）。
const PASSWORD: &[u8] = b"interop-fake-password-please-ignore";
/// 单次读帧等待上限。
const WAIT: Duration = Duration::from_secs(10);
/// 「会话已失步」判据的观察窗口：够长以确认「真的没有 SYNACK」。
const OBSERVE: Duration = Duration::from_secs(3);

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

/// 在观察窗口内收下所有语义帧；返回 (帧列表, 是否读到 EOF)。
async fn collect_frames<S>(stream: &mut S, window: Duration) -> (Vec<Frame>, bool)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return (frames, false);
        }
        match tokio::time::timeout(left, Frame::read(stream, u16::MAX, WAIT)).await {
            Ok(Ok(frame)) => match frame.command {
                Command::Waste | Command::HeartResponse | Command::HeartRequest => continue,
                _ => frames.push(frame),
            },
            Ok(Err(_)) => return (frames, true),
            Err(_) => return (frames, false),
        }
    }
}

/// 完成「认证 → Settings(v=2) → 收 ServerSettings」。
async fn handshake<S>(stream: &mut S) -> Option<Frame>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    Credential::new(PASSWORD)
        .send(stream, b"", WAIT)
        .await
        .expect("认证发送");
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: "v=2\nclient=lengsuo-anytls\npadding-md5=75cff2ad89aadf5e257059ee571ebe11"
            .as_bytes()
            .to_vec(),
    }
    .write(stream, WAIT)
    .await
    .expect("写 Settings");
    read_frame(stream, WAIT).await
}

/// 官方 server 对**认证块摘要改 1 bit** 的实况：**断连**（不回应任何帧）。
///
/// 判据（参考 `cmd/server/inbound_tcp.go:38-46`）：摘要不等即 `fallback`
/// （空实现）⇒ 连接被关闭 ⇒ 客户端读帧必然得到 `Error::Io`（EOF/断连），
/// **不是**超时，也**不是**读到任何帧。
///
/// 与本仓 `frame_tamper::authentication_block_tampering_is_rejected` 同口径。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn official_server_disconnects_on_tampered_auth_block() {
    let Some(mut fixture) = crate::interop_harness::Fixture::start("tamper-auth").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut stream = crate::tls::client_handshake(&connector, crate::tls::EXPECTED_NAME, tcp, WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    // 用**生产代码路径**生成认证块，再把摘要的第 1 字节翻位。
    let mut block = Vec::new();
    Credential::new(PASSWORD)
        .send(&mut block, b"", WAIT)
        .await
        .expect("生成认证块");
    block[0] ^= 0x01;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &block)
        .await
        .expect("写篡改认证块");
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .expect("刷新");

    let outcome = Frame::read(&mut stream, u16::MAX, WAIT).await;
    match outcome {
        Err(Error::Io(err)) => {
            println!("官方 server 对篡改认证块的反应：断连（{err}）");
        }
        Ok(frame) => panic!(
            "篡改认证块后官方 server 不得回应任何帧，实际读到 cmd={}",
            frame.command as u8
        ),
        Err(other) => panic!("篡改认证块后官方 server 应断连（Io 错误），实际 {other:?}"),
    }

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(
        !log.contains(std::str::from_utf8(PASSWORD).expect("口令是 UTF-8")),
        "server 日志不得出现口令"
    );
}

/// 官方 server 对**帧头命令字节改成未知值** 的实况：**帧流失步**，会话失去功能。
///
/// 判据（参考 `proxy/session/session.go:358-360`）：未知命令走 `default:` 分支，
/// **静默忽略且不消费载荷** ⇒ 载荷字节留在流里 ⇒ 下一次读帧头拿到的是
/// **载荷开头**而非真实帧头 ⇒ 流编号/长度全乱 ⇒ 后续**正常**流也建不起来
/// （收不到 SYNACK）。
///
/// ⚠️ 这条**不是**「参考也拒绝」——参考**不校验**帧头；它只是**偶然地**
/// 因为失步而失去了会话功能。本仓更严：`src/frame.rs:45` 的
/// `_ => Err(Error::Invalid)` 直接判非法并断连。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn official_server_desynchronizes_frame_stream_on_unknown_command_byte() {
    let Some(mut fixture) = crate::interop_harness::Fixture::start("tamper-cmd").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let target = spawn_target().await;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut stream = crate::tls::client_handshake(&connector, crate::tls::EXPECTED_NAME, tcp, WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    let settings = handshake(&mut stream).await.expect("收 ServerSettings");
    assert_eq!(settings.command, Command::ServerSettings, "应协商到 v2");

    // 篡改帧：把 PUSH 的命令字节改成未定义值 0xFF，载荷是合法目标地址 + 载荷。
    let payload = b"official-unknown-command-probe";
    let mut tampered = Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(target.addr, payload),
    }
    .encode()
    .expect("编码 PUSH");
    tampered[0] = 0xFF;
    tokio::io::AsyncWriteExt::write_all(&mut stream, &tampered)
        .await
        .expect("写篡改帧");
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .expect("刷新");

    // 随后开一条**完全正常**的流：参考因失步而**建不起来**（收不到 SYNACK）。
    let clean = b"official-clean-stream-after-unknown-command";
    Frame {
        command: Command::Syn,
        stream_id: 2,
        data: Vec::new(),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("写 SYN");
    Frame {
        command: Command::Push,
        stream_id: 2,
        data: push_with_target(target.addr, clean),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("写 PUSH");

    let (frames, _eof) = collect_frames(&mut stream, OBSERVE).await;
    // `Frame` 刻意不实现 `Debug`（免得载荷进诊断输出），故只列命令与流编号。
    let seen: Vec<(Command, u32)> = frames
        .iter()
        .map(|frame| (frame.command, frame.stream_id))
        .collect();
    assert!(
        !frames
            .iter()
            .any(|frame| frame.command == Command::SynAck && frame.stream_id == 2),
        "参考**不校验**帧头命令：未知命令被静默忽略且不消费载荷 ⇒ 帧流失步 ⇒ \
         后续正常流收不到 SYNACK（实际收到：{seen:?}）"
    );
    println!("官方 server 对未知命令字节的反应：静默忽略 ⇒ 帧流失步（会话失去功能）");

    // 篡改载荷**绝不能**被交给上层（参考与本仓一致）。
    assert_eq!(
        target.accepted.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "未知命令帧不得触发拨号"
    );
    assert!(
        target.received().is_empty(),
        "未知命令帧的载荷不得交给上层（参考的失步也不会把它当数据转发）"
    );

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(
        !log.contains(std::str::from_utf8(PASSWORD).expect("口令是 UTF-8")),
        "server 日志不得出现口令"
    );
}

/// 官方 server 对**长度字段改大**（声明长度 > 实际字节数）的实况：**永久阻塞**。
///
/// 判据（参考 `proxy/session/session.go:195-205`）：`cmdPSH` 分支按 `hdr.Length()`
/// 分配缓冲并 `io.ReadFull` 读满；字节不足就**一直等**——参考的会话连接
/// **没有读超时**（`SetDeadline` 只在 `Close()` 里出现，`session.go:114`）。
/// ⇒ 客户端在观察窗口内**既收不到任何帧，也等不到断连**（读到的是超时）。
///
/// ⛔ 参考在此**不是 fail-closed**：它只是**挂住**（连接与 goroutine 都被占住）。
/// 本仓更严：会话读有上限（`ServerConfig::new` 的 wait），超时即 `Error::Timeout` 断连。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn official_server_stalls_on_inflated_length_field() {
    let Some(mut fixture) = crate::interop_harness::Fixture::start("tamper-len").await else {
        return;
    };
    let connector = fixture.connector().expect("TLS 客户端配置");
    let target = spawn_target().await;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut stream = crate::tls::client_handshake(&connector, crate::tls::EXPECTED_NAME, tcp, WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    let settings = handshake(&mut stream).await.expect("收 ServerSettings");
    assert_eq!(settings.command, Command::ServerSettings, "应协商到 v2");

    // 长度字段改大：声明长度比实际载荷大 64 字节 ⇒ 服务端永远等不到那么多字节。
    let mut tampered = Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(target.addr, b"official-inflated-length"),
    }
    .encode()
    .expect("编码 PUSH");
    let declared = u16::from_be_bytes([tampered[5], tampered[6]]);
    tampered[5..7].copy_from_slice(&(declared + 64).to_be_bytes());
    tokio::io::AsyncWriteExt::write_all(&mut stream, &tampered)
        .await
        .expect("写篡改帧");
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .expect("刷新");

    // 观察窗口内：既没有帧，也没有断连（读到的是**超时**而不是 Io 错误）。
    let outcome = Frame::read(&mut stream, u16::MAX, OBSERVE).await;
    match outcome {
        Err(Error::Timeout) => {
            println!("官方 server 对长度字段改大的反应：永久阻塞（无读超时 ⇒ 不回应也不断连）");
        }
        Ok(frame) => panic!(
            "长度字段改大后官方 server 不得回应任何帧，实际读到 cmd={}",
            frame.command as u8
        ),
        Err(Error::Io(err)) => panic!(
            "参考在长度字段改大时应**阻塞**而非断连（实际断连：{err}）——\
             若参考已改版加了读超时，本用例的结论需重写"
        ),
        Err(other) => panic!("长度字段改大后的观察结果异常：{other:?}"),
    }
    assert_eq!(
        target.accepted.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "长度字段改大的帧不得触发拨号"
    );

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(
        !log.contains(std::str::from_utf8(PASSWORD).expect("口令是 UTF-8")),
        "server 日志不得出现口令"
    );
}
