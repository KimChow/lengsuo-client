//! 隔离性用例：一条连接被篡改拒绝后，**新开一条连接必须能正常往返**。
//!
//! 判据：服务端每条连接独立建状态机（`src/server/session.rs:72-88`：
//! `Session::run` 每次新建 `ServerState`），拒绝路径不写任何跨连接共享状态。
//! 用例用**真实 TCP**（非 duplex）走服务端监听端口，先送一条篡改帧把
//! 第 1 条连接作废，再在第 2 条连接上完成认证 → Settings → SYN → PUSH →
//! SYNACK → 回程 PUSH 的完整往返。
//!
//! ⚠️ 这里用明文 TCP 而非 TLS：TLS 是**部署层**（`src/server/tls.rs`），
//! 参考实现把它放在 `cmd/server/inbound_tcp.go:27` 的 `handleTcpConnection` 里，
//! 而 `server::serve` 接的是**已握手**的流。隔离性判据属会话层，用明文
//! 直连 `server::serve` 与生产装配等价，且不引入证书依赖。
#![allow(dead_code)]

use crate::harness::{
    push_with_target, settings, spawn_target, Outcome, RustServer, PASSWORD, TOTAL, WAIT,
};
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    Error,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 读一帧并跳过 Waste 填充帧。
async fn next_semantic(stream: &mut TcpStream) -> Result<Frame, Error> {
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT).await?;
        if frame.command != Command::Waste {
            return Ok(frame);
        }
    }
}

/// 认证并完成 Settings 协商（返回已协商的 ServerSettings 帧）。
async fn handshake(stream: &mut TcpStream) -> Result<Frame, Error> {
    Credential::new(PASSWORD)
        .send(stream, b"", WAIT)
        .await
        .map_err(|err| Error::Io(std::io::Error::other(err.to_string())))?;
    settings()
        .write(stream, WAIT)
        .await
        .map_err(|err| Error::Io(std::io::Error::other(err.to_string())))?;
    next_semantic(stream).await
}

/// 干净收尾：发 FIN → 半关闭写端 → 读到 EOF。
///
/// 必须显式半关闭：直接 drop 掉带未读数据的 socket 会让内核发 RST，
/// 服务端读到的是 `ECONNRESET`（`Error::Io`）而不是干净 EOF
/// （`src/server/session.rs:104-106` 只把 `UnexpectedEof` 当干净收尾）。
/// 本仓 `server::serve` 走明文 TCP，故这里用 TCP 半关闭表达「对端正常关闭」。
async fn close_cleanly(stream: &mut TcpStream) {
    Frame {
        command: Command::Fin,
        stream_id: 1,
        data: Vec::new(),
    }
    .write(stream, WAIT)
    .await
    .expect("FIN");
    stream.shutdown().await.expect("半关闭写端");
    // 读到 EOF：把服务端可能还在发的填充帧排空（避免 close 时残留未读数据）。
    let mut sink = Vec::new();
    let _ = tokio::io::AsyncReadExt::read_to_end(stream, &mut sink).await;
}

/// 第 1 条连接：送一条未知命令的篡改帧，必须被拒绝。
///
/// 之后第 2 条连接必须能完整往返 ⇒ 拒绝路径没有污染后续会话。
#[tokio::test]
async fn rejected_tampered_connection_does_not_pollute_later_sessions() {
    timeout(TOTAL * 2, async {
        let server = RustServer::spawn(PASSWORD).await;
        let target = spawn_target().await;

        // 第 1 条连接：认证 + Settings 正常，然后送未知命令的帧。
        {
            let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
            let settings_frame = handshake(&mut stream).await.expect("Settings 协商");
            assert_eq!(settings_frame.command, Command::ServerSettings);
            let mut bytes = Frame {
                command: Command::Push,
                stream_id: 1,
                data: push_with_target(target.addr, b"must-not-be-delivered"),
            }
            .encode()
            .expect("编码 PUSH");
            bytes[0] = 0xFF; // 未定义命令字节
            stream.write_all(&bytes).await.expect("写篡改帧");
            stream.flush().await.expect("刷新");
        }

        // 第 1 条连接必须以失败结束（fail-closed）。
        let first = server.await_outcome(0, TOTAL).await;
        assert!(
            matches!(first, Outcome::Failed { .. }),
            "被篡改的连接必须以失败结束，实际：{first:?}"
        );

        // 第 2 条连接：必须完整往返。
        let payload = b"session-after-tamper-must-work";
        {
            let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
            let settings_frame = handshake(&mut stream).await.expect("Settings 协商");
            assert_eq!(settings_frame.command, Command::ServerSettings);
            Frame {
                command: Command::Syn,
                stream_id: 1,
                data: Vec::new(),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("SYN");
            Frame {
                command: Command::Push,
                stream_id: 1,
                data: push_with_target(target.addr, payload),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("PUSH");

            let ack = next_semantic(&mut stream).await.expect("读 SYNACK");
            assert_eq!(ack.command, Command::SynAck, "新连接必须正常建流");
            let echoed = next_semantic(&mut stream).await.expect("读回程");
            assert_eq!(echoed.command, Command::Push);
            assert_eq!(echoed.data, payload, "新连接必须逐字节往返一致");
            close_cleanly(&mut stream).await;
        }

        let second = server.await_outcome(1, TOTAL).await;
        assert!(
            matches!(second, Outcome::Clean { streams_opened: 1 }),
            "新连接必须干净收尾且开过一条流，实际：{second:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "只有第 2 条（干净）连接才允许拨号"
        );
        assert_eq!(
            target.received(),
            payload.to_vec(),
            "目标只应收到干净连接的载荷"
        );
    })
    .await
    .expect("用例超时");
}

/// 连续多条被篡改的连接之后，第 N+1 条连接仍必须正常往返。
///
/// 这是对上一条的加压：拒绝路径连跑多次，确认没有累积效应
/// （例如共享计数器、流编号或 padding 计数被污染）。
#[tokio::test]
async fn repeated_tampered_connections_still_leave_a_healthy_session() {
    timeout(TOTAL * 2, async {
        let server = RustServer::spawn(PASSWORD).await;
        let target = spawn_target().await;

        for _ in 0..3 {
            let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
            handshake(&mut stream).await.expect("Settings 协商");
            let mut bytes = Frame {
                command: Command::Push,
                stream_id: 1,
                data: push_with_target(target.addr, b"repeat-tamper"),
            }
            .encode()
            .expect("编码 PUSH");
            bytes[0] = 0xFF;
            stream.write_all(&bytes).await.expect("写篡改帧");
            stream.flush().await.expect("刷新");
            drop(stream);
        }
        for index in 0..3 {
            let outcome = server.await_outcome(index, TOTAL).await;
            assert!(
                matches!(outcome, Outcome::Failed { .. }),
                "第 {index} 条被篡改的连接必须失败，实际：{outcome:?}"
            );
        }

        // 第 4 条连接：必须完整往返。
        let payload = b"after-three-rejections";
        {
            let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
            handshake(&mut stream).await.expect("Settings 协商");
            Frame {
                command: Command::Syn,
                stream_id: 1,
                data: Vec::new(),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("SYN");
            Frame {
                command: Command::Push,
                stream_id: 1,
                data: push_with_target(target.addr, payload),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("PUSH");
            let ack = next_semantic(&mut stream).await.expect("读 SYNACK");
            assert_eq!(ack.command, Command::SynAck);
            let echoed = next_semantic(&mut stream).await.expect("读回程");
            assert_eq!(echoed.data, payload, "第 4 条连接必须逐字节往返一致");
            close_cleanly(&mut stream).await;
        }
        let outcome = server.await_outcome(3, TOTAL).await;
        assert!(
            matches!(outcome, Outcome::Clean { streams_opened: 1 }),
            "第 4 条连接必须干净收尾，实际：{outcome:?}"
        );
        assert_eq!(
            target.received(),
            payload.to_vec(),
            "目标只应收到干净连接的载荷"
        );
    })
    .await
    .expect("用例超时");
}
