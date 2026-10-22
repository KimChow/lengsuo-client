//! 「截断后会话资源仍被回收」格：fail-closed 不得把资源泄漏在连接上。
//!
//! 判据（参考 `tests/tamper_matrix/isolation.rs` 的「被拒连接不污染后续会话」
//! 范式，只读引用不改该文件）：
//! 1. 截断连接以 `Err` 结束（fail-closed）；
//! 2. 之后新开一条连接必须能**完整往返**（截断路径没有留下跨连接脏状态）；
//! 3. 只有健康的第 2 条连接才允许拨号。
#![allow(dead_code)]

use super::harness::{
    fake_password, handshake, push_with_target, shutdown_write, spawn_target, Outcome, RustServer,
    TOTAL, WAIT,
};
use lengsuo_anytls::frame::{Command, Frame};
use std::sync::atomic::Ordering;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::test]
async fn truncated_connection_releases_resources_and_does_not_pollute_later_sessions() {
    timeout(TOTAL * 2, async {
        let password = fake_password();
        let server = RustServer::spawn(password.clone()).await;
        let target = spawn_target().await;

        // 第 1 条连接：认证 → Settings → 半截帧头 → 断开（截断）。
        {
            let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
            let negotiated = handshake(&mut stream, &password).await;
            assert_eq!(negotiated.command, Command::ServerSettings);
            stream
                .write_all(&[Command::Push as u8, 0x00])
                .await
                .expect("写半截帧头");
            stream.flush().await.expect("刷新");
            shutdown_write(&mut stream).await;
        }
        let first = server.await_outcome(0).await;
        assert!(
            matches!(first, Outcome::Failed { .. }),
            "截断连接必须以失败结束，实际：{first:?}"
        );

        // 第 2 条连接：必须完整往返。
        let payload = b"session-after-truncation-must-work";
        {
            let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
            let negotiated = handshake(&mut stream, &password).await;
            assert_eq!(negotiated.command, Command::ServerSettings);
            Frame {
                command: Command::Syn,
                stream_id: 1,
                data: Vec::new(),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("写 SYN");
            Frame {
                command: Command::Push,
                stream_id: 1,
                data: push_with_target(target.addr, payload),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("写 PUSH");

            let mut acked = false;
            let mut echoed = Vec::new();
            while !acked || echoed.len() < payload.len() {
                let frame = Frame::read(&mut stream, u16::MAX, WAIT)
                    .await
                    .expect("读服务端帧");
                match frame.command {
                    Command::SynAck => acked = true,
                    Command::Push => echoed.extend_from_slice(&frame.data),
                    _ => {}
                }
            }
            assert_eq!(echoed, payload, "新连接必须逐字节往返一致");
            Frame {
                command: Command::Fin,
                stream_id: 1,
                data: Vec::new(),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("写 FIN");
            shutdown_write(&mut stream).await;
        }

        let second = server.await_outcome(1).await;
        assert!(
            matches!(second, Outcome::Clean { streams_opened: 1 }),
            "截断之后的新连接必须干净收尾且开过一条流，实际：{second:?}"
        );
        assert_eq!(
            target.accepted.load(Ordering::SeqCst),
            1,
            "只有健康的第 2 条连接才允许拨号"
        );
        assert_eq!(target.received(), payload.to_vec(), "载荷逐字节一致");
    })
    .await
    .expect("用例超时");
}
