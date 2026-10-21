//! 「对端干净关闭」格：正常关闭 ⇒ 服务端 `Ok(stats)`。
//!
//! 这是截断 fail-closed 修复的**对照组**：如果把「干净关闭」也改成 `Err`，
//! 就会出现另一种 fail-open（正常会话被误杀）。故本模块钉住正常路径仍绿。
#![allow(dead_code)]

use super::harness::{
    fake_password, handshake, push_with_target, shutdown_write, spawn_target, Outcome, RustServer,
    TOTAL, WAIT,
};
use lengsuo_anytls::frame::{Command, Frame};
use std::sync::atomic::Ordering;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 正常关闭（发完 FIN 后半关闭写端）⇒ 服务端 `Ok`。
///
/// 判据：这是「对端正常关闭」，**不是**截断 ⇒ 会话必须干净收尾。
#[tokio::test]
async fn clean_close_yields_ok_session() {
    timeout(TOTAL, async {
        let password = fake_password();
        let server = RustServer::spawn(password.clone()).await;
        let target = spawn_target().await;

        let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
        let negotiated = handshake(&mut stream, &password).await;
        assert_eq!(negotiated.command, Command::ServerSettings);

        let payload = b"clean-close-payload";
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

        // 收到 SYNACK ⇒ 流已建立。
        loop {
            let frame = Frame::read(&mut stream, u16::MAX, WAIT)
                .await
                .expect("读服务端帧");
            if frame.command == Command::SynAck {
                break;
            }
        }

        // 正常关闭：发 FIN，再半关闭写端（FIN 之后仍留在帧边界上）。
        Frame {
            command: Command::Fin,
            stream_id: 1,
            data: Vec::new(),
        }
        .write(&mut stream, WAIT)
        .await
        .expect("写 FIN");
        shutdown_write(&mut stream).await;

        let outcome = server.await_outcome(0).await;
        assert!(
            matches!(outcome, Outcome::Clean { streams_opened: 1 }),
            "正常关闭必须干净收尾（Ok），实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(Ordering::SeqCst),
            1,
            "正常关闭前应已拨号一次"
        );
        assert_eq!(target.received(), payload.to_vec(), "载荷逐字节一致");
    })
    .await
    .expect("用例超时");
}
