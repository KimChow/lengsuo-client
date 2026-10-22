//! 「帧被截断」格：帧头截断 / 载荷截断 / 载荷缺失 ⇒ 服务端 **`Err`**。
//!
//! 判据核心：`src/server/session.rs` 的 `serve` 必须把截断判成 fail-closed
//! （返回 `Err`），而**不是**旧实现的「一律 `Ok(stats)`」。
#![allow(dead_code)]

use super::harness::{
    fake_password, handshake, push_with_target, shutdown_write, spawn_target, Outcome, RustServer,
    TOTAL, WAIT,
};
use lengsuo_anytls::frame::{Command, Eof, Frame};
use std::sync::atomic::Ordering;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// **帧头截断**（发 3 字节头就断开）⇒ 服务端 `Err`，且**不是**干净 EOF 语义。
#[tokio::test]
async fn truncated_header_fails_closed_and_is_not_clean_eof() {
    timeout(TOTAL, async {
        let password = fake_password();
        let server = RustServer::spawn(password.clone()).await;

        let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
        let negotiated = handshake(&mut stream, &password).await;
        assert_eq!(negotiated.command, Command::ServerSettings);

        // 只写 3 字节帧头就断开 ⇒ 服务端读到的是「半个帧头」。
        stream
            .write_all(&[Command::Push as u8, 0x00, 0x00])
            .await
            .expect("写半截帧头");
        stream.flush().await.expect("刷新");
        shutdown_write(&mut stream).await;

        let outcome = server.await_outcome(0).await;
        // 判据 1：必须是失败，不是 `Ok(stats)`。
        let Outcome::Failed { reason, eof } = outcome else {
            panic!("截断的帧头必须使会话以失败结束（Err），实际：{outcome:?}");
        };
        // 判据 2：必须是「截断」分类，**不是**「干净 EOF」分类。
        assert_eq!(
            eof,
            Some(Eof::Truncated),
            "截断的帧头必须表现为 Truncated（不是 Clean），实际错误：{reason}"
        );
        // 判据 3：必须**不是**干净 EOF 的语义——两者是不同的错误值。
        assert_ne!(
            eof,
            Some(Eof::Clean),
            "截断绝不能被当作干净 EOF（fail-open），实际错误：{reason}"
        );
    })
    .await
    .expect("用例超时");
}

/// **payload 截断**（完整头 + 长度字段说 100 + 只发 10 字节 payload）⇒ 服务端 `Err`。
///
/// 判据：长度字段声明了 100 字节，收到 <100 ⇒ 截断（`Eof::Truncated`），
/// **不得**把「读多少算多少」的半截载荷当有效帧交付。
#[tokio::test]
async fn truncated_payload_fails_closed_and_is_not_clean_eof() {
    timeout(TOTAL, async {
        let password = fake_password();
        let server = RustServer::spawn(password.clone()).await;
        let target = spawn_target().await;

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

        // 完整帧头（长度字段 = 100）+ 只有 10 字节载荷。
        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, b"truncated-payload"),
        }
        .encode()
        .expect("编码 PUSH");
        bytes[5..7].copy_from_slice(&100u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        stream.write_all(&bytes).await.expect("写截断帧");
        stream.flush().await.expect("刷新");
        shutdown_write(&mut stream).await;

        let outcome = server.await_outcome(0).await;
        // 判据 1：必须失败。
        let Outcome::Failed { reason, eof } = outcome else {
            panic!("截断的载荷必须使会话以失败结束（Err），实际：{outcome:?}");
        };
        // 判据 2：分类必须是「截断」。
        assert_eq!(
            eof,
            Some(Eof::Truncated),
            "截断的载荷必须表现为 Truncated，实际错误：{reason}"
        );
        // 判据 3：截断帧**不得**产生副作用（目标从未被拨号）。
        assert_eq!(
            target.accepted.load(Ordering::SeqCst),
            0,
            "被截断的帧不得触发拨号"
        );
        assert!(
            target.received().is_empty(),
            "被截断的帧不得把半截载荷交给上层"
        );
    })
    .await
    .expect("用例超时");
}

/// **载荷一个字节都没收到**也是截断（头已完整、长度字段说 N>0 却收到 0 字节）。
///
/// 这条专钉「载荷层 0 字节」这个边界：此时已**不在帧边界**上 ⇒ 属截断，
/// 绝不能被误判成「对端干净关闭」。
#[tokio::test]
async fn payload_missing_entirely_is_truncated_not_clean_eof() {
    timeout(TOTAL, async {
        let password = fake_password();
        let server = RustServer::spawn(password.clone()).await;

        let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
        let negotiated = handshake(&mut stream, &password).await;
        assert_eq!(negotiated.command, Command::ServerSettings);

        // 完整帧头，长度字段 = 1，但一个载荷字节都不发。
        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: Vec::new(),
        }
        .encode()
        .expect("编码 PUSH");
        bytes[5..7].copy_from_slice(&1u16.to_be_bytes());
        stream.write_all(&bytes).await.expect("写帧头");
        stream.flush().await.expect("刷新");
        shutdown_write(&mut stream).await;

        let outcome = server.await_outcome(0).await;
        let Outcome::Failed { reason, eof } = outcome else {
            panic!("载荷缺失必须使会话以失败结束（Err），实际：{outcome:?}");
        };
        assert_eq!(
            eof,
            Some(Eof::Truncated),
            "帧头完整但载荷 0 字节 = 截断（不是 Clean），实际错误：{reason}"
        );
    })
    .await
    .expect("用例超时");
}
