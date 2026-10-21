//! 篡改矩阵的「截断」与「乱序」两格：帧流被截短 / 帧被换序 ⇒ 必须 fail-closed。
//!
//! ## 与其余格的关系
//!
//! 本卡四类篡改面（载荷 / 命令字节 / 长度字段 / 认证块）分别在
//! `tls_tamper`（载荷）、`frame_tamper`（命令字节 / 长度字段 / 认证块）里取证。
//! 本模块补的是**流级**的两格：**截断**（字节被砍掉）与**乱序**（帧被换序）。
//!
//! ## 判据位置
//!
//! - 截断：`src/frame.rs:122`（`read_exact` 读帧头）与 `:129`（`read_exact` 读载荷）。
//!   字节不足时 `read_exact` 报 `UnexpectedEof` ⇒ 会话层
//!   `src/server/session.rs:104-106` **把 EOF 当干净收尾**（`Ok(stats)`）。
//!   ⇒ 本模块的判据因此**不是**「必须报错」，而是
//!   **「被截断的帧绝不能产生任何副作用」**：目标没被拨号、没收到字节、
//!   没有流被打开（`streams_opened == 0`）。
//! - 乱序：`src/server_state.rs:110-125`（SYN 判据：流编号必须**严格递增**）
//!   与 `:130-134`（PUSH 判据：流编号必须在活跃集合内）。
//!   把 SYN(2) 与 SYN(1) 换序 ⇒ 收到 SYN(1) 时 `max_syn_id` 仍为 0 ⇒ 通过；
//!   随后收到 SYN(2) ⇒ `2 > max_syn_id(=1)` ⇒ **也**通过。
//!   ⇒ 所以「单纯换序 SYN」**不**必然被拒；本模块改用**可观测的必然失败**：
//!   把 PUSH 帧**换序到 SYN 之前**（PUSH 先于其流的开流帧）⇒ PUSH 的流编号
//!   不在活跃集合内 ⇒ `require_active` 失败 ⇒ `Error::Invalid`（fail-closed）。
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
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT).await?;
        if frame.command != Command::Waste {
            return Ok(frame);
        }
    }
}

/// **截断**：帧载荷被砍掉一半 ⇒ 截断的帧绝不能产生副作用。
///
/// 判据（三条同时成立才通过）：
/// 1. 会话可以干净收尾（EOF 被当正常收尾，见模块头注）**或**以错误结束——
///    两种都合法，**关键是不许**「半截载荷被当成有效数据交付」。
/// 2. 目标**从未被拨号**（`accepted == 0`）：截断的 PUSH 读不满 ⇒ 地址不完整 ⇒ 不拨号。
/// 3. 目标**从未收到字节**（`received` 为空）。
///
/// ⚠️ `streams_opened == 1` 是**预期**的：前面那条**完整**的 SYN 合法地开了一条流
/// （只是从未拨号，因为首帧 PUSH 没到）。截断只应影响**被截断的那条帧**。
///
/// ⛔ 判据的**核心**是第 2、3 条：fail-closed 的可观测后果是「没有副作用」，
/// 而不是「必须报某个特定错误」。
#[tokio::test]
async fn truncated_frame_payload_produces_no_side_effect() {
    timeout(TOTAL, async {
        let server = RustServer::spawn(PASSWORD).await;
        let target = spawn_target().await;

        let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
        let settings_frame = handshake(&mut stream).await.expect("Settings 协商");
        assert_eq!(settings_frame.command, Command::ServerSettings);

        // 开流 SYN（完整帧），随后送一条**载荷被砍半**的 PUSH。
        Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .write(&mut stream, WAIT)
        .await
        .expect("写 SYN");

        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, b"truncated-payload-must-not-arrive"),
        }
        .encode()
        .expect("编码 PUSH");
        // 砍掉载荷的后半截（帧头声明的长度保持不变 ⇒ 读不满）。
        bytes.truncate(bytes.len() - 10);
        stream.write_all(&bytes).await.expect("写截断帧");
        stream.flush().await.expect("刷新");
        // 半关闭写端：服务端读到 EOF，判定这半截帧到底怎么处理。
        stream.shutdown().await.expect("半关闭写端");

        let outcome = server.await_outcome(0, TOTAL).await;
        println!("截断帧后的会话结局：{outcome:?}");
        // 判据 1：会话结束（干净收尾或失败都算）；完整 SYN 开的那条流可以存在，
        // 但它**从未拨号**（下面由 accepted == 0 钉住）。
        if let Outcome::Clean { streams_opened } = outcome {
            assert_eq!(
                streams_opened, 1,
                "只有那条**完整**的 SYN 允许开流（截断的 PUSH 不得再开流）"
            );
        }
        // 判据 2、3：无副作用。
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
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

/// **乱序**：PUSH 帧被换序到其开流帧（SYN）**之前** ⇒ 必须 fail-closed。
///
/// 判据位置：`src/server_state.rs:130-134`——PUSH 要求流编号在活跃集合内；
/// 集合只有收到 SYN 后才插入 ⇒ 先到的 PUSH 必然找不到流 ⇒ `Error::Invalid`。
///
/// 断言：会话以 `Error::Invalid` 失败，且目标**从未被拨号**。
#[tokio::test]
async fn reordered_push_before_its_syn_is_rejected() {
    timeout(TOTAL, async {
        let server = RustServer::spawn(PASSWORD).await;
        let target = spawn_target().await;

        let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
        let settings_frame = handshake(&mut stream).await.expect("Settings 协商");
        assert_eq!(settings_frame.command, Command::ServerSettings);

        // 乱序：先送 PUSH（sid=1），再送它的 SYN（sid=1）。
        let push = Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, b"reordered-push-must-not-arrive"),
        }
        .encode()
        .expect("编码 PUSH");
        stream.write_all(&push).await.expect("写乱序 PUSH");
        stream.flush().await.expect("刷新");
        Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .write(&mut stream, WAIT)
        .await
        .expect("写 SYN");

        let outcome = server.await_outcome(0, TOTAL).await;
        assert!(
            matches!(outcome, Outcome::Failed { .. }),
            "乱序（PUSH 先于 SYN）必须使会话以失败结束，实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "乱序帧不得触发拨号"
        );
        assert!(target.received().is_empty(), "乱序帧的载荷不得交给上层");
    })
    .await
    .expect("用例超时");
}

/// **乱序（流编号倒序）**：SYN(2) 先于 SYN(1) ⇒ 流编号必须严格递增 ⇒ 必须被拒。
///
/// 判据位置：`src/server_state.rs:118-120`——`frame.stream_id <= self.max_syn_id`
/// 即 `InvalidStream("SYN 流编号未严格递增")` ⇒ `Error::Invalid`。
///
/// ⚠️ 口径边界（**如实记录**）：**倒序**的 SYN(2)→SYN(1) 在 `max_syn_id` 尚未推进时
/// （`max_syn_id == 0`）会被接受（SYN(2) 通过 ⇒ `max_syn_id = 2`），
/// 随后的 SYN(1) 因 `1 <= 2` 才被拒。故本用例送 **SYN(2) → SYN(1)**：
/// 第一条被接受、第二条（编号更小）被拒 ⇒ 会话 fail-closed。
#[tokio::test]
async fn reordered_syn_with_decreasing_stream_id_is_rejected() {
    timeout(TOTAL, async {
        let server = RustServer::spawn(PASSWORD).await;
        let target = spawn_target().await;

        let mut stream = TcpStream::connect(server.addr).await.expect("连接服务端");
        let settings_frame = handshake(&mut stream).await.expect("Settings 协商");
        assert_eq!(settings_frame.command, Command::ServerSettings);

        // 乱序：先 SYN(2)，再 SYN(1)（编号倒序）。
        for sid in [2u32, 1u32] {
            Frame {
                command: Command::Syn,
                stream_id: sid,
                data: Vec::new(),
            }
            .write(&mut stream, WAIT)
            .await
            .expect("写 SYN");
        }

        let outcome = server.await_outcome(0, TOTAL).await;
        assert!(
            matches!(outcome, Outcome::Failed { .. }),
            "SYN 流编号倒序必须使会话以失败结束，实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "乱序 SYN 不得触发拨号"
        );
    })
    .await
    .expect("用例超时");
}
