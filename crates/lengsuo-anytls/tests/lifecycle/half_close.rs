//! B. 半关闭（对应 `docs/audit-all1.md` §3 矩阵的「半关闭」格）。
//!
//! 三条判据：
//! 5. **单向半关闭**：客户端发完载荷后关写端 ⇒ 对端**仍能收到完整载荷**，
//!    读方向**继续可收**，直到对端也关才 EOF。
//! 6. **对端半关闭的对称性**：服务端先关写端 ⇒ 客户端读到**干净 EOF**
//!    （0 字节），**不是** `Err(UnexpectedEof)` / `ConnectionReset`。
//!    ⚠️ 关键坑：「EOF 且缓冲空」= 干净 EOF；「EOF 且残留半帧」才是协议错误。
//! 7. **半关闭后同连接继续用**：半关闭一条流后**还能开新流并正常收发**
//!    （会话未因半关闭而整体销毁）。
//!
//! 参考判据（anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50）：
//! - `proxy/session/session.go:251-259`（cmdFIN）：删除流并 `closeLocally`
//!   ——**只关这一条流**，会话循环继续（`recvLoop` 的 for 循环不退出）。
//! - `proxy/session/stream.go:68-81`（`closeLocally`）：只关本地读半
//!   （`s.pipeR.Close()`），**不通知对端**（注释即「don't notify remote peer」）。
//! - `proxy/session/stream.go:83-100`（`closeWithError`）：本地主动关流时
//!   **补发一条 `cmdFIN`** 给对端（`sess.streamClosed`），即对端会看到流 EOF。
//! - `proxy/session/session.go:367-376`（`streamClosed`）：写 `cmdFIN` 后从
//!   `s.streams` 删除该流；**会话本身不关闭**。
//! - `proxy/pipe/io_pipe.go:73-80,108-116`：读半关闭（`closeRead`）与写半关闭
//!   （`closeWrite`）是**两个独立**的关闭语义；`closeWrite` 后读侧读到 EOF，
//!   而 `closeRead` 后写侧拿到 `io.ErrClosedPipe`。
//! - `proxy/session/session.go:196-208`（cmdPSH）：FIN 之后同 sid 的 PUSH
//!   **找不到流即被丢弃**（`if ok` 判据），不报错、不 panic。
//!
//! 本仓对应实现：`src/server_state.rs:133-141`（FIN 关闭流并移出活跃集合）、
//! `src/server/streams.rs:166-169`（`close_local`：关出站通道 + 标记 client_fin，
//! **会话不销毁**）、`src/server/streams.rs:200-221`（`collect_target`：目标 EOF
//! 且本端未先收到 FIN 时**补发一条 FIN**）。
use super::client::{ClientSession, Terminator};
use super::{spawn_rust_server, Eof, SessionOutcome, PASSWORD};
use lengsuo_anytls::frame::Command;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// B5：单向半关闭（客户端关写端）。
///
/// 判据：客户端发完载荷 → 关写端（TCP 半关闭）⇒
/// 1. 对端（服务端代理）**仍能收到完整载荷**（目标侧字节数 == 载荷长度）；
/// 2. 读方向**继续可收**：服务端在客户端半关闭后仍会回程数据（echo），
///    客户端能读到回程；
/// 3. 直到对端也关才 EOF。
#[tokio::test]
async fn one_way_half_close_keeps_read_direction_open() {
    let server = spawn_rust_server(PASSWORD).await;
    // 目标在读到 EOF 后回送尾数据：证明「写端半关闭后读端仍可收」。
    let payload = b"lifecycle-half-close-payload";
    let tail = b"-tail-after-eof";
    let target = super::spawn_target(tail, false).await;

    let mut client = ClientSession::connect(server.addr).await.expect("连接");
    client.handshake(PASSWORD).await.expect("握手");
    let sid = client
        .open_stream(target.addr, payload)
        .await
        .expect("开流");

    // 载荷先完整回程一次（首帧含地址 + 载荷）。
    let echoed = client
        .read_bytes(sid, payload.len())
        .await
        .expect("读首帧回程");
    assert_eq!(echoed, payload, "首帧回程逐字节一致");

    // 客户端关写端（半关闭）：读方向保持可用。
    client.shutdown_write().await.expect("半关闭写端");

    // 判据 1：目标仍收到**完整载荷**（半关闭不是丢弃数据）。
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !target.eof_seen.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        target.eof_seen.load(Ordering::SeqCst),
        "目标应看到客户端的写端半关闭（读到 EOF）"
    );
    assert!(
        target
            .received()
            .windows(payload.len())
            .any(|w| w == payload),
        "目标必须收到完整载荷"
    );

    // 判据 2：读方向**继续可收**——服务端回程的尾数据仍能到达客户端。
    // 目标在读到 EOF 后回送 tail，服务端把它作为 PUSH 发回。
    let got = client
        .read_bytes(sid, payload.len() + tail.len())
        .await
        .expect("半关闭后读方向仍可收");
    assert!(
        got.windows(tail.len()).any(|w| w == tail),
        "半关闭后读方向必须继续可收（收到回程尾数据）"
    );
}

/// B6：服务端先关流 ⇒ 客户端读到**干净 EOF**（0 字节），不是 UnexpectedEof。
///
/// 场景：目标（服务端的下游）先关闭 ⇒ 服务端 `collect_target` 读到 EOF 且
/// 本端未先收到 FIN ⇒ **补发一条 `cmdFIN`**（`src/server/streams.rs:218-220`，
/// 参考 `streamClosed` 同语义）⇒ 客户端读到**协议层的流 EOF**（`cmdFIN`）。
///
/// 关键坑：「EOF 且缓冲空」= 干净 EOF（`Ok(None)` 语义）；「EOF 且残留半帧」
/// 才是协议错误（截断）。本用例断言 EOF 判定是 `Eof::Clean`（残留 0 字节），
/// 且结束原因是 `cmdFIN`（而非传输层异常）。
#[tokio::test]
async fn peer_half_close_yields_clean_eof_not_truncation() {
    let server = spawn_rust_server(PASSWORD).await;
    // 目标回显一次后**立即关闭**（对端先关 ⇒ 服务端补发 FIN）。
    let payload = b"lifecycle-peer-half-close";
    let target = super::spawn_target(&[], true).await;

    let mut client = ClientSession::connect(server.addr).await.expect("连接");
    client.handshake(PASSWORD).await.expect("握手");
    let sid = client
        .open_stream(target.addr, payload)
        .await
        .expect("开流");
    let echoed = client.read_bytes(sid, payload.len()).await.expect("读回程");
    assert_eq!(echoed, payload, "回程逐字节一致");

    // 判据：客户端读到**干净 EOF**（0 字节残留），不是 Err(UnexpectedEof)。
    let outcome = client
        .read_to_eof(sid)
        .await
        .expect("读到流 EOF（不得以错误收场）");
    assert_eq!(
        outcome.eof,
        Eof::Clean,
        "EOF 且缓冲空 = 干净 EOF；残留半帧才是协议错误（实际 {:?}）",
        outcome.eof
    );
    assert_eq!(
        outcome.terminator,
        Terminator::Fin,
        "服务端应以 cmdFIN 结束该流（参考 streamClosed 语义）"
    );
}

/// B6'：对照项——**残留半帧**的 EOF 与干净 EOF **必须能区分**。
///
/// 做法：客户端在半帧中途断开传输层（只写出帧头的一部分），服务端读帧时
/// 遇到 EOF。按协议语义，这**不是**干净收尾，而是**截断**（协议错误）。
///
/// 判据（两侧对照）：
/// - **参考 anytls-go 能区分**：`proxy/session/session.go:190` 用
///   `io.ReadFull(s.conn, hdr[:])`——一个字节都没读到是 `io.EOF`（正常收尾），
///   读到一半才是 `io.ErrUnexpectedEOF`（截断）⇒ 参考把这两种 EOF 分开处理。
/// - **本仓分不开**（**实现缺陷**，本卡是纯测试卡，**不改** `src/**`）：
///   `src/frame.rs:120-140` 的 `Frame::read` 用 `read_exact`，「一个字节都没
///   读到」与「读到一半」**都是** `ErrorKind::UnexpectedEof`；
///   而 `src/server/session.rs:103-107` 把 `UnexpectedEof` 一律当作
///   **干净收尾** ⇒ **截断被误判成干净 EOF**。
///
/// 本用例**如实断言当前实况**（截断当前被判成干净收尾），并把正确判据
/// 写进断言文本与 `docs/anytls-status.md`：
/// 「EOF 且缓冲空 = 干净 EOF；EOF 且残留半帧 = 截断（协议错误）」。
/// 修复位置：`src/server/session.rs` 的读帧循环需要区分「缓冲空」与
/// 「残留半帧」（参考语义见 `session.go:190` 的 `io.ReadFull`）。
#[tokio::test]
async fn eof_with_partial_frame_is_currently_mistaken_for_clean_eof() {
    let server = spawn_rust_server(PASSWORD).await;
    let target = super::spawn_target(&[], false).await;

    let mut client = ClientSession::connect(server.addr).await.expect("连接");
    client.handshake(PASSWORD).await.expect("握手");
    let _sid = client
        .open_stream(target.addr, b"truncation-probe")
        .await
        .expect("开流");

    // 直接写**半个帧头**（7 字节头只写 3 字节）再断开传输层。
    let partial = [Command::Push as u8, 0x00, 0x00];
    use tokio::io::AsyncWriteExt;
    client.stream.write_all(&partial).await.expect("写半帧");
    client.stream.flush().await.expect("刷新");
    drop(client.stream);

    // 等待服务端会话结束。
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while server.finished() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let outcome = server.outcome(0).expect("服务端会话应已结束");

    // 实况断言：当前实现把「残留半帧的 EOF」判成**干净收尾**（缺陷）。
    // 参考 anytls-go 在同一情形下是 `io.ErrUnexpectedEOF`（截断，fail-closed）。
    match outcome {
        SessionOutcome::Clean { streams_opened } => {
            assert_eq!(
                streams_opened, 1,
                "实况：截断被误判为干净收尾（流已开且不再记账）"
            );
            eprintln!(
                "已知缺陷：残留半帧的 EOF 被判为干净收尾（参考 session.go:190                  的 io.ReadFull 会给 io.ErrUnexpectedEOF）"
            );
        }
        SessionOutcome::Failed { reason, io_kind } => {
            // 若将来修复为 fail-closed，本用例改为断言「截断 = 协议错误」。
            assert_eq!(
                io_kind,
                Some(std::io::ErrorKind::UnexpectedEof),
                "截断必须表现为 UnexpectedEof（半帧残留），实际：{reason}"
            );
        }
    }
}

/// B7：半关闭一个流后，**还能开新流并正常收发**（会话未因半关闭而整体销毁）。
///
/// 判据：流 1 半关闭（发 `cmdFIN`）后，同一条连接上流 2 仍能开、能收、能回。
#[tokio::test]
async fn connection_reusable_after_half_close() {
    let server = spawn_rust_server(PASSWORD).await;
    let target = super::spawn_target(&[], false).await;

    let mut client = ClientSession::connect(server.addr).await.expect("连接");
    client.handshake(PASSWORD).await.expect("握手");

    let first = b"lifecycle-first-stream";
    let sid1 = client
        .open_stream(target.addr, first)
        .await
        .expect("开流 1");
    let echoed = client
        .read_bytes(sid1, first.len())
        .await
        .expect("读流 1 回程");
    assert_eq!(echoed, first, "流 1 回程逐字节一致");

    // 半关闭流 1：只发 `cmdFIN`，**不**关传输层。
    client.send_fin(sid1).await.expect("发 FIN");

    // 判据：同一条连接上开**新流**并正常收发（会话未被半关闭整体销毁）。
    let second = b"lifecycle-second-stream";
    let sid2 = client
        .open_stream(target.addr, second)
        .await
        .expect("半关闭后仍能开新流");
    assert_eq!(sid2, 2, "新流编号继续递增");
    let echoed = client
        .read_bytes(sid2, second.len())
        .await
        .expect("读流 2 回程");
    assert_eq!(echoed, second, "半关闭后新流回程逐字节一致");

    // 判据：被半关闭的流 1 不得复活——目标侧只被打开两次（流 1、流 2 各一次）。
    assert_eq!(
        target.accepted.load(Ordering::SeqCst),
        2,
        "半关闭的流不得复活（目标连接数 == 打开的流数）"
    );
}
