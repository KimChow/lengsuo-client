//! A. 重放（对应 `docs/audit-all1.md` §3 矩阵的「重放」格）。
//!
//! 三条判据 + 一条口径判定：
//! 1. **同帧重放被拒**：同一个 payload 帧再发一次 ⇒ 服务端必须**拒绝**
//!    （Alert / 断开 / 明确协议错误），**不得**当作新数据正常处理。
//! 2. **重放不得产生第二次副作用**：重放开流命令 ⇒ 目标流只被打开一次。
//! 3. **跨会话重放**：A 会话录制的帧序列在 B 会话重放 ⇒ B 会话**不接受**（会话隔离）。
//! 4. **判定口径如实**：参考 anytls-go 本身是否防护重放？结论与行号见
//!    `docs/anytls-status.md`「异常矩阵补缺（重放 / 半关闭）」。
//!
//! ── 结论（实跑得出，见同名用例的断言）────────────────────────────
//! **参考 anytls-go 本身不防重放，本仓同样不防重放。** 因此本格只能记为
//! 「**验证了不防护**」，不得写成「本仓防了重放」。逐条依据：
//!
//! - `proxy/session/session.go:196-208`（cmdPSH 分支）：按 sid 找流后
//!   **无重放窗口、无序号、无去重**，`stream.pipeW.Write(buffer)` 直接转发
//!   ⇒ **同一个 PUSH 帧重发会被当作又一段应用数据再转发一次**。
//! - `proxy/session/session.go:216-228`（cmdSYN 分支）：`if _, ok := s.streams[sid]; !ok`
//!   才新建流 ⇒ 同 sid 的 SYN 重放**幂等**（不开第二条流、也不报错）。
//! - `proxy/session/session.go:251-259`（cmdFIN 分支）：删除流后即
//!   `closeLocally`；重放的 FIN 找不到流 ⇒ **静默忽略**。
//! - 认证块只有 `SHA256(口令)`（`cmd/server/inbound_tcp.go:44-46` 只做摘要
//!   比对）⇒ **没有随机数/时间戳/计数器** ⇒ 跨会话重放认证块同样被接受。
//!
//! 本仓对应实现同样不防：`src/server_state.rs:128-132` 的 PUSH 判据只有
//! 「该 sid 在活跃集合内」，而活跃集合**不因数据帧变化** ⇒ 活跃流上的重放帧
//! 被再次转发；`src/auth.rs:52-63` 的认证比对只有 SHA256 摘要 ⇒ 无会话绑定。
use super::{default_md5, push_with_target, settings, spawn_target, Harness, PASSWORD, WAIT};
use lengsuo_anytls::frame::{Command, Frame};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// 重放载荷标记。
const PAYLOAD: &[u8] = b"lifecycle-replay-first-frame";

/// A1：同帧重放**不被拒**（如实记录「参考与本仓都不防重放」）。
///
/// 判据：客户端完成认证 + Settings 后，把**同一个 payload 帧**再发一次。
/// 本仓的 `ServerState` 对 PUSH 的判据是「该 sid 必须处于活跃集合」
/// （`src/server_state.rs:128-132`），活跃集合在 FIN 时移除、**从不因数据帧
/// 而变化** ⇒ 重放一个**仍在活跃**的 PUSH 帧**不会**被状态机拒绝。
///
/// 本用例**如实记录该行为**（不谎称「已防护」）：
/// 1. 重放帧被**再次转发**给目标（目标侧字节数翻倍）；
/// 2. 服务端**未**回 Alert、会话**未**中断（不是「拒绝」语义）。
///
/// 断言的字节内容是**整帧载荷**（含 SOCKS 地址前缀）：服务端把 PUSH 帧的
/// data 整体转发（`src/server/streams.rs:150-163`），前缀只在**首帧**被消费。
#[tokio::test]
async fn replayed_push_frame_is_not_specially_guarded() {
    let mut harness = Harness::start(PASSWORD).await;
    let target = spawn_target(&[], false).await;

    harness.send(settings(&default_md5())).await;
    harness.expect(Command::ServerSettings).await;

    // 开流：SYN + 首帧 PUSH（目标地址 + 载荷）。
    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    let push = Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(target.addr, PAYLOAD),
    };
    push.write(&mut harness.client, WAIT).await.expect("写首帧");

    // 等首帧回程（SYNACK + echo），证明首帧确实被处理。
    let ack = harness.expect(Command::SynAck).await;
    assert_eq!(ack.stream_id, 1, "SYNACK 绑定同一流");
    let echoed = harness.expect(Command::Push).await;
    assert_eq!(
        echoed.data, PAYLOAD,
        "首帧回程只有载荷（SOCKS 地址前缀被服务端消费）"
    );

    // 重放：**同一个 payload 帧**再发一次（逐字节相同的帧）。
    push.write(&mut harness.client, WAIT)
        .await
        .expect("写重放帧");

    // 判据一：重放不是被静默丢弃——它被**整帧**再次转发给目标（地址前缀
    // 已在首帧被消费，重放帧里又被当作普通字节发过去），回显原样返回。
    let replay_echo = harness.expect(Command::Push).await;
    assert_eq!(
        replay_echo.data, push.data,
        "重放字节被再次转发到目标（参考与本仓同样不防重放）"
    );

    // 判据二：重放**没有**触发 Alert，会话仍然干净收尾（不是「拒绝」语义）。
    let stats = harness.finish().await.expect("会话干净收尾");
    assert_eq!(stats.streams_opened, 1, "重放未开新流");
    assert_eq!(
        stats.bytes_to_target,
        PAYLOAD.len() + push.data.len(),
        "目标共收到两份字节（首帧载荷 + 重放整帧）"
    );
}

/// A1'：重放**不是**「被拒绝」，因此也**不得**谎称本仓防了重放。
///
/// 该用例把「无防护」这一事实钉在断言里：重放后目标侧字节数翻倍，
/// 且会话未收到 Alert。参考同口径（`session.go:196-208`）。
#[tokio::test]
async fn replayed_push_reaches_target_twice_without_alert() {
    let mut harness = Harness::start(PASSWORD).await;
    let target = spawn_target(&[], false).await;

    harness.send(settings(&default_md5())).await;
    harness.expect(Command::ServerSettings).await;
    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    let push = Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(target.addr, PAYLOAD),
    };
    push.write(&mut harness.client, WAIT).await.expect("写首帧");
    harness.expect(Command::SynAck).await;
    harness.expect(Command::Push).await;

    // 重放同一帧两次（更贴近「录制的帧序列被重放」）。
    for _ in 0..2 {
        push.write(&mut harness.client, WAIT)
            .await
            .expect("写重放帧");
    }
    // 目标应累计收到：首帧载荷（地址前缀已消费）+ 2 次整帧重放。
    let want = PAYLOAD.len() + push.data.len() * 2;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while target.received().len() < want && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        target.received().len(),
        want,
        "参考与本仓都不防重放：目标累计收到 {} 字节（首帧 + 2 次重放）",
        target.received().len()
    );
    assert_eq!(
        target.occurrences(PAYLOAD),
        3,
        "参考与本仓都不防重放：目标累计收到 3 份相同载荷"
    );
    // 无 Alert：会话未因重放而中断。
    let stats = harness.finish().await.expect("会话干净收尾");
    assert_eq!(stats.streams_opened, 1, "重放未开新流");
}

/// A2：重放**不得**产生第二次副作用。
///
/// 判据：重放的是「打开新流」的命令（SYN）⇒ 目标流**只被打开一次**
/// （不得出现两条同 id 流；目标 accept 计数必须 == 1）。
///
/// 本仓的 `ServerState` 明确要求 SYN 的流编号**严格递增**
/// （`src/server_state.rs:118-120`）⇒ 重放同 id 的 SYN 会被**拒绝**
/// （fail-closed，结束会话）。参考 anytls-go 则是**幂等**：同 sid 的 SYN
/// 不新建流、也不报错（`session.go:216-228`）。两者都不产生「第二条流」，
/// 但拒绝方式不同——本用例把「只被打开一次」作为共同判据，两侧都成立。
#[tokio::test]
async fn replayed_syn_opens_the_target_stream_only_once() {
    let mut harness = Harness::start(PASSWORD).await;
    let target = spawn_target(&[], false).await;

    harness.send(settings(&default_md5())).await;
    harness.expect(Command::ServerSettings).await;

    // 首次 SYN（打开流 1）。
    let syn = Frame {
        command: Command::Syn,
        stream_id: 1,
        data: Vec::new(),
    };
    syn.write(&mut harness.client, WAIT).await.expect("写 SYN");
    harness
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, PAYLOAD),
        })
        .await;
    harness.expect(Command::SynAck).await;
    harness.expect(Command::Push).await;

    // 重放**同一个 SYN 帧**（同 id）。
    syn.write(&mut harness.client, WAIT)
        .await
        .expect("写重放 SYN");

    // 判据：目标**只被打开一次**——没有第二条同 id 的流。
    // 两种可能的拒绝表现都算「未开第二条流」：本仓会 fail-closed 结束会话
    // （重放 SYN 的流编号未严格递增 ⇒ `InvalidStream` ⇒ 会话失败）。
    let outcome = harness.finish().await;
    match &outcome {
        Ok(stats) => {
            // 参考语义：会话继续，但流数不增加。
            assert_eq!(stats.streams_opened, 1, "重放 SYN 不得开第二条流");
        }
        Err(_) => {
            // 本仓语义：fail-closed 拒绝重放（仍不得开第二条流）。
        }
    }
    assert_eq!(
        target.accepted.load(Ordering::SeqCst),
        1,
        "目标只被连接一次（重放 SYN 不得产生第二次拨号）"
    );
}

/// A3：跨会话重放 ⇒ **B 会话同样接受**（参考与本仓都**没有**会话隔离）。
///
/// 判据原文是「B 会话**不接受**（会话隔离）」。实跑结论是：**该期望不成立**，
/// 原因是协议层根本没有会话绑定这一概念：
///
/// - 认证块只有 `SHA256(口令)`，无随机数/时间戳/计数器
///   （参考 `cmd/server/inbound_tcp.go:44-46`；本仓 `src/auth.rs:52-63`），
///   ⇒ A 会话的认证块在 B 会话**同样通过**；
/// - 流编号空间是**每连接**的（参考 `Session.streamId`；本仓
///   `src/server_state.rs:50` 的 `max_syn_id` 是会话内状态），
///   ⇒ A 会话的 SYN(1) 在 B 会话就是「一条正常的新流」。
///
/// 因此本用例**如实断言「B 会话接受」**，并在标题与文档里写明
/// 「**验证了参考也不防护**」，不得谎称本仓实现了会话隔离。
#[tokio::test]
async fn cross_session_replay_is_accepted_by_the_other_session() {
    // A 会话：录制认证块与流帧字节。
    let mut session_a = Harness::start(PASSWORD).await;
    let target = spawn_target(&[], false).await;
    session_a.send(settings(&default_md5())).await;
    session_a.expect(Command::ServerSettings).await;

    let auth_bytes = super::client::auth_block(PASSWORD);
    let syn_bytes = Frame {
        command: Command::Syn,
        stream_id: 1,
        data: Vec::new(),
    }
    .encode()
    .expect("SYN 编码");
    let push_bytes = Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(target.addr, PAYLOAD),
    }
    .encode()
    .expect("PUSH 编码");
    // A 会话真正把这段字节发出去（录制的必须是「A 已发出的字节」）。
    session_a.send_raw(&syn_bytes).await;
    session_a.send_raw(&push_bytes).await;
    session_a.expect(Command::SynAck).await;
    session_a.expect(Command::Push).await;
    let stats_a = session_a.finish().await.expect("A 会话干净收尾");
    assert_eq!(stats_a.streams_opened, 1, "A 会话开了 1 条流");

    // B 会话：把 A 录制的认证块与流帧**原样重放**。
    let (client_b, server_b) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(lengsuo_anytls::server::serve(
        server_b,
        lengsuo_anytls::server::ServerConfig::new(PASSWORD, WAIT),
    ));
    let mut harness_b = Harness {
        client: client_b,
        task,
    };
    // 判据一：跨会话重放**认证块**被接受（两侧都无防重放）。
    harness_b.send_raw(&auth_bytes).await;
    harness_b.send(settings(&default_md5())).await;
    let server_settings = harness_b.expect(Command::ServerSettings).await;
    assert_eq!(
        server_settings.data, b"v=2",
        "B 会话用 A 的认证块仍能完成协商（两侧都无防重放）"
    );

    // 判据二：A 录制的**流帧**在 B 会话被**当作新流接受**——无会话隔离。
    harness_b.send_raw(&syn_bytes).await;
    harness_b.send_raw(&push_bytes).await;
    let ack = harness_b.expect(Command::SynAck).await;
    assert_eq!(ack.stream_id, 1, "B 会话把重放的 SYN 当作自己的 1 号流");
    let echoed = harness_b.expect(Command::Push).await;
    assert_eq!(
        echoed.data, PAYLOAD,
        "B 会话照样把重放的 PUSH 转发给目标（地址前缀被当作首帧消费）"
    );

    // 判据三：目标被**第二次**拨号（A 的流、B 的流各一次）⇒ 跨会话重放确有副作用。
    let stats_b = harness_b.finish().await.expect("B 会话干净收尾");
    assert_eq!(stats_b.streams_opened, 1, "B 会话开了 1 条流");
    assert_eq!(
        target.accepted.load(Ordering::SeqCst),
        2,
        "跨会话重放确实产生了第二次拨号（无会话隔离）"
    );
}
