//! A 组：半关闭（half-close）—— 对应 `docs/audit-all1.md` §3 矩阵的
//! 「半关闭」格（原为 ❌）。
//!
//! 语义基线（参考实现）：
//! - `transport/internet/hysteria/conn.go` `interConn.Close()` =
//!   `stream.CancelRead(0)` + `stream.Close()`；`interConn.Write` 走
//!   `quic.Stream.Write`（**不**带 FIN 语义），半关闭由 QUIC 流的
//!   **FIN 帧**表达（quic-go 的 `stream.Close()` 发 FIN）。
//! - `proxy/hysteria/client.go` 的 TCP 分支用 `buf.Copy` 双向中继；
//!   `common/buf/copy.go` 的 `Copy` 在读到 `io.EOF` 时**正常返回 nil**
//!   ⇒ 读方向的 EOF 是**干净 EOF**，不是错误。
//! - `proxy/hysteria/server.go` 的 TCP 分支把 `interConn` 直接交给
//!   `dispatcher.DispatchLink`（`Reader: buf.NewReader(conn)`）⇒ 服务端
//!   读到客户端 FIN 后，读方向返回 EOF。
//!
//! 本仓对应实现：`proxy::TcpProxyStream::finish()`（发送侧 FIN，
//! 对齐 `interConn.Close` 的发送半边）与 `proxy::relay`（服务端把 QUIC
//! 流的 EOF 转成出站 TCP 的 `shutdown(Write)` ⇒ 目标读到干净 EOF）。
//!
//! ⚠️ 关键区分（任务书点名）：**「EOF 且缓冲空」是干净 EOF（`Ok(0)` /
//! `Ok(None)`）；「EOF 且残留半帧」才是协议错误**。本组用例逐条区分这两者。

use super::{
    client_udp_table, connect_with, pattern, spawn_tcp_target, spawn_udp_target, start_server,
    wait_until, ClientUdpTable, TargetEvent, TargetScript, IO_TIMEOUT, RECLAIM_DEADLINE,
};
use lengsuo_hysteria::proxy;
use lengsuo_hysteria::tcp::{Status, TcpResponse};

/// A1：客户端单向半关闭 ⇒ 对端仍能收到**完整**载荷，且读方向仍可继续收。
///
/// 断言语义：
/// 1. 客户端写完载荷后 `finish()`（只关写端），目标端必须**完整**收到
///    全部载荷（不是被当成连接断开而截断/丢失）；
/// 2. 目标端在客户端半关闭之后才回写数据 ⇒ 客户端**仍能读到**回包
///    （半关闭不是全关闭）；
/// 3. 目标端读到 EOF（干净 EOF，`Ok(0)`）⇒ 目标端确实看到了 FIN。
#[tokio::test]
async fn half_close_client_write_side_keeps_read_direction_alive() {
    let server = start_server("hc1", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 目标：先读完，等 EOF（客户端半关闭）之后才回写。
    let payload = pattern(64 * 1024);
    let reply = pattern(4096);
    let target = spawn_tcp_target(TargetScript::ReplyAfterEof(reply.clone())).await;

    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");

    // 写入载荷 → 半关闭（只关写端）。
    let write_fut = async {
        stream.write_all(&payload).await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 断言 1：目标端完整收到载荷（半关闭没有把数据截断）。
    let got = tokio::time::timeout(IO_TIMEOUT, async {
        loop {
            let got = target.received();
            if got.len() >= payload.len() {
                break got;
            }
            // 让出调度（`#[tokio::test]` 是单线程运行时，忙等会饿死它）。
            tokio::time::sleep(super::POLL_INTERVAL).await;
        }
    })
    .await
    .expect("等待目标收全载荷超时");
    assert_eq!(
        got.len(),
        payload.len(),
        "半关闭后目标端应收全载荷，实际收到 {} / {} 字节",
        got.len(),
        payload.len()
    );
    assert_eq!(got, payload, "半关闭后目标端收到的载荷内容不符");

    // 断言 2：目标端在客户端半关闭之后才回写 ⇒ 客户端读方向仍可继续收。
    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    let read_fut = async {
        while received.len() < reply.len() {
            let n = stream.read(&mut buf).await.expect("读取失败");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        received
    };
    let received = tokio::time::timeout(IO_TIMEOUT, read_fut)
        .await
        .expect("半关闭后读取回包超时");
    assert_eq!(
        received, reply,
        "半关闭后读方向应仍能收到完整回包（半关闭不是全关闭）"
    );
}

/// A2：对端半关闭的对称性 —— 服务端侧先关写端 ⇒ 客户端读到**干净 EOF**，
/// 不是 `Err(UnexpectedEof)` / `ConnectionReset`。
///
/// ⚠️ 关键区分：目标端在读到第一批数据后回写一段数据，然后
/// `shutdown(Write)`（**半关闭写端**），但**继续读**。于是：
/// - 客户端 `read` 必须先返回 `Ok(n)` 拿到数据，**随后**返回 `Ok(0)`
///   （干净 EOF，且缓冲已空）；
/// - 客户端**不得**收到任何读错误（`Err(UnexpectedEof)` / `Err(Reset)` /
///   `Err(ConnectionLost)`）—— 那才叫「把半关闭当成了连接断开」。
/// - 也**不得**是「EOF 但缓冲里还有残留字节」（那是残帧被误当干净 EOF）。
#[tokio::test]
async fn half_close_peer_write_side_yields_clean_eof() {
    let server = start_server("hc2", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 目标：读到第一批数据后回写，再半关闭写端（但继续读）。
    let reply = pattern(64);
    let mut target = spawn_tcp_target(TargetScript::ReplyThenHalfClose(reply.clone())).await;

    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");

    let payload = pattern(1024);
    let write_fut = async {
        stream.write_all(&payload).await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 客户端读：先拿到数据，再拿到干净 EOF（缓冲空）。
    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    let mut eof = false;
    let read_fut = async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) => panic!("半关闭的读方向不应报错（干净 EOF 才是期望）：{e:?}"),
            }
        }
    };
    tokio::time::timeout(IO_TIMEOUT, read_fut)
        .await
        .expect("等待干净 EOF 超时");

    assert!(eof, "对端半关闭写端后，客户端应读到干净 EOF（Ok(0)）");
    assert_eq!(
        received,
        reply,
        "干净 EOF 之前的数据必须完整送达（收到 {} 字节，期望 {} 字节）",
        received.len(),
        reply.len()
    );

    // 目标端确实观察到了客户端的 FIN（客户端半关闭的写端）。
    let saw_eof = target.wait_event(|ev| ev == TargetEvent::Eof).await;
    assert!(saw_eof, "目标端应读到客户端半关闭产生的 EOF");
}

/// A2b：「EOF 且缓冲空」是干净 EOF，「EOF 且残留半帧」才是协议错误。
///
/// 本用例把两种 EOF 语义**显式区分**开：
///
/// 1. **干净 EOF（端到端，客户端方向）**：服务端把**完整**响应帧发完后
///    关闭流 ⇒ 客户端先读到完整帧，再读到 `Ok(0)`，且**缓冲已空**
///    ⇒ 判为干净 EOF（对齐参考 `common/buf/copy.go` 的 `Copy` 遇
///    `io.EOF` 正常返回 nil）。
/// 2. **残缺帧 = 协议错误（帧级判定）**：一个**被截断**的 TCPResponse
///    帧，解码器必须报 `Truncated`（协议错误），**不得**被当成完整帧
///    接受（对齐参考 `protocol.go` `ReadTCPResponse` 的 `io.ReadFull`
///    短读 ⇒ 错误）。
///
/// ⚠️ 口径说明（为什么第 2 条在帧级而不是流级断言）：
/// QUIC 流的读侧只把 **FIN** 映射成 EOF（`Ok(None)`），QUIC 本身没有
/// 「半帧」概念（HTTP/3 的帧边界在 H3 层）；而本仓服务端的响应帧是
/// `send.write_all(&response)` **原子**写出的 ⇒ 「干净 FIN + 半截响应
/// 帧」在**客户端流层**不可构造。故协议级判定落在**帧解码器**上，
/// 而**服务端请求解析器**的同类判定（残缺请求 ⇒ 拒绝、不建承载）由
/// `cleanup::cleanup_server_rejects_malformed_frame_without_residue`
/// 端到端覆盖。
#[tokio::test]
async fn half_close_clean_eof_is_distinct_from_truncated_frame() {
    let server = start_server("hc2b", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // --- 1. 干净 EOF：完整响应帧 + 流结束 ---
    let target = spawn_tcp_target(TargetScript::CloseAfterFirstRead).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    // 写一点数据让服务端侧承载跑起来（响应帧此时已完整发出）。
    let write_fut = async {
        stream.write_all(b"ping").await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 读方向：先拿到响应帧之后的目标数据（此处为空），再拿到干净 EOF。
    // `ReadOutcome::CleanEof` 的定义就是「EOF 且缓冲为空」。
    let outcome = tokio::time::timeout(IO_TIMEOUT, super::read_proxy_to_eof(&mut stream))
        .await
        .expect("等待干净 EOF 超时");
    match outcome {
        super::ReadOutcome::CleanEof { data } => {
            assert!(data.is_empty(), "完整响应帧之后不应有残留字节");
        }
        super::ReadOutcome::EofWithResidue { data } => {
            panic!("完整响应帧后读到的是「EOF 且有残留」（{data:?}）——不该发生")
        }
        super::ReadOutcome::ReadError { err, .. } => {
            panic!("干净路径不应有读错误：{err}");
        }
    }

    // --- 2. 残缺帧 = 协议错误（帧级判定）---
    // 完整帧：解码器必须接受。
    let full = TcpResponse {
        status: Status::Ok,
        message: "ok".to_string(),
        padding: vec![0u8; 16],
    }
    .encode()
    .expect("编码完整响应帧");
    let (decoded, consumed) = TcpResponse::decode(&full).expect("完整帧应解码成功");
    assert_eq!(decoded.status, Status::Ok, "完整帧的状态字节应正确");
    assert_eq!(consumed, full.len(), "完整帧应被精确消耗");

    // 截断到一半：解码器必须报**协议错误**（`Truncated`），不得放行。
    let truncated = &full[..full.len() / 2];
    match TcpResponse::decode(truncated) {
        Err(lengsuo_hysteria::Error::Truncated { .. }) => {}
        Err(other) => panic!("残缺帧应报 Truncated，实际 {other:?}"),
        Ok(_) => panic!("残缺帧不得被当成完整帧接受（协议错误被放行）"),
    }
}

/// A3：半关闭后的复用 —— 同一 QUIC 连接上，半关闭一个 stream 后**还能开
/// 新 stream 并正常收发**（会话表未因半关闭而整体销毁）。
///
/// 这条直接对应矩阵「半关闭」格的关键风险：半关闭若被实现成「拆连接」，
/// 新流就开不出来。
#[tokio::test]
async fn half_close_then_reuse_same_connection() {
    let server = start_server("hc3", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 第一条流：正常交互后半关闭。
    let first_target = spawn_tcp_target(TargetScript::ReplyThenDrain(pattern(64))).await;
    let mut first = proxy::tcp_connect(&client, &first_target.addr.to_string())
        .await
        .expect("第一条流 tcp_connect 失败");
    let payload = pattern(128);
    let first_fut = async {
        first.write_all(&payload).await.expect("写入失败");
        first.finish().expect("半关闭失败");
        let mut buf = vec![0u8; 64];
        let mut got = Vec::new();
        while got.len() < 64 {
            let n = first.read(&mut buf).await.expect("读取失败");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    };
    let got = tokio::time::timeout(IO_TIMEOUT, first_fut)
        .await
        .expect("第一条流交互超时");
    assert_eq!(got, pattern(64), "第一条流回包内容不符");

    // 第二条流：同一条 QUIC 连接上重新开流，必须能正常收发。
    let second_target = spawn_tcp_target(TargetScript::ReplyThenDrain(pattern(32))).await;
    let mut second = proxy::tcp_connect(&client, &second_target.addr.to_string())
        .await
        .expect("半关闭后应仍能开新流并建连");
    let second_fut = async {
        second.write_all(b"second").await.expect("写入失败");
        second.finish().expect("半关闭失败");
        let mut buf = vec![0u8; 32];
        let mut got = Vec::new();
        while got.len() < 32 {
            let n = second.read(&mut buf).await.expect("读取失败");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    };
    let got = tokio::time::timeout(IO_TIMEOUT, second_fut)
        .await
        .expect("第二条流交互超时");
    assert_eq!(got, pattern(32), "半关闭后新流的回包内容不符");

    // 连接本身仍然活着：客户端 UDP 会话表未被清空。
    assert_eq!(
        client_udp_table(&client).await,
        ClientUdpTable::Open,
        "半关闭一个 stream 不应影响整条连接（客户端会话表仍开着）"
    );
}

/// A4：UDP 侧的对应语义 —— UDP 无连接，半关闭**不适用**。
///
/// 本用例把这一格从「❌」变成「**明确的『不适用 + 有据』**」：
/// 1. UDP 路径**不暴露**半关闭概念：`proxy::udp_out_datagrams` /
///    `UdpSession` 的 API 里没有任何 FIN/half-close 入口（只有
///    `send_raw` / `recv_raw`，收发的是**完整数据报**）；
/// 2. 实证：一次 UDP 往返收到的是**完整数据报**（载荷逐字节相符），
///    不存在「半个数据报」这种半关闭中间态。
#[tokio::test]
async fn half_close_is_not_applicable_to_udp_datagrams() {
    let server = start_server("hc4", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");
    let target = spawn_udp_target().await;

    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    let payload = pattern(512);
    let addr_bytes = target.addr.to_string().into_bytes();
    let dgrams =
        proxy::udp_out_datagrams(session.id, &addr_bytes, &payload, 1200).expect("组 UDP datagram");
    for d in &dgrams {
        session.send_raw(d).expect("UDP 发送失败");
    }
    let mut defrag = proxy::OwnedDefragger::default();
    let got = tokio::time::timeout(IO_TIMEOUT, proxy::udp_recv(&mut session, &mut defrag))
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");

    // 断言 1：收到的是**完整数据报**（逐字节相符，无半截）。
    assert_eq!(
        got.data, payload,
        "UDP 收到的是完整数据报，不存在半关闭的中间态"
    );

    // 断言 2：UDP 路径不暴露半关闭概念 —— 会话句柄只有数据报收发，
    // 没有任何 FIN/half-close 入口（类型上就没有）。
    //
    // 编译期证据：`UdpSession` 的公开方法集是
    // `recv_raw` / `send_raw` / `max_datagram_size`（见
    // `quic/client.rs`），没有 `finish` / `shutdown`。
    // 运行期证据：同一会话在「发完一批」之后仍能继续收发 ⇒ 会话没有被
    // 半关闭掉。
    let payload2 = pattern(256);
    let dgrams2 = proxy::udp_out_datagrams(session.id, &addr_bytes, &payload2, 1200)
        .expect("组 UDP datagram");
    for d in &dgrams2 {
        session.send_raw(d).expect("UDP 发送失败");
    }
    let got2 = tokio::time::timeout(IO_TIMEOUT, proxy::udp_recv(&mut session, &mut defrag))
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");
    assert_eq!(got2.data, payload2, "同一 UDP 会话应能继续收发完整数据报");

    // 断言 3：UDP 会话全程未被「半关闭」：客户端会话表仍开着。
    assert_eq!(
        client_udp_table(&client).await,
        ClientUdpTable::Open,
        "UDP 路径不应出现半关闭导致的会话关闭"
    );
}

/// A5：半关闭**不**触发会话回收（半关闭 ≠ 清理）。
///
/// 半关闭一个 stream 之后，承载（QUIC 连接）仍然存活 ⇒ 服务端的连接级
/// 会话表**不应**归零。这条把「半关闭」与「清理」两格在语义上分开：
/// 半关闭只关一个方向，清理才拆连接。
#[tokio::test]
async fn half_close_does_not_reclaim_sessions() {
    let server = start_server("hc5", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 先建一条 TCP 承载，确认服务端连接数 ≥ 1。
    let target = spawn_tcp_target(TargetScript::CloseAfterFirstRead).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    let write_fut = async {
        stream.write_all(b"x").await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 服务端连接数不为 0（承载还活着）。
    let reclaimed = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() == 0
    })
    .await;
    assert!(
        !reclaimed,
        "半关闭不应导致会话被回收（服务端连接数应仍 > 0，实际 {}）",
        server.open_connections()
    );
    assert!(
        server.open_connections() >= 1,
        "半关闭后承载仍应存活，服务端连接数 = {}",
        server.open_connections()
    );
}
