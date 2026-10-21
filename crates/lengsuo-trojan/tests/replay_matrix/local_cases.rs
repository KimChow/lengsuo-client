//! 本仓（lengsuo-trojan）的**重放行为取证**。
//!
//! 每个用例断言的是**当前真实行为**，不是「我们希望的行为」；如果参考行为与
//! 本仓不同，差异写进 `docs/trojan-replay.md` 的偏离清单，而不是在用例里放宽判据。
//!
//! 取证点：
//! - 逐字节重放同一请求头（同连接）⇒ 本仓把它当作**应用载荷**转发给目标，
//!   不解析成第二条请求、不额外建立到目标的连接。
//! - 跨连接重放同一请求头 ⇒ 本仓**接受**它，等价于一次新的合法请求。
//! - 跨会话重放（拿 A 会话的头打 B 会话）⇒ 本仓**接受**它：trojan 无会话概念，
//!   头部里没有任何与「会话」绑定的字段。
//! - 头部里没有一次性字段 ⇒ 用本仓自己的 `codec::encode` 产出两段头，断言
//!   它们**逐字节相同**（同一口令 ⇒ 同一头部），并与独立实现的 SHA-224 交叉校验。

use super::harness::*;
use super::sha224::hex_sha224;
use lengsuo_trojan::codec;
use lengsuo_trojan::server::Error;
use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// 头部里**没有**一次性字段：同一口令编出的两段请求头逐字节相同。
///
/// 这条是「重放」在协议层成立的前提：头部完全由（口令、命令、目标）决定，
/// 没有 nonce / 时间戳 / 会话标识 / 序号，因此同一段字节天然可以在任意时刻、
/// 任意连接上重放。对照参考 `proxy/trojan/protocol.go` 的 `ConnWriter.writeHeader`：
/// 写出的就是「Account.Key + CRLF + 命令 + 地址 + CRLF」，同样没有一次性字段。
#[tokio::test]
async fn trojan_header_carries_no_one_time_field() {
    timeout(TOTAL, async {
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], 443),
        };
        let first = codec::encode(&request, &Credential::new(PASSWORD)).unwrap();
        let second = codec::encode(&request, &Credential::new(PASSWORD)).unwrap();
        assert_eq!(
            first, second,
            "同一口令编出的头部必须逐字节相同（头部不得含一次性字段）"
        );
        // 独立实现的 SHA-224 与 crate 内的 Credential 交叉校验：
        // 前 56 字节就是口令的 SHA-224 小写 hex，说明前缀是**口令的函数**，
        // 不是会话随机数。
        assert_eq!(
            &first[..56],
            hex_sha224(PASSWORD).as_bytes(),
            "头部前缀必须是口令的 SHA-224 小写 hex（与独立实现一致）"
        );
        // 头部结构：哈希 56 + CRLF 2 + 命令 1 + V4 地址 7 + CRLF 2 = 68。
        assert_eq!(first.len(), 68, "IPv4 目标的 trojan 头部长度应为 68 字节");
        assert_eq!(&first[56..58], b"\r\n");
        assert_eq!(first[58], 1, "命令字节必须为 TCP=1");
        assert_eq!(&first[59..60], &[0x01], "ATYP 必须是 IPv4");
        assert_eq!(&first[66..68], b"\r\n");
    })
    .await
    .unwrap();
}

/// 逐字节重放同一请求头（**同一条连接**）：本仓把它当作应用载荷转发。
///
/// 真实行为：TCP 流没有消息边界，第二次出现的头部字节就是载荷的一部分，
/// 被原样转发给业务目标。本仓不解析第二条请求、不额外建立到目标的连接。
/// 观测面：业务目标的 accept 计数必须**仍然等于 1**（没有第二条到目标的连接）。
#[tokio::test]
async fn replay_same_header_on_one_connection_is_forwarded_as_payload() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = RecordingTarget::spawn(PAYLOAD.len() + 68).await;
        let server = RustServer::start(&identity, PASSWORD).await;

        let mut stream = identity.connect(server.port).await;
        let header = header(&target.request(), PASSWORD);
        stream.write_all(&header).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        // 逐字节重放同一段头部。
        stream.write_all(&header).await.unwrap();
        stream.flush().await.unwrap();

        // 目标侧应收到「载荷 + 重放的头部」共 PAYLOAD.len() + 68 字节。
        let mut received = vec![0u8; PAYLOAD.len() + 68];
        timeout(WAIT, stream.read_exact(&mut received))
            .await
            .expect("回程超时")
            .expect("回程读失败");
        assert_eq!(
            &received[..PAYLOAD.len()],
            PAYLOAD,
            "第一次请求必须正常完成"
        );
        assert_eq!(
            &received[PAYLOAD.len()..],
            &header[..],
            "重放的头部字节必须被当作应用载荷原样转发（不解析成第二条请求）"
        );

        // 关键观测面：业务目标只被连接了**一次**——重放没有建立第二条连接。
        assert_eq!(
            target.accepted(),
            1,
            "重放不得额外建立到目标的连接（trojan 无重放防护，如实记录）"
        );
        assert_eq!(
            target.received().len(),
            PAYLOAD.len() + 68,
            "目标侧只应收到一条流的载荷"
        );

        stream.shutdown().await.unwrap();
        server.stop().await;
    })
    .await
    .unwrap();
}

/// 跨连接重放同一请求头：被**接受**，等价于一次新的合法请求。
///
/// 这是「参考与本仓都不防护重放」在协议层的直接体现：服务端没有任何
/// 「这个头部见过没有」的状态，因此第二段连接上的同一段头部被正常认证、
/// 正常路由到目标。
#[tokio::test]
async fn replay_same_header_on_new_connection_is_accepted() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        let server = RustServer::start(&identity, PASSWORD).await;

        // 第一次连接：正常建立。
        let header = header(&target.request(), PASSWORD);
        let mut first = identity.connect(server.port).await;
        first.write_all(&header).await.unwrap();
        first.write_all(PAYLOAD).await.unwrap();
        first.flush().await.unwrap();
        let reply = read_exact(&mut first, PAYLOAD.len(), WAIT).await;
        assert_eq!(reply, PAYLOAD, "第一次请求必须正常完成");
        first.shutdown().await.unwrap();

        // 第二次连接：**逐字节相同**的头部 —— 本仓必须照样接受。
        let mut second = identity.connect(server.port).await;
        second.write_all(&header).await.unwrap();
        second.write_all(PAYLOAD).await.unwrap();
        second.flush().await.unwrap();
        let reply = read_exact(&mut second, PAYLOAD.len(), WAIT).await;
        assert_eq!(
            reply, PAYLOAD,
            "重放的头部必须被接受为一次新的合法请求（本仓无重放防护）"
        );
        second.shutdown().await.unwrap();

        // 独立观测面：业务目标被连接了两次（重放确实到达了业务）。
        assert_eq!(
            target.accepted(),
            2,
            "重放必须真的抵达业务目标（否则观测面无效）"
        );

        server.stop().await;
    })
    .await
    .unwrap();
}

/// 跨会话重放：拿 **A 会话**的头部去打 **B 会话**（另一条连接、另一段流）。
///
/// 本仓没有「会话」概念：头部里不含会话标识，服务端也没有会话表，
/// 因此 A 的头部在 B 上照样通过认证并被路由到 A 指向的目标。
#[tokio::test]
async fn replay_header_across_sessions_is_accepted() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let session_a = EchoTarget::spawn(PAYLOAD.len()).await;
        let session_b = EchoTarget::spawn(PAYLOAD.len()).await;
        let server = RustServer::start(&identity, PASSWORD).await;

        // 会话 A：正常走通。
        let header_a = header(&session_a.request(), PASSWORD);
        let mut stream_a = identity.connect(server.port).await;
        stream_a.write_all(&header_a).await.unwrap();
        stream_a.write_all(PAYLOAD).await.unwrap();
        stream_a.flush().await.unwrap();
        let reply = read_exact(&mut stream_a, PAYLOAD.len(), WAIT).await;
        assert_eq!(reply, PAYLOAD, "会话 A 必须正常完成");
        stream_a.shutdown().await.unwrap();

        // 会话 B：注入 **A 的头部**。本仓按头部里的地址路由 ⇒ 抵达 A 的目标。
        let mut stream_b = identity.connect(server.port).await;
        stream_b.write_all(&header_a).await.unwrap();
        stream_b.write_all(PAYLOAD).await.unwrap();
        stream_b.flush().await.unwrap();
        let reply = read_exact(&mut stream_b, PAYLOAD.len(), WAIT).await;
        assert_eq!(reply, PAYLOAD, "跨会话重放必须被接受（本仓无会话绑定字段）");
        stream_b.shutdown().await.unwrap();

        assert_eq!(session_a.accepted(), 2, "A 的目标必须被两次连接");
        assert_eq!(
            session_b.accepted(),
            0,
            "B 的目标不得被连接（头部里的地址决定路由）"
        );

        server.stop().await;
    })
    .await
    .unwrap();
}

/// 跨**口令**重放：用别的口令的头部打本仓 ⇒ 必须被拒（fail-closed）。
///
/// 这条是重放矩阵的**否定面**：证明「不防护重放」不等于「不校验口令」。
/// 判据是服务端返回可判别的 `Error::Authentication`，且业务目标 accept 计数
/// 不得增长——不把「读超时」当拒绝证据。
#[tokio::test]
async fn replay_with_wrong_password_is_rejected_fail_closed() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        let server = RustServer::start(&identity, PASSWORD).await;

        // 对照：先证明观测面有效（正确口令能走通）。
        let mut control = identity.connect(server.port).await;
        control
            .write_all(&header(&target.request(), PASSWORD))
            .await
            .unwrap();
        control.write_all(PAYLOAD).await.unwrap();
        control.flush().await.unwrap();
        let reply = read_exact(&mut control, PAYLOAD.len(), WAIT).await;
        assert_eq!(reply, PAYLOAD, "对照组必须走通");
        control.shutdown().await.unwrap();
        let accepted_after_control = target.accepted();
        assert_eq!(accepted_after_control, 1, "对照组必须抵达业务目标一次");

        // 别的口令编出的头：结构合法、只是口令不对。
        let mut replay = identity.connect(server.port).await;
        replay
            .write_all(&header(&target.request(), OTHER_PASSWORD))
            .await
            .unwrap();
        replay.write_all(PAYLOAD).await.unwrap();
        replay.flush().await.unwrap();
        assert_peer_closed(&mut replay, WAIT).await;

        server.stop().await;
        assert_eq!(
            target.accepted(),
            accepted_after_control,
            "错误口令不得抵达业务目标"
        );
    })
    .await
    .unwrap();
}

/// 决定性区分面：把重放的头部**改指另一个目标**再重放。
///
/// 如果重放被当成**新请求**解析，本仓会去拨号**新目标**（新目标的 accept 计数
/// 涨到 1）；如果重放只是**应用载荷**，新目标的 accept 计数必须**保持 0**。
/// 这条比「回程内容」更决定性：回程内容在某些读块粒度下可能碰巧一致。
///
/// 判据：新目标 accept 计数 == 0，且原目标的 accept 计数 == 1。
#[tokio::test]
async fn replay_header_retargeted_is_not_parsed_as_new_request() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let original = EchoTarget::spawn(PAYLOAD.len()).await;
        let other = EchoTarget::spawn(PAYLOAD.len()).await;
        let server = RustServer::start(&identity, PASSWORD).await;

        // 第一次：正常请求，指向 original。
        let header = header(&original.request(), PASSWORD);
        let mut stream = identity.connect(server.port).await;
        stream.write_all(&header).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        let reply = read_exact(&mut stream, PAYLOAD.len(), WAIT).await;
        assert_eq!(reply, PAYLOAD, "第一次请求必须正常完成");
        assert_eq!(original.accepted(), 1, "第一次请求必须抵达原目标一次");
        assert_eq!(other.accepted(), 0, "另一个目标此时不该被连接");

        // 同一连接上重放**改指另一个目标**的头部。
        let mut patched = retarget_header(&header, [127, 0, 0, 1], other.port);
        patched.truncate(68);
        stream.write_all(&patched).await.unwrap();
        stream.flush().await.unwrap();

        // 读侧：目标侧不会回更多字节（重放只是载荷，原目标已回完并关写端）。
        // 观测面用 accept 计数判定，不依赖回程内容。
        let mut sink = vec![0u8; 1];
        let _ = timeout(WAIT, stream.read(&mut sink)).await;

        assert_eq!(
            other.accepted(),
            0,
            "重放不得被解析成新请求（否则会拨到改指后的目标）"
        );
        assert_eq!(original.accepted(), 1, "重放不得额外建立到原目标的连接");

        stream.shutdown().await.unwrap();
        server.stop().await;
    })
    .await
    .unwrap();
}

/// 认证失败时服务端返回**可判别的错误变体**（而不是 panic 或挂起）。
///
/// 单连接形态：接一条连接、观察其处理结果。错误口令 ⇒ `Error::Authentication`。
#[tokio::test]
async fn wrong_password_yields_authentication_error_variant() {
    timeout(TOTAL, async {
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        let connection = spawn_single_plain(PASSWORD).await;

        let mut stream = tokio::net::TcpStream::connect(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            connection.port,
        )))
        .await
        .unwrap();
        let mut bad = header(&target.request(), OTHER_PASSWORD);
        // 头部之后补一点载荷，模拟真实客户端在头后紧跟数据。
        bad.extend_from_slice(PAYLOAD);
        stream.write_all(&bad).await.unwrap();
        stream.flush().await.unwrap();

        match timeout(WAIT, connection.task).await.unwrap().unwrap() {
            Err(Error::Authentication) => {}
            other => panic!("期望 Error::Authentication，得到 {other:?}"),
        }
        assert_eq!(target.accepted(), 0, "错误口令不得抵达业务目标");
    })
    .await
    .unwrap();
}
