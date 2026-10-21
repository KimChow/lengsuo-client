//! **固定基线参考**（Xray v26.3.27，commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//! 的重放行为**独立复核**（续）：参考客户端重放、参考服务端同连接转发、
//! 「改指目标」的决定性区分面、错误口令的否定面，以及双向互通对照组。
//!
//! 与 `reference_cases.rs` 同源，共享同一套夹具与判定纪律：拒绝必须有独立观测面
//! （业务目标 accept 计数），**不把「我方读超时」当拒绝**；每条用例都带正常对照组。

use super::harness::*;
use super::reference_cases::{
    reference_client_config, reference_client_tls_config, reference_round_trip,
    reference_server_config, reference_server_tls_config, CAPTURE_BOUND,
};
use super::sha224::hex_sha224;
use super::support;
use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// ③ 参考**客户端**重放自己的头：连两次参考服务端，第二次照样被接受。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reference_client_replay_is_accepted_by_reference_server() {
    timeout(TOTAL, async {
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        let server_port = support::free_port();
        let reference =
            support::launch(reference_server_config(server_port, PASSWORD), server_port).await;

        // 第一次会话。
        let socks_a = support::free_port();
        let client_a = support::launch(
            reference_client_config(socks_a, server_port, PASSWORD),
            socks_a,
        )
        .await;
        reference_round_trip(socks_a, target.port).await;
        drop(client_a);
        assert_eq!(target.accepted(), 1, "第一次会话必须抵达业务目标一次");

        // 第二次会话：参考客户端**重新写一遍同样的头**（参考的头无一次性字段，
        // 所以两次字节相同），参考服务端必须照样接受。
        let socks_b = support::free_port();
        let client_b = support::launch(
            reference_client_config(socks_b, server_port, PASSWORD),
            socks_b,
        )
        .await;
        reference_round_trip(socks_b, target.port).await;
        drop(client_b);

        assert_eq!(
            target.accepted(),
            2,
            "第二次会话必须抵达业务目标（参考不防护重放）"
        );

        drop(reference);
    })
    .await
    .unwrap();
}

/// ④ 参考**服务端**在**同一条连接**上收到重放的头部：同样当作应用载荷转发，
///    不解析成第二条请求、不额外建立到目标的连接。
///
/// 这是本仓同名用例（`local_cases::replay_same_header_on_one_connection_is_forwarded_as_payload`）
/// 的**参考侧对照**：两边都必须表现为「转发为载荷 + 只连一次」。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reference_server_forwards_replayed_header_on_same_connection() {
    timeout(TOTAL, async {
        // 目标按脚本读满：第一次「载荷」，第二次「载荷 + 重放的头部」。
        // 长度在连接发生前登记，不依赖时序猜测。
        let target = ScriptedTarget::spawn(vec![PAYLOAD.len(), PAYLOAD.len() + 68]).await;
        let server_port = support::free_port();
        let reference =
            support::launch(reference_server_config(server_port, PASSWORD), server_port).await;

        // 先用参考客户端跑一次，拿到它真正写出的头部字节。
        let capture = CaptureServer::spawn(server_port, true).await;
        let socks = support::free_port();
        let client = support::launch(
            reference_client_config(socks, capture.port, PASSWORD),
            socks,
        )
        .await;
        reference_round_trip(socks, target.port).await;
        drop(client);

        let deadline = tokio::time::Instant::now() + CAPTURE_BOUND;
        let header = loop {
            let seen = capture.headers();
            if !seen.is_empty() {
                break seen[0].clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "捕获端未在预算内看到参考客户端写出的头部"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(header.len(), 68, "IPv4 目标的 trojan 头部长度应为 68 字节");
        assert_eq!(
            target.accepted(),
            1,
            "对照组：第一次请求必须抵达业务目标一次"
        );

        // 现在**同一条连接**上写：头 + 载荷 + 重放的头。
        let mut stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        stream.write_all(&header).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.write_all(&header).await.unwrap();
        stream.flush().await.unwrap();

        let mut reply = vec![0u8; PAYLOAD.len() + 68];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .expect("回程超时")
            .expect("回程读失败");
        assert_eq!(&reply[..PAYLOAD.len()], PAYLOAD, "第一次请求必须正常完成");
        assert_eq!(
            &reply[PAYLOAD.len()..],
            &header[..],
            "参考服务端必须把重放的头部当作应用载荷转发"
        );
        stream.shutdown().await.unwrap();

        // 独立观测面：目标仍只被连接了**一次**（重放没有建立第二条连接）。
        assert_eq!(target.accepted(), 2, "对照组那条 + 重放那条 = 两次连接");

        capture.stop().await;
        drop(reference);
    })
    .await
    .unwrap();
}

/// ⑤ 决定性区分面（参考侧）：同一条连接上重放**改指另一个目标**的头部。
///
/// 与本仓同名用例（`local_cases::replay_header_retargeted_is_not_parsed_as_new_request`）
/// 对照：参考若把重放当成新请求，就会拨号改指后的目标（新目标 accept 计数
/// 涨到 1）；参考与本仓都只把它当载荷 ⇒ 新目标 accept 计数保持 0。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reference_server_does_not_parse_replayed_header_as_new_request() {
    timeout(TOTAL, async {
        let original = EchoTarget::spawn(PAYLOAD.len()).await;
        let other = EchoTarget::spawn(PAYLOAD.len()).await;
        let server_port = support::free_port();
        let reference =
            support::launch(reference_server_config(server_port, PASSWORD), server_port).await;

        // 先用参考客户端跑一次，拿到它真正写出的头部字节。
        let capture = CaptureServer::spawn(server_port, true).await;
        let socks = support::free_port();
        let client = support::launch(
            reference_client_config(socks, capture.port, PASSWORD),
            socks,
        )
        .await;
        reference_round_trip(socks, original.port).await;
        drop(client);

        let deadline = tokio::time::Instant::now() + CAPTURE_BOUND;
        let header = loop {
            let seen = capture.headers();
            if !seen.is_empty() {
                break seen[0].clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "捕获端未在预算内看到参考客户端写出的头部"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(original.accepted(), 1, "对照组必须抵达原目标一次");
        assert_eq!(other.accepted(), 0, "另一个目标此时不该被连接");

        // 同一连接上重放**改指另一个目标**的头部。
        let patched = retarget_header(&header, [127, 0, 0, 1], other.port);
        let mut stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        stream.write_all(&header).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.write_all(&patched).await.unwrap();
        stream.flush().await.unwrap();

        // 观测面用 accept 计数判定，不依赖回程内容。
        let mut sink = vec![0u8; 1];
        let _ = timeout(WAIT, stream.read(&mut sink)).await;

        assert_eq!(
            other.accepted(),
            0,
            "参考不得把重放解析成新请求（否则会拨到改指后的目标）"
        );
        // 原目标被连了两次：一次是对照会话，一次是本次重放所在的**新连接**
        // （参考服务端对每条入站连接各拨一次目标，这是正常行为）。
        assert_eq!(
            original.accepted(),
            2,
            "原目标应只被「对照会话 + 重放会话」各连一次"
        );

        stream.shutdown().await.unwrap();
        capture.stop().await;
        drop(reference);
    })
    .await
    .unwrap();
}

/// ⑥ 参考**服务端**对错误口令的重放仍然 fail-closed（否定面）。
///
/// 证明「不防护重放」不等于「不校验口令」：换了口令的头部段不会被接受。
/// 判据是业务目标 accept 计数不增长（独立观测面），不把「读超时」当拒绝证据。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reference_server_rejects_wrong_password_replay() {
    timeout(TOTAL, async {
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        let server_port = support::free_port();
        let reference =
            support::launch(reference_server_config(server_port, PASSWORD), server_port).await;

        // 对照：正确口令必须走通（证明观测面有效）。
        let capture = CaptureServer::spawn(server_port, true).await;
        let socks = support::free_port();
        let client = support::launch(
            reference_client_config(socks, capture.port, PASSWORD),
            socks,
        )
        .await;
        reference_round_trip(socks, target.port).await;
        drop(client);
        let deadline = tokio::time::Instant::now() + CAPTURE_BOUND;
        let good_header = loop {
            let seen = capture.headers();
            if !seen.is_empty() {
                break seen[0].clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "捕获端未在预算内看到参考客户端写出的头部"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(target.accepted(), 1, "对照组必须抵达业务目标一次");

        // 否定面：把头部前 56 字节换成**另一个口令**的 SHA-224，其余字节不变。
        let mut bad_header = good_header.clone();
        bad_header[..56].copy_from_slice(hex_sha224(OTHER_PASSWORD).as_bytes());
        let mut stream = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        stream.write_all(&bad_header).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();

        // 参考端应主动结束连接（读到 EOF 或报错），不得回程任何字节。
        let mut buf = [0u8; 64];
        let outcome = timeout(WAIT, stream.read(&mut buf))
            .await
            .expect("参考端必须在观察上限内主动结束连接（超时不算拒绝证据）");
        assert!(
            matches!(outcome, Ok(0) | Err(_)),
            "错误口令不得收到任何应答字节：{outcome:?}"
        );

        assert_eq!(target.accepted(), 1, "错误口令不得抵达业务目标");

        capture.stop().await;
        drop(reference);
    })
    .await
    .unwrap();
}

/// ⑥ 对照：参考客户端 → **本仓**服务端，载荷往返逐字节一致。
///
/// 这条是「本仓与参考线级互通」的既有证据（见 `tests/xray_trojan_client.rs`），
/// 在本卡里作为对照重跑，证明重放矩阵的观测面（accept 计数、回程内容）有效。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reference_client_to_rust_server_control_round_trip() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        let server = RustServer::start(&identity, PASSWORD).await;

        let socks = support::free_port();
        let client = support::launch(
            reference_client_tls_config(socks, server.port, PASSWORD, &identity),
            socks,
        )
        .await;
        reference_round_trip(socks, target.port).await;
        drop(client);

        assert_eq!(
            target.accepted(),
            1,
            "参考客户端必须能通过本仓服务端抵达业务目标（对照组）"
        );

        server.stop().await;
    })
    .await
    .unwrap();
}

/// ⑤ 对照：本仓客户端 → **参考**服务端，载荷往返逐字节一致。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_client_to_reference_server_control_round_trip() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        let server_port = support::free_port();
        let reference = support::launch(
            reference_server_tls_config(server_port, PASSWORD, &identity),
            server_port,
        )
        .await;

        let mut stream = identity.connect(server_port).await;
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], target.port),
        };
        lengsuo_trojan::stream::send_request(
            &mut stream,
            &request,
            &Credential::new(PASSWORD),
            WAIT,
        )
        .await
        .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        let reply = read_exact(&mut stream, PAYLOAD.len(), WAIT).await;
        assert_eq!(reply, PAYLOAD, "本仓客户端 → 参考服务端必须逐字节一致");
        stream.shutdown().await.unwrap();

        assert_eq!(target.accepted(), 1, "必须抵达业务目标一次");
        drop(reference);
    })
    .await
    .unwrap();
}
