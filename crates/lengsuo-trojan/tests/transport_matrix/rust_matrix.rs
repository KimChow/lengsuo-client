//! 外层传输矩阵的 **Rust↔Rust 回环**部分（非忽略）。
//!
//! 目的：证明同一组 trojan 语义在三种外层（`tcp` / `ws` / `httpupgrade`）上
//! 判定**一致** —— 正常往返逐字节一致、错密码与截断都 fail-closed、半关闭后
//! 回程仍完整。这不是与参考的互通（对端是本仓自己的服务端），真实互通见
//! `transport_matrix/xray_matrix.rs`（`#[ignore]`，必须 `--ignored` 实跑）。
//!
//! 逐外层的**唯一**差异在两处，本文件把它们显式写出来：
//!
//! 1. 建流：TLS 之后套 `ws` / `httpupgrade` 升级，或直接用裸 TLS 流；
//! 2. 关写端：WS 走 `Close` 帧，其余走底层 FIN。
//!
//! 判定纪律：拒绝类用例**不以“我方读操作超时”**为证据。要求
//! （a）本仓服务端的处理任务返回**可判别的错误变体**（不是 panic、不是挂起），
//! （b）业务目标的 accept 计数**不增长**。

use std::time::Duration;

use lengsuo_trojan::transport::{httpupgrade, server as transport_server, ws};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::harness::{
    bounded_shutdown, client_action, header_bytes, tcp_request, Action, Identity, Outcome, Outer,
    Target, Verdict, BAD_PASSWORD, CLOSE_BOUND, HANDSHAKE, PASSWORD, PATH, PAYLOAD, REPLY,
    REPLY_BULK_LEN, TOTAL, TRUNCATION_CUTS, WAIT,
};

/// 本仓服务端：TLS 接入 → （按外层）升级 → trojan `server::process`。
///
/// 每条连接的处理结果被记录下来，作为拒绝类用例的“可判别错误变体”证据。
struct RustServer {
    port: u16,
    outcomes: std::sync::Arc<std::sync::Mutex<Vec<Verdict>>>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl RustServer {
    async fn start(identity: &Identity, outer: Outer) -> Self {
        let mut validator = lengsuo_trojan::server::Validator::new();
        validator.add("matrix@example.com", PASSWORD).unwrap();
        let server = lengsuo_trojan::server::Server::new(
            validator,
            lengsuo_trojan::server::Timeouts::new(HANDSHAKE, WAIT).unwrap(),
        );
        let tls = identity.server();
        let config = transport_server::Config::new(PATH, "");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let outcomes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = outcomes.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let tls = tls.clone();
                let server = server.clone();
                let config = config.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    let outcome = run_connection(socket, tls, server, config, outer).await;
                    sink.lock().unwrap().push(outcome);
                });
            }
        });
        Self {
            port,
            outcomes,
            accept_task: Some(accept_task),
        }
    }

    /// 已完成的每连接处理判定（按完成顺序）。
    fn outcomes(&self) -> Vec<Verdict> {
        self.outcomes.lock().unwrap().clone()
    }

    async fn stop(mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = timeout(CLOSE_BOUND, task).await;
        }
    }
}

/// 单条连接的处理：按外层建流，然后交给 trojan `process`。
///
/// 升级失败（路径/头不匹配）发生在 trojan 协议层**之前**，归类为
/// `Verdict::UpgradeFailed`；其余按 `server::Error` 的变体归一。
async fn run_connection(
    socket: TcpStream,
    tls: lengsuo_tls::TlsServer,
    server: lengsuo_trojan::server::Server,
    config: transport_server::Config,
    outer: Outer,
) -> Verdict {
    let stream = match tls.accept(socket).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = error;
            return Verdict::Other;
        }
    };
    match outer {
        Outer::Tcp => match server.process(stream).await {
            Ok(()) => Verdict::Completed,
            Err(error) => Verdict::of(&error),
        },
        Outer::Ws => match transport_server::accept_ws(stream, &config, WAIT).await {
            Ok(conn) => match server.process(conn).await {
                Ok(()) => Verdict::Completed,
                Err(error) => Verdict::of(&error),
            },
            Err(_) => Verdict::UpgradeFailed,
        },
        Outer::HttpUpgrade => {
            match transport_server::accept_httpupgrade(stream, &config, WAIT).await {
                Ok(conn) => match server.process(conn).await {
                    Ok(()) => Verdict::Completed,
                    Err(error) => Verdict::of(&error),
                },
                Err(_) => Verdict::UpgradeFailed,
            }
        }
    }
}

/// 客户端在给定外层上建流（TLS → 升级）并跑一次动作。
///
/// 三个分支的流类型不同，但都喂给同一个泛型 `client_action`。
async fn run_client(
    identity: &Identity,
    port: u16,
    outer: Outer,
    action: Action,
    target_port: u16,
) -> Outcome {
    let endpoint = ([127, 0, 0, 1], port).into();
    match outer {
        Outer::Tcp => {
            let mut stream = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::Ws => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = ws::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("WS 升级失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::HttpUpgrade => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = httpupgrade::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("HTTPUpgrade 升级失败");
            client_action(&mut stream, action, target_port).await
        }
    }
}

/// 正常往返：回程逐字节一致，且业务目标 accept 计数恰为 1。
///
/// 这一条同时是其它用例的**对照组**：证明观测面确实能抓到“抵达业务”。
#[tokio::test]
async fn rust_matrix_normal_roundtrip_on_every_outer() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        for outer in Outer::ALL {
            let target = Target::bind(REPLY.to_vec()).await;
            let server = RustServer::start(&identity, outer).await;
            let outcome =
                run_client(&identity, server.port, outer, Action::Normal, target.port()).await;
            assert_eq!(
                outcome.reply,
                REPLY,
                "{} 档回程必须与请求逐字节一致",
                outer.name()
            );
            assert_eq!(
                target.accepted(),
                1,
                "{} 档必须恰好抵达业务目标一次",
                outer.name()
            );
            server.stop().await;
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 错密码：三个外层都必须 fail-closed —— 业务目标 accept 计数不增长，
/// 本仓服务端返回**认证失败**变体。
#[tokio::test]
async fn rust_matrix_wrong_password_is_rejected_on_every_outer() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        for outer in Outer::ALL {
            let target = Target::bind(REPLY.to_vec()).await;
            let server = RustServer::start(&identity, outer).await;
            let outcome = run_client(
                &identity,
                server.port,
                outer,
                Action::WrongPassword,
                target.port(),
            )
            .await;
            assert!(
                !outcome.unexpected_data,
                "{} 档错密码不得收到任何数据",
                outer.name()
            );
            // 拒绝必须是**有界**的：要么对端主动结束，要么我方读到错误。
            // “观察上限内什么都没发生”不算拒绝证据。
            assert!(
                outcome.rejected_cleanly(),
                "{} 档错密码必须得到有界拒绝（读到结束或错误），得到 {outcome:?}",
                outer.name()
            );
            // 沉降后再核对观测面，排除迟到的拨号。
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                target.accepted(),
                0,
                "{} 档错密码不得抵达业务目标",
                outer.name()
            );
            let outcomes = server.outcomes();
            assert_eq!(outcomes.len(), 1, "{} 档应恰好处理一条连接", outer.name());
            assert_eq!(
                outcomes[0],
                Verdict::Authentication,
                "{} 档错密码必须是认证失败变体",
                outer.name()
            );
            server.stop().await;
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 截断请求头：两个截断点都必须得到**有界**拒绝。
///
/// - 判定线之前（`< 58` 字节）：参考 `proxy/trojan/server.go:176` 的
///   `firstLen < 58 || first.Byte(56) != '\r'` ⇒ `NotTrojanProtocol`。
/// - 跨过判定线、头部不全：服务端按握手截止（`HANDSHAKE`）给出 `Timeout`。
///
/// 两种情况下业务目标 accept 计数都必须**不增长**。
#[tokio::test]
async fn rust_matrix_truncated_header_is_rejected_on_every_outer() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        for outer in Outer::ALL {
            for (cut, label) in TRUNCATION_CUTS {
                let target = Target::bind(REPLY.to_vec()).await;
                let server = RustServer::start(&identity, outer).await;
                let outcome = run_client(
                    &identity,
                    server.port,
                    outer,
                    Action::Truncated { cut },
                    target.port(),
                )
                .await;
                assert!(
                    !outcome.unexpected_data,
                    "{} 档截断({label})不得收到任何数据",
                    outer.name()
                );
                assert!(
                    outcome.rejected_cleanly(),
                    "{} 档截断({label})必须得到有界拒绝（读到结束或错误），得到 {outcome:?}",
                    outer.name()
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
                assert_eq!(
                    target.accepted(),
                    0,
                    "{} 档截断({label})不得抵达业务目标",
                    outer.name()
                );
                let outcomes = server.outcomes();
                assert_eq!(
                    outcomes.len(),
                    1,
                    "{} 档截断({label})应恰好处理一条连接",
                    outer.name()
                );
                // 变体可判别：判定线之前是协议错误，跨线之后是握手超时。
                let expected = if cut < 58 {
                    Verdict::NotTrojanProtocol
                } else {
                    Verdict::Timeout
                };
                assert_eq!(
                    outcomes[0],
                    expected,
                    "{} 档截断({label})期望 {expected:?}",
                    outer.name()
                );
                server.stop().await;
                target.stop().await;
            }
        }
    })
    .await
    .unwrap();
}

/// 半关闭：关写端之后必须仍能收完整个大回程（64 KiB，跨多个 TLS 记录）。
///
/// 逐外层的关闭语义不同（WS 发 `Close` 帧，其余发 FIN），但**协议层**结论
/// 必须一致：半关闭不得切断回程。
#[tokio::test]
async fn rust_matrix_half_close_still_delivers_bulk_reply_on_every_outer() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let bulk = vec![0xA5u8; REPLY_BULK_LEN];
        for outer in Outer::ALL {
            let target = Target::bind(bulk.clone()).await;
            let server = RustServer::start(&identity, outer).await;
            let outcome = run_client(
                &identity,
                server.port,
                outer,
                Action::HalfClose,
                target.port(),
            )
            .await;
            assert_eq!(
                outcome.reply.len(),
                REPLY_BULK_LEN,
                "{} 档半关闭后必须收满 {} 字节回程",
                outer.name(),
                REPLY_BULK_LEN
            );
            assert!(
                outcome.reply.iter().all(|byte| *byte == 0xA5),
                "{} 档半关闭后的回程内容必须逐字节一致",
                outer.name()
            );
            assert_eq!(
                target.accepted(),
                1,
                "{} 档半关闭必须恰好抵达业务目标一次",
                outer.name()
            );
            server.stop().await;
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 外层升级失败必须 fail-closed：错误路径下服务端**不得**处理 trojan，
/// 业务目标也不得被触达。
///
/// 这一条覆盖“外层”本身的拒绝面（参考 `transport/internet/websocket/hub.go:47`
/// 的路径校验与 `httpupgrade/hub.go:58` 的路径校验：路径不匹配 ⇒ 拒绝）。
#[tokio::test]
async fn rust_matrix_wrong_upgrade_path_is_refused_on_every_outer() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        for outer in [Outer::Ws, Outer::HttpUpgrade] {
            let target = Target::bind(REPLY.to_vec()).await;
            let server = RustServer::start(&identity, outer).await;
            let endpoint = ([127, 0, 0, 1], server.port).into();
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            // 故意用错误路径发起升级。
            let rejected = match outer {
                Outer::Ws => ws::Client::new("/wrong-path", "localhost", "localhost")
                    .upgrade(tls, WAIT)
                    .await
                    .is_err(),
                Outer::HttpUpgrade => {
                    httpupgrade::Client::new("/wrong-path", "localhost", "localhost")
                        .upgrade(tls, WAIT)
                        .await
                        .is_err()
                }
                Outer::Tcp => unreachable!(),
            };
            assert!(rejected, "{} 档错误路径必须被拒", outer.name());
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                target.accepted(),
                0,
                "{} 档错误路径不得抵达业务目标",
                outer.name()
            );
            assert_eq!(
                server.outcomes(),
                vec![Verdict::UpgradeFailed],
                "{} 档错误路径必须在**外层升级**处被拒，不得进入 trojan 处理",
                outer.name()
            );
            server.stop().await;
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 截断用例的辅助断言：请求头长度与截断点必须落在头部之内。
///
/// 这条不是独立结论，而是把 `TRUNCATION_CUTS` 的取值与实际线上头部长度
/// 绑定起来，防止以后改了编码器却忘了同步截断点。
#[tokio::test]
async fn rust_matrix_truncation_points_are_inside_the_header() {
    let header = header_bytes(1234, PASSWORD);
    // 56 哈希 + 2 CRLF + 1 命令 + 地址(1+4+2) + 2 CRLF = 68。
    assert_eq!(header.len(), 68, "trojan 头部长度必须是 68 字节");
    for (cut, label) in TRUNCATION_CUTS {
        assert!(cut < header.len(), "{label} 截断点必须落在头部之内");
    }
    // 判定线：不足 58 字节 ⇒ 参考的首块协议判定线之前。
    assert!(TRUNCATION_CUTS[0].0 < 58);
    assert!(TRUNCATION_CUTS[1].0 >= 58);
    // 错误密码的头部与正确密码等长（只有摘要不同），截断点语义一致。
    assert_eq!(header_bytes(1234, BAD_PASSWORD).len(), header.len());
    // 目标地址端口不同不改变头部长度。
    assert_eq!(tcp_request(4321).header_len(), header.len());
}

/// 半关闭的实现细节自检：裸 TCP 与 HTTPUpgrade 走 FIN，WS 走 `Close` 帧。
///
/// 判据是**线上字节**：WS 的关写端必须发出 `Close` 帧（opcode 0x8，FIN 置位），
/// 而裸流必须直接关写半、不发任何额外字节。
#[tokio::test]
async fn rust_matrix_close_semantics_differ_per_outer() {
    timeout(TOTAL, async {
        // WS：关写端应产生一个 `Close` 帧。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8(request).unwrap();
            let key = text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                        Some(value.trim().to_owned())
                    } else {
                        None
                    }
                })
                .expect("必须带 Sec-WebSocket-Key");
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                lengsuo_trojan::transport::sha1::accept_key(&key)
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            // 读一个帧：关写端后应收到 `Close` 帧。
            let mut head = [0u8; 2];
            socket.read_exact(&mut head).await.unwrap();
            head
        });
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut conn = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(tcp, WAIT)
            .await
            .unwrap();
        bounded_shutdown(&mut conn).await.unwrap();
        let head = timeout(WAIT, server).await.unwrap().unwrap();
        assert_eq!(head[0] & 0x0f, 0x8, "WS 关写端必须发 Close 帧（opcode 0x8）");
        assert_eq!(head[0] & 0x80, 0x80, "Close 帧必须置 FIN");

        // HTTPUpgrade：关写端只关写半，不发任何额外字节。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
            // 关写端后应读到 EOF，且没有任何字节。
            let mut rest = Vec::new();
            socket.read_to_end(&mut rest).await.unwrap();
            rest
        });
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut conn = httpupgrade::Client::new(PATH, "localhost", "localhost")
            .upgrade(tcp, WAIT)
            .await
            .unwrap();
        bounded_shutdown(&mut conn).await.unwrap();
        let rest = timeout(WAIT, server).await.unwrap().unwrap();
        assert!(
            rest.is_empty(),
            "HTTPUpgrade 关写端不得产生任何线上字节，得到 {rest:?}"
        );
    })
    .await
    .unwrap();
}

/// 让 `PAYLOAD` / `CLOSE_BOUND` 在本文件被显式引用（判据常量集中在 harness）。
#[test]
fn harness_constants_are_referenced() {
    assert!(!PAYLOAD.is_empty());
    assert!(CLOSE_BOUND > Duration::ZERO);
}
