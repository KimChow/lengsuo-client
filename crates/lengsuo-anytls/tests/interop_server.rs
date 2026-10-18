//! AnyTLS 服务端方向真实互通（TLS 承载）：spawn anytls-go v0.0.13 的 anytls-client
//! （socks5 入口，出站**无条件** TLS），本端用 tokio-rustls 的 TlsAcceptor 包住
//! TcpStream 后交给 interop_server::session::serve 组装服务端，经隧道回程核对逐字节一致。
//!
//! 安全边界（必须如实记录）：官方参考客户端是示例客户端，`InsecureSkipVerify=true`，
//! **不校验**服务端证书（cmd/client/main.go）。本用例因此只证明
//! 「Rust rustls TLS 服务端 ↔ 官方客户端真实握手 + 认证 + 单流载荷往返」，
//! 不得据此声称产品侧 TLS 信任链/证书校验已验收。
//! 证书为本测试临时 openssl 自签（回环、1 天有效、用后即删），不是任何生产凭据。
//! 默认 #[ignore]，LENGSUO_ANYTLS 指向参考二进制目录。
#[path = "interop_server/harness.rs"]
mod harness;
#[path = "interop_server/pumps.rs"]
mod pumps;
#[path = "interop_server/report.rs"]
mod report;
#[path = "interop_server/session.rs"]
mod session;
#[path = "interop/support.rs"]
mod support;
#[path = "interop_server/tls.rs"]
mod tls;

use std::time::Duration;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 anytls-go 参考二进制（LENGSUO_ANYTLS）与 openssl 自签证书"]
async fn anytls_go_client_through_rust_tls_server_echo() {
    use report::Failure;
    use support::Process;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    let (_server_bin, client_bin, version) = support::fixture();
    println!("anytls-go version {version}");
    let password = support::PASSWORD;
    let wait = support::WAIT;

    // 临时测试 PKI（openssl 生成 CA+叶子；不可用时返回明确错误）。
    let dir = support::temp_dir("tls-server-dir");
    let pki = match tls::generate_test_pki(&dir) {
        Ok(pki) => pki,
        Err(Failure::Transport(reason)) => panic!("TLS 夹具准备失败：{reason}"),
        Err(other) => panic!("TLS 夹具准备失败：{other:?}"),
    };
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");

    // 本地 echo 目标。
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo 监听");
    let echo_addr = echo.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // 本端 AnyTLS 服务端：**TLS 接受**（明文一律握手失败，无回退）。
    let rust_server_port = support::free_port();
    let rust_listener = tokio::net::TcpListener::bind(("127.0.0.1", rust_server_port))
        .await
        .expect("rust server 监听");
    let (report_tx, report_rx) = oneshot::channel::<(report::Report, Result<(), Failure>)>();
    let mut report_tx = Some(report_tx);
    tokio::spawn(async move {
        while let Ok((socket, _)) = rust_listener.accept().await {
            let acceptor = acceptor.clone();
            let report_tx = report_tx.take();
            tokio::spawn(async move {
                let tls_stream = match tls::handshake(&acceptor, socket, wait).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        println!("TLS 握手被拒（预期只接受真实 TLS）：{err:?}");
                        return;
                    }
                };
                println!("TLS 握手完成，进入 anytls 会话");
                let outcome = session::serve(tls_stream, password.as_bytes(), wait).await;
                if let Some(sender) = report_tx {
                    let _ = sender.send(outcome);
                }
            });
        }
    });

    // 官方客户端：出站自带 TLS（v0.0.13 无 -tls 开关，也没有明文模式）。
    let socks_port = support::free_port();
    let client_log = dir.join("client.log");
    let mut client = Process::client(
        &client_bin,
        &format!("127.0.0.1:{socks_port}"),
        &format!("127.0.0.1:{rust_server_port}"),
        &client_log,
    );
    support::wait_listening(
        std::net::SocketAddr::from(([127, 0, 0, 1], socks_port)),
        "anytls-client socks",
    )
    .await;

    // 经 socks5 隧道 CONNECT 到 echo，收发核对。
    timeout(support::TOTAL, async {
        let mut socks = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .expect("连接 socks5");
        socks.write_all(&[0x05, 0x01, 0x00]).await.expect("握手写");
        let mut hello = [0u8; 2];
        socks.read_exact(&mut hello).await.expect("握手读");
        assert_eq!(hello, [0x05, 0x00], "socks5 方法协商");
        let mut connect = vec![0x05, 0x01, 0x00, 0x01];
        match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => connect.extend_from_slice(&v4.octets()),
            std::net::IpAddr::V6(_) => panic!("测试固定 IPv4"),
        }
        connect.extend_from_slice(&echo_addr.port().to_be_bytes());
        socks.write_all(&connect).await.expect("CONNECT 写");
        let mut reply = [0u8; 10];
        socks.read_exact(&mut reply).await.expect("CONNECT 回复");
        assert_eq!(reply[1], 0x00, "socks5 CONNECT 应成功");

        let payload = b"real-tls-server-direction-echo-check";
        socks.write_all(payload).await.expect("数据写");
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while got.len() < payload.len() {
            let n = socks.read(&mut buf).await.expect("数据读");
            assert!(n > 0, "连接提前关闭");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, payload, "真实 TLS 下端到端回程逐字节一致");
        // 显式关流，让本端看到 FIN 并回 FIN。
        let _ = socks.shutdown().await;
    })
    .await
    .expect("TLS server 方向互通总超时");

    // 官方客户端不做证书校验：这里只核对它建立了 TLS 连接并完成了 anytls 会话。
    let code = client.kill();
    println!("anytls-client exit code={code:?}");
    let log = support::read_log(&client_log);
    assert!(!log.contains(password), "客户端日志不得出现口令");

    // 会话统计：证书校验不在本用例范围（见文件头说明）。
    let (stats, outcome) = timeout(support::TOTAL, report_rx)
        .await
        .expect("等待会话结束超时")
        .expect("会话统计通道已交付");
    assert_eq!(stats.peer_version, Some(2), "对端 Settings 声明协议 v2");
    assert_eq!(stats.syn_acks_sent, 1, "应恰好一条 SYNACK");
    assert_eq!(stats.streams_opened.len(), 1, "应打开一条流");
    assert_eq!(stats.bytes_to_target, payload_len(), "转发给目标的字节数");
    assert_eq!(stats.bytes_to_client, payload_len(), "回程给客户端的字节数");
    assert_eq!(stats.alerts_sent, 0, "不应触发 Alert");
    match outcome {
        // 进程被 kill 后 TLS  abrupt 关闭属预期收尾路径。
        Ok(()) | Err(Failure::Transport(_)) => {}
        Err(other) => panic!("会话异常结束：{other:?}"),
    }
    support::remove_temp(&dir);
}

/// 回程核对用的载荷长度（与上面写出的常量保持一致）。
fn payload_len() -> usize {
    b"real-tls-server-direction-echo-check".len()
}

/// Rust↔Rust 单流往返载荷：出站字节计数与回程比对都用它（7 字节
/// 目标地址前缀被服务端解析消耗，不计入转发）。
const RUST_RUST_PAYLOAD: &[u8] = b"rust-to-rust-real-tls-roundtrip";

/// 明文连接必须被 TLS 接受器拒绝，且会话层一次都不进入（fail-closed，无明文回退）。
/// 不需要参考二进制，因此不 #[ignore]。
#[tokio::test]
async fn plaintext_connection_is_rejected_before_anytls_layer() {
    use harness::Observed;
    use tokio::io::AsyncWriteExt;

    let password = support::PASSWORD;
    let wait = support::WAIT;
    let dir = support::temp_dir("reject-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, mut observed) = harness::spawn_tls_server(password.as_bytes(), acceptor, wait);

    // 直接写 anytls 认证字节（明文），期望握手期就被拒。
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    // SHA256(口令) + BE16 长度 0，与 Credential::send 的明文形式一致。
    let digest = <sha2::Sha256 as sha2::Digest>::digest(password.as_bytes());
    socket.write_all(&digest).await.expect("写明文摘要");
    socket
        .write_all(&0u16.to_be_bytes())
        .await
        .expect("写零填充长度");
    let _ = socket.flush().await;

    let event = timeout(wait, observed.recv())
        .await
        .expect("等待握手判定超时")
        .expect("接受循环已回报");
    match event {
        Observed::HandshakeRejected(reason) => {
            println!("明文连接被拒：{reason}");
            assert!(
                reason.contains("TLS 握手"),
                "拒绝理由应为 TLS 握手失败，实际：{reason}"
            );
        }
        Observed::SessionEnded(stats, outcome) => {
            panic!("明文连接竟然进入了会话层：{stats:?} {outcome:?}");
        }
    }
    // 再多等一会儿，确认没有第二条会话（明文不会以其他方式被接受）。
    let extra = timeout(Duration::from_millis(200), observed.recv()).await;
    assert!(
        extra.is_err(),
        "明文连接后不应再出现任何会话事件：{extra:?}"
    );
    support::remove_temp(&dir);
}

/// 真实 TLS + 错误口令：认证必须失败且不进入会话层（无明文/无静默放行）。
#[tokio::test]
async fn tls_handshake_succeeds_but_wrong_password_is_not_authenticated() {
    use harness::Observed;
    use report::Failure;
    use tokio::io::AsyncWriteExt;

    let password = support::PASSWORD;
    let wait = support::WAIT;
    let dir = support::temp_dir("wrong-pw-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, mut observed) = harness::spawn_tls_server(password.as_bytes(), acceptor, wait);

    // 用会校验服务端的 Rust TLS 客户端连接（信任锚=该自签证书，名称=localhost）。
    let connector = tls::verifying_connector(&pki.ca).expect("TLS 客户端配置");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    let mut stream = tls::client_handshake(&connector, tls::TEST_SERVER_NAME, socket, wait)
        .await
        .expect("Rust 客户端 TLS 握手（含证书校验）");

    // 发送错误口令的认证字节：摘要应为 SHA256(其它口令)。
    let wrong = <sha2::Sha256 as sha2::Digest>::digest(b"definitely-not-the-password");
    stream.write_all(&wrong).await.expect("写错误摘要");
    stream
        .write_all(&0u16.to_be_bytes())
        .await
        .expect("写零填充长度");
    stream.flush().await.expect("flush");

    let event = timeout(support::TOTAL, observed.recv())
        .await
        .expect("等待会话结果超时")
        .expect("接受循环已回报");
    match event {
        Observed::HandshakeRejected(reason) => {
            panic!("TLS 握手本应成功（证书已校验），实际被拒：{reason}");
        }
        Observed::SessionEnded(stats, outcome) => {
            assert!(
                matches!(outcome, Some(Failure::Authentication)),
                "应为认证失败"
            );
            assert!(
                stats.streams_opened.is_empty()
                    && stats.syn_acks_sent == 0
                    && stats.bytes_to_target == 0,
                "认证失败不得有会话统计"
            );
        }
    }
    support::remove_temp(&dir);
}

/// 真实 TLS + 正确口令但未发 Settings 就送 SYN：会话层必须 fail-closed，
/// 发出 Alert 并以 `Failure::Protocol`（携带原因文本）结束。客户端实际读回
/// Alert 帧作为观测佐证——不是只靠超时推断被拒。
#[tokio::test]
async fn syn_before_settings_is_alerted_and_session_refused() {
    use harness::Observed;
    use lengsuo_anytls::{
        auth::Credential,
        frame::{Command, Frame},
    };
    use report::Failure;

    let password = support::PASSWORD;
    let wait = support::WAIT;
    let dir = support::temp_dir("no-settings-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, mut observed) = harness::spawn_tls_server(password.as_bytes(), acceptor, wait);

    let connector = tls::verifying_connector(&pki.ca).expect("TLS 客户端配置");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    let mut stream = tls::client_handshake(&connector, tls::TEST_SERVER_NAME, socket, wait)
        .await
        .expect("TLS 握手（证书校验通过）");

    timeout(support::TOTAL, async {
        Credential::new(password.as_bytes())
            .send(&mut stream, b"", wait)
            .await
            .expect("认证发送");
        // 故意跳过 Settings 帧，直接 SYN（流编号非零即可命中 started() 检查）。
        Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .write(&mut stream, wait)
        .await
        .expect("写 SYN");
        // 观测佐证：客户端必须真的收到 Alert 帧，而不是等超时。
        let frame = Frame::read(&mut stream, u16::MAX, wait)
            .await
            .expect("读服务端帧");
        assert_eq!(frame.command, Command::Alert, "应答帧应为 Alert");
        let text = String::from_utf8_lossy(&frame.data).into_owned();
        println!("收到 Alert：{text}");
        assert!(
            text.contains("settings"),
            "Alert 文本应说明缺 Settings，实际：{text}"
        );
    })
    .await
    .expect("总超时");

    let event = timeout(support::TOTAL, observed.recv())
        .await
        .expect("等待会话结果超时")
        .expect("接受循环已回报");
    let Observed::SessionEnded(stats, outcome) = event else {
        panic!("TLS 握手本应成功");
    };
    let reason = match outcome {
        Some(Failure::Protocol(text)) => text,
        other => panic!("应为协议失败，实际：{other:?}"),
    };
    assert!(
        reason.contains("Settings"),
        "失败原因应可读，实际：{reason}"
    );
    assert_eq!(stats.alerts_sent, 1, "恰好一条 Alert");
    assert!(
        stats.streams_opened.is_empty() && stats.syn_acks_sent == 0,
        "违规会话不得有流统计"
    );
    support::remove_temp(&dir);
}

/// Rust↔Rust：本仓 TLS 客户端（校验证书与名称）+ 本端服务端组装的全往返。
/// 这一路覆盖产品侧 TLS 安全语义（证书校验、名称匹配、错误名称拒绝），
/// 与官方客户端那一路互补：官方示例不校验证书，不能代替此处的验收。
#[tokio::test]
async fn rust_tls_client_with_cert_verification_roundtrips_single_stream() {
    use harness::Observed;
    use lengsuo_anytls::{
        auth::Credential,
        client_state::ClientState,
        frame::{Command, Frame},
    };
    use tokio::io::AsyncWriteExt;

    let password = support::PASSWORD;
    let wait = support::WAIT;
    let dir = support::temp_dir("rust-rust-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, mut observed) = harness::spawn_tls_server(password.as_bytes(), acceptor, wait);
    let echo_addr = harness::spawn_echo().await;

    let connector = tls::verifying_connector(&pki.ca).expect("TLS 客户端配置");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    let mut stream = tls::client_handshake(&connector, tls::TEST_SERVER_NAME, socket, wait)
        .await
        .expect("TLS 握手（证书校验通过）");

    timeout(support::TOTAL, async {
        Credential::new(password.as_bytes())
            .send(&mut stream, b"", wait)
            .await
            .expect("认证发送");
        let mut state = ClientState::new(8).expect("客户端状态机");
        state.mark_settings_sent().expect("Settings 一次性");
        // 本仓 ServerState::parse_settings 要求 v + 非空 client + 32 位十六进制
        // padding-md5，三者缺一都会 fail-closed 终止会话（interop.rs 对官方 Go 服务端
        // 只发 v=2 是另一条路径的行为，不适用于本端服务端）。
        Frame {
            command: Command::Settings,
            stream_id: 0,
            data: b"v=2\nclient=lengsuo-test\npadding-md5=00000000000000000000000000000000"
                .to_vec(),
        }
        .write(&mut stream, wait)
        .await
        .expect("写 Settings");

        // 先掺一条 Waste 填充帧：服务端应静默丢弃（计入 waste_frames）而不影响会话。
        Frame {
            command: Command::Waste,
            stream_id: 0,
            data: vec![7u8; 16],
        }
        .write(&mut stream, wait)
        .await
        .expect("写 Waste 填充帧");
        let sid = state.open_stream().expect("取流 ID");
        Frame {
            command: Command::Syn,
            stream_id: sid,
            data: Vec::new(),
        }
        .write(&mut stream, wait)
        .await
        .expect("写 SYN");
        let mut push_data = Vec::new();
        let std::net::IpAddr::V4(v4) = echo_addr.ip() else {
            panic!("测试固定 IPv4 回环");
        };
        push_data.push(1u8);
        push_data.extend_from_slice(&v4.octets());
        push_data.extend_from_slice(&echo_addr.port().to_be_bytes());
        let payload = RUST_RUST_PAYLOAD;
        push_data.extend_from_slice(payload);
        Frame {
            command: Command::Push,
            stream_id: sid,
            data: push_data,
        }
        .write(&mut stream, wait)
        .await
        .expect("写 PUSH（目标地址 + 载荷）");

        // 收 SYNACK 与回程 Push；ServerSettings/UpdatePadding/心跳忽略。
        let mut acked = false;
        let mut echoed: Vec<u8> = Vec::new();
        let mut negotiated = None;
        while echoed.len() < payload.len() {
            let frame = Frame::read(&mut stream, u16::MAX, wait)
                .await
                .expect("读服务端帧");
            match frame.command {
                Command::SynAck => {
                    assert_eq!(frame.stream_id, sid, "SYNACK 绑定同一条流");
                    assert!(frame.data.is_empty(), "成功 SYNACK 无载荷");
                    acked = true;
                }
                Command::Push => {
                    assert_eq!(frame.stream_id, sid, "PUSH 绑定同一条流");
                    echoed.extend_from_slice(&frame.data);
                }
                Command::ServerSettings => {
                    negotiated = Some(String::from_utf8_lossy(&frame.data).into_owned());
                }
                Command::Alert => panic!("服务端 Alert：会话被拒"),
                _ => {}
            }
            let _ = state.accept(&frame);
        }
        assert!(acked, "必须先有 SYNACK");
        assert_eq!(echoed, payload, "真实 TLS 下端到端回程逐字节一致");
        assert_eq!(
            negotiated.as_deref(),
            Some("v=2"),
            "本端应下发 ServerSettings"
        );
        assert_eq!(state.peer_version(), 2, "客户端状态机协商到 v2");

        state.close_stream(sid).expect("本地关流");
        Frame {
            command: Command::Fin,
            stream_id: sid,
            data: Vec::new(),
        }
        .write(&mut stream, wait)
        .await
        .expect("写 FIN");
        let _ = stream.shutdown().await;
    })
    .await
    .expect("Rust↔Rust TLS 往返总超时");

    let event = timeout(support::TOTAL, observed.recv())
        .await
        .expect("等待会话结果超时")
        .expect("接受循环已回报");
    let Observed::SessionEnded(stats, outcome) = event else {
        panic!("Rust 客户端 TLS 握手不应被拒");
    };
    assert_eq!(stats.peer_version, Some(2), "对端 Settings 声明 v2");
    assert_eq!(stats.syn_acks_sent, 1, "恰好一条 SYNACK");
    assert_eq!(
        stats.bytes_to_target,
        RUST_RUST_PAYLOAD.len(),
        "7 字节目标地址前缀被解析消耗，只有载荷转发给目标"
    );
    assert_eq!(
        stats.bytes_to_client,
        RUST_RUST_PAYLOAD.len(),
        "回程只有载荷"
    );
    assert_eq!(stats.alerts_sent, 0, "不应触发 Alert");
    assert_eq!(stats.waste_frames, 1, "掺入的 Waste 帧应被静默计为填充");
    assert_eq!(
        stats.streams_closed, stats.streams_opened,
        "FIN 后服务端应记录同一条流已关闭"
    );
    assert!(outcome.is_none(), "干净收尾：{outcome:?}");
    support::remove_temp(&dir);
}

/// 错误 SNI 名称必须被拒绝（证书校验有效，不因自签而放行名称不匹配）。
#[tokio::test]
async fn tls_client_rejects_wrong_server_name() {
    let wait = support::WAIT;
    let dir = support::temp_dir("wrong-name-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, _observed) = harness::spawn_tls_server(support::PASSWORD.as_bytes(), acceptor, wait);

    let connector = tls::verifying_connector(&pki.ca).expect("TLS 客户端配置");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    let outcome = tls::client_handshake(&connector, "evil.example", socket, wait).await;
    match outcome {
        Err(err) => println!("名称不匹配被拒：{err:?}"),
        Ok(_) => panic!("错误 SNI 名称竟然通过证书校验"),
    }
    support::remove_temp(&dir);
}
