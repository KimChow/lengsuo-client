//! 服务端会话（`lengsuo_anytls::server`）的 Rust↔Rust 端到端用例。
//!
//! 这些用例**不需要**参考二进制，默认执行：用 `tokio::io::duplex` 直接驱动
//! `server::serve` 的帧循环，逐帧断言协议时序（Settings → ServerSettings/SYNACK、
//! 心跳回包、目标地址解析、字节转发、FIN 收尾），并用一条经真实 TLS 的用例覆盖
//! `server::tls` 的接受器装配。参考二进制互通另见 `interop_server_full.rs`（`#[ignore]`）。
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    padding::PaddingScheme,
    server::{self, tls, ServerConfig},
    Error,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);
const TOTAL: Duration = Duration::from_secs(10);
const PASSWORD: &[u8] = b"unit-test-password";

/// 在 `duplex` 管道的服务端半上跑会话，客户端半交回调用方。
struct Harness {
    client: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<Result<server::SessionStats, Error>>,
}

impl Harness {
    /// 建连接并完成认证（客户端侧）。
    async fn start(password: &[u8]) -> Self {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = ServerConfig::new(password, WAIT);
        let task = tokio::spawn(server::serve(server_side, config));
        let mut harness = Self { client, task };
        Credential::new(password)
            .send(&mut harness.client, b"", WAIT)
            .await
            .expect("认证发送");
        harness
    }

    async fn send(&mut self, frame: Frame) {
        frame.write(&mut self.client, WAIT).await.expect("写帧");
    }

    async fn recv(&mut self) -> Frame {
        // 服务端会按 padding 方案插入 Waste 填充帧（参考 writeConn）；参考客户端
        // recvLoop 对 cmdWaste 一律静默丢弃，这里同样跳过，只看真实语义帧。
        loop {
            let frame = Frame::read(&mut self.client, u16::MAX, WAIT)
                .await
                .expect("读帧");
            if frame.command != Command::Waste {
                return frame;
            }
        }
    }

    /// 读一帧并断言命令；返回帧。
    async fn expect(&mut self, command: Command) -> Frame {
        let frame = self.recv().await;
        assert_eq!(
            frame.command,
            command,
            "帧命令不符：期望 {command:?}，实际 {:?}（sid={}, len={}）",
            frame.command,
            frame.stream_id,
            frame.data.len()
        );
        frame
    }

    /// 杀掉客户端半，让服务端读到 EOF，返回会话统计。
    async fn finish(self) -> Result<server::SessionStats, Error> {
        drop(self.client);
        timeout(TOTAL, self.task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic")
    }
}

/// 回环 echo 目标：连接后原样回写直到 EOF。
async fn spawn_echo() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo 监听");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 客户端 Settings 帧：本模块的 `ServerState` 要求 v + client + padding-md5。
fn settings(padding_md5: &str) -> Frame {
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: format!("v=2\nclient=lengsuo-test\npadding-md5={padding_md5}").into_bytes(),
    }
}

/// 目标地址 + 载荷拼成首帧 PUSH（参考：地址是 SOCKS5 格式）。
fn push_with_target(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        panic!("测试固定 IPv4 回环");
    };
    let mut data = vec![0x01];
    data.extend_from_slice(&v4.octets());
    data.extend_from_slice(&addr.port().to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// 完整正向路径：Settings → ServerSettings → SYN → PUSH（目标+载荷）→ SYNACK →
/// 回程 PUSH 逐字节一致 → FIN → 干净收尾，并核对统计。
#[tokio::test]
async fn echo_roundtrip_with_settings_synack_and_fin() {
    let mut harness = Harness::start(PASSWORD).await;
    let echo = spawn_echo().await;
    let md5 = PaddingScheme::default_scheme().md5().to_owned();

    harness.send(settings(&md5)).await;
    // 参考：客户端 v>=2 → 服务端回 ServerSettings("v=2")。
    let server_settings = harness.expect(Command::ServerSettings).await;
    assert_eq!(server_settings.data, b"v=2", "ServerSettings 载荷");
    assert_eq!(server_settings.stream_id, 0, "控制帧 stream id 为 0");

    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    // 一帧内既含目标地址又含载荷：服务端应解析地址后剩余字节直接转发。
    let payload = b"rust-rust-single-frame-echo";
    harness
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(echo, payload),
        })
        .await;

    let ack = harness.expect(Command::SynAck).await;
    assert_eq!(ack.stream_id, 1, "SYNACK 绑定同一流");
    assert!(ack.data.is_empty(), "成功 SYNACK 无载荷");
    let echoed = harness.expect(Command::Push).await;
    assert_eq!(echoed.stream_id, 1, "回程 PUSH 绑定同一流");
    assert_eq!(echoed.data, payload, "回程逐字节一致");

    harness
        .send(Frame {
            command: Command::Fin,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    // 客户端 FIN 后服务端不再补发 FIN（参考 closeLocally 语义）：关闭客户端即收尾。
    let stats = harness.finish().await.expect("干净收尾");
    assert_eq!(stats.peer_version, Some(2), "协商到 v2");
    assert_eq!(stats.streams_opened, 1, "打开一条流");
    assert_eq!(stats.streams_closed, 1, "关闭一条流");
    assert_eq!(
        stats.syn_acks_sent, 0,
        "SYNACK 计数由上层维护，这里不重复计"
    );
    assert_eq!(stats.bytes_to_target, payload.len(), "转发字节数");
    assert_eq!(stats.bytes_to_client, payload.len(), "回程字节数");
}

/// 目标地址跨帧：首帧 PUSH 只放半截地址，服务端必须缓存等下一帧，不得拨号或报错。
#[tokio::test]
async fn target_address_split_across_frames_is_buffered() {
    let mut harness = Harness::start(PASSWORD).await;
    let echo = spawn_echo().await;
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    harness.send(settings(&md5)).await;
    let _ = harness.expect(Command::ServerSettings).await;
    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;

    let full = push_with_target(echo, b"split-address");
    let (head, tail) = full.split_at(4); // 半截地址（IPv4 地址共 7 字节）
    harness
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: head.to_vec(),
        })
        .await;
    // 此刻不应有 SYNACK（地址未完整）；给一点时间确认——超时或只读到 Waste 都算通过。
    let early = timeout(Duration::from_millis(150), harness.recv()).await;
    assert!(early.is_err(), "地址未完整时不应有语义帧（尤其 SYNACK）");

    harness
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: tail.to_vec(),
        })
        .await;
    let ack = harness.expect(Command::SynAck).await;
    assert_eq!(ack.stream_id, 1);
    let echoed = harness.expect(Command::Push).await;
    assert_eq!(echoed.data, b"split-address", "跨帧地址后载荷仍需回程");
    let stats = harness.finish().await.expect("干净收尾");
    assert_eq!(stats.bytes_to_target, b"split-address".len());
}

/// 心跳：任意关联值原样回传 HeartResponse（参考 cmdHeartRequest 分支）。
#[tokio::test]
async fn heartbeat_request_is_answered_with_same_id() {
    let mut harness = Harness::start(PASSWORD).await;
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    harness.send(settings(&md5)).await;
    let _ = harness.expect(Command::ServerSettings).await;

    harness
        .send(Frame {
            command: Command::HeartRequest,
            stream_id: 37,
            data: Vec::new(),
        })
        .await;
    let response = harness.expect(Command::HeartResponse).await;
    assert_eq!(response.stream_id, 37, "关联值原样回传");
    assert!(response.data.is_empty(), "心跳无载荷");
    let stats = harness.finish().await.expect("干净收尾");
    assert_eq!(stats.heartbeats, 1);
}

/// Settings 之前发 SYN：必须回 Alert 文本并以协议失败结束（fail-closed），
/// 且不建立任何流。
#[tokio::test]
async fn syn_before_settings_is_alerted() {
    let mut harness = Harness::start(PASSWORD).await;
    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    let alert = harness.expect(Command::Alert).await;
    let text = String::from_utf8_lossy(&alert.data);
    assert!(
        text.contains("settings"),
        "Alert 文本应说明缺 Settings，实际：{text}"
    );
    let outcome = harness.finish().await;
    assert!(outcome.is_err(), "违规会话应以失败结束：{outcome:?}");
}

/// 错误口令：认证失败，会话在进入帧循环前就结束，不产生任何统计。
#[tokio::test]
async fn wrong_password_fails_before_frame_loop() {
    let mut harness = Harness::start(b"correct-password").await;
    // Harness 已用 b"correct-password" 认证；这里改用错误口令重连。
    let _ = &mut harness;
    drop(harness);

    let (client, server_side) = tokio::io::duplex(1024);
    let config = ServerConfig::new(PASSWORD, WAIT);
    let task = tokio::spawn(server::serve(server_side, config));
    let mut client = client;
    Credential::new(b"wrong-password")
        .send(&mut client, b"", WAIT)
        .await
        .expect("发送错误口令");
    drop(client);
    let outcome = timeout(TOTAL, task)
        .await
        .expect("超时")
        .expect("任务 panic");
    assert!(
        matches!(outcome, Err(Error::Authentication)),
        "应为认证失败，实际：{outcome:?}"
    );
}

/// 空口令边界：口令为空时 SHA256("") 仍是合法摘要；只是对端摘要不同即拒绝。
#[tokio::test]
async fn empty_configured_password_rejects_non_empty() {
    let (client, server_side) = tokio::io::duplex(1024);
    let config = ServerConfig::new(b"", WAIT);
    let task = tokio::spawn(server::serve(server_side, config));
    let mut client = client;
    Credential::new(b"non-empty")
        .send(&mut client, b"", WAIT)
        .await
        .expect("发送");
    drop(client);
    let outcome = timeout(TOTAL, task)
        .await
        .expect("超时")
        .expect("任务 panic");
    assert!(matches!(outcome, Err(Error::Authentication)));
}

/// 活跃流容量：达到 `max_streams` 后再开流，服务端必须 fail-closed 结束会话
/// （状态机 `InvalidStream("活跃流已达上限")`）。
#[tokio::test]
async fn exceeding_max_streams_ends_session() {
    let (client, server_side) = tokio::io::duplex(64 * 1024);
    let mut config = ServerConfig::new(PASSWORD, WAIT);
    config.max_streams = 2;
    let task = tokio::spawn(server::serve(server_side, config));
    let mut client = client;
    Credential::new(PASSWORD)
        .send(&mut client, b"", WAIT)
        .await
        .expect("认证");
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    settings(&md5)
        .write(&mut client, WAIT)
        .await
        .expect("Settings");
    for sid in 1..=2 {
        Frame {
            command: Command::Syn,
            stream_id: sid,
            data: Vec::new(),
        }
        .write(&mut client, WAIT)
        .await
        .expect("SYN");
    }
    // 第三条超出容量：会话应以失败结束。
    Frame {
        command: Command::Syn,
        stream_id: 3,
        data: Vec::new(),
    }
    .write(&mut client, WAIT)
    .await
    .expect("SYN");
    drop(client);
    let outcome = timeout(TOTAL, task)
        .await
        .expect("超时")
        .expect("任务 panic");
    assert!(outcome.is_err(), "超容量应结束会话，实际：{outcome:?}");
}

/// 真 TLS 装配：`server::tls::acceptor` + `server::serve` 在真实握手后跑通 echo。
/// 证书由测试用 openssl 现签（无产品凭据）；若环境无 openssl 则跳过。
#[tokio::test]
async fn tls_acceptor_serves_echo_after_handshake() {
    let Some(pki) = test_pki() else {
        eprintln!("跳过：环境无 openssl，无法生成测试 PKI");
        return;
    };
    let acceptor = tls::acceptor(pki.chain.clone(), pki.key_der()).expect("TLS 接受器");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("监听");
    let port = listener.local_addr().expect("地址").port();
    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            if let Ok(stream) = tls::handshake(&acceptor, socket, WAIT).await {
                let _ = server::serve(stream, ServerConfig::new(PASSWORD, WAIT)).await;
            }
        }
    });
    let echo = spawn_echo().await;

    // 客户端：用测试 CA 校验服务端，再做认证 + 单流 echo。
    let connector = tls_client(&pki.ca).expect("TLS 客户端");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接");
    let mut stream = timeout(
        WAIT,
        connector.connect(
            tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").expect("名称"),
            socket,
        ),
    )
    .await
    .expect("握手超时")
    .expect("TLS 握手（含证书校验）");

    Credential::new(PASSWORD)
        .send(&mut stream, b"", WAIT)
        .await
        .expect("认证");
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    settings(&md5)
        .write(&mut stream, WAIT)
        .await
        .expect("Settings");
    let _ = next_semantic(&mut stream).await;
    Frame {
        command: Command::Syn,
        stream_id: 1,
        data: Vec::new(),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("SYN");
    let payload = b"tls-server-echo-check";
    Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(echo, payload),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("PUSH");
    let ack = next_semantic(&mut stream).await;
    assert_eq!(ack.command, Command::SynAck, "真实 TLS 下也要回 SYNACK");
    let echoed = next_semantic(&mut stream).await;
    assert_eq!(echoed.command, Command::Push);
    assert_eq!(echoed.data, payload, "真实 TLS 下回程逐字节一致");
}

/// 读下一帧并跳过 Waste 填充（与 `Harness::recv` 同语义，供裸流用例复用）。
async fn next_semantic<S: AsyncReadExt + Unpin>(stream: &mut S) -> Frame {
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT).await.expect("读帧");
        if frame.command != Command::Waste {
            return frame;
        }
    }
}

/// 测试 PKI（openssl 现签两级链）。
struct TestPki {
    chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    key: Vec<u8>,
    ca: Vec<u8>,
}

impl TestPki {
    fn key_der(&self) -> tokio_rustls::rustls::pki_types::PrivateKeyDer<'static> {
        tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(self.key.clone()),
        )
    }
}

/// 在临时目录用 openssl 生成 CA + 叶子（SAN=localhost/127.0.0.1）；无 openssl 返回 None。
fn test_pki() -> Option<TestPki> {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("lengsuo-anytls-unit-pki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let p = |name: &str| dir.join(name).to_str().unwrap_or_default().to_owned();
    let ok = |args: &[&str]| {
        Command::new("openssl")
            .args(args)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    };
    let ca_key = p("ca-key.pem");
    let ca_pem = p("ca.pem");
    let ca_der = p("ca.der");
    let csr = p("leaf.csr");
    let leaf_key = p("leaf-key.pem");
    let leaf_der = p("leaf.der");
    let leaf_key_der = p("leaf-key.der");
    let ext = p("leaf.ext");

    let ready = ok(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &ca_key,
        "-out",
        &ca_pem,
        "-days",
        "1",
        "-subj",
        "/CN=lengsuo-unit-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]) && ok(&["x509", "-in", &ca_pem, "-outform", "DER", "-out", &ca_der])
        && ok(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &leaf_key,
            "-out",
            &csr,
            "-subj",
            "/CN=localhost",
        ]);
    if !ready {
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let ext_body = "subjectAltName=DNS:localhost,IP:127.0.0.1\n\
                    basicConstraints=critical,CA:FALSE\n\
                    keyUsage=critical,digitalSignature,keyEncipherment\n\
                    extendedKeyUsage=serverAuth\n";
    std::fs::write(&ext, ext_body).ok()?;
    let signed = ok(&[
        "x509",
        "-req",
        "-in",
        &csr,
        "-CA",
        &ca_pem,
        "-CAkey",
        &ca_key,
        "-set_serial",
        "01",
        "-days",
        "1",
        "-extfile",
        &ext,
        "-outform",
        "DER",
        "-out",
        &leaf_der,
    ]) && ok(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        &leaf_key,
        "-outform",
        "DER",
        "-out",
        &leaf_key_der,
    ]);
    if !signed {
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let pki = TestPki {
        chain: vec![
            tokio_rustls::rustls::pki_types::CertificateDer::from(std::fs::read(&leaf_der).ok()?),
            tokio_rustls::rustls::pki_types::CertificateDer::from(std::fs::read(&ca_der).ok()?),
        ],
        key: std::fs::read(&leaf_key_der).ok()?,
        ca: std::fs::read(&ca_der).ok()?,
    };
    let _ = std::fs::remove_dir_all(&dir);
    Some(pki)
}

/// 会校验服务端的 TLS 客户端（唯一信任锚 = 测试 CA）。
fn tls_client(ca_der: &[u8]) -> Result<tokio_rustls::TlsConnector, Box<dyn std::error::Error>> {
    let mut store = tokio_rustls::rustls::RootCertStore::empty();
    store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(
        ca_der.to_vec(),
    ))?;
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(store)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}
