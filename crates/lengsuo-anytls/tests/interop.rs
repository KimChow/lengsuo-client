//! AnyTLS 与 anytls-go v0.0.13 参考二进制的真实互通（客户端方向）。
//! 默认 `#[ignore]`，环境变量 `LENGSUO_ANYTLS` 指向参考二进制目录。
//! 只绑 127.0.0.1、假口令、随机端口、进程由 Drop 守卫回收。

mod interop {
    pub mod support;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要显式提供 anytls-go 参考二进制（LENGSUO_ANYTLS）"]
async fn rust_client_authenticates_and_proxies_via_anytls_go_server() {
    use interop::support::{self, Process};
    use lengsuo_anytls::auth::Credential;
    use lengsuo_anytls::client_state::ClientState;
    use lengsuo_anytls::frame::{Command, Frame};
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::timeout,
    };

    let (server_bin, _client_bin, version) = support::fixture();
    support::assert_fixture_clean(&support::temp_dir("probe"));
    println!("anytls-go version {version}");

    let wait = support::WAIT;
    let password = support::PASSWORD;

    // 回环 echo 目标服务。
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
                    match socket.read(&mut buf).await {
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

    // anytls-go server。
    let server_port = support::free_port();
    let dir = support::temp_dir("server");
    let server_log = dir.join("server.log");
    let mut server_proc = Process::server(
        &server_bin,
        &format!("127.0.0.1:{server_port}"),
        &server_log,
    );
    support::wait_listening(
        std::net::SocketAddr::from(([127, 0, 0, 1], server_port)),
        "anytls-server",
    )
    .await;

    // v0.0.13 server 无条件包 TLS（自签现生成证书）。本仓 lengsuo-tls 不提供
    // "跳过校验"配置（生产不提供），互通测试用 python ssl 做部署层桥：
    // 本仓原语（明文 anytls 帧）↔ python 桥（TLS）↔ anytls-go server。
    // TLS 属部署层边界，与协议文档一致；被验证的是认证与帧的线格式互通。
    let bridge_port = support::free_port();
    let bridge_script = support::BRIDGE_PY;
    let script_path =
        std::env::temp_dir().join(format!("lengsuo-anytls-bridge-{}.py", std::process::id()));
    std::fs::write(&script_path, bridge_script).expect("写桥脚本失败");
    let bridge = std::process::Command::new("python3")
        .arg(&script_path)
        .arg(bridge_port.to_string())
        .arg(server_port.to_string())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("启动 python TLS 桥");
    let bridge_guard = support::ProcessGuard(bridge);
    support::wait_listening(
        std::net::SocketAddr::from(([127, 0, 0, 1], bridge_port)),
        "python TLS 桥",
    )
    .await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", bridge_port))
        .await
        .expect("连接 python TLS 桥");
    let credential = Credential::new(password.as_bytes());
    timeout(support::TOTAL, async {
        // 认证：SHA256(password) + BE16 padding 长度 + padding。
        credential
            .send(&mut stream, b"", wait)
            .await
            .expect("认证发送");
        // 协议文档：认证成功服务器直接进入会话循环（失败才断连/fallback），
        // **没有回包**。本仓 auth.rs 的 verify 是对称自检用途，互通路径不用。
        // 认证是否成功由后续 SynAck/Alert 判定。

        // 会话层：Settings 先行 → SYN(1) → PUSH(目标地址 + 数据)。
        let mut state = ClientState::new(8).expect("客户端状态机");
        state.mark_settings_sent().expect("Settings 一次性");
        // StringMap 线格式（util/string_map.go）：k=v 行、换行分隔。
        // v=2 声明协议版本；padding-md5 缺省触发 server 下发 UpdatePaddingScheme，
        // 测试里对该帧忽略即可。
        let settings_data = b"v=2".to_vec();
        let settings = Frame {
            command: Command::Settings,
            stream_id: 0,
            data: settings_data,
        };
        stream
            .write_all(&settings.encode().expect("编码 Settings"))
            .await
            .expect("写 Settings");
        stream.flush().await.expect("flush settings");

        let stream_id = state.open_stream().expect("取流 ID");
        let syn = Frame {
            command: Command::Syn,
            stream_id,
            data: Vec::new(),
        };
        let mut target = Vec::new();
        // anytls 的 PUSH 载荷首段是目标地址（SOCKS 地址格式）。
        let addr = echo_addr;
        target.push(1); // ATYP_IPV4
        let octets = match addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            std::net::IpAddr::V6(_) => panic!("测试固定 IPv4 回环"),
        };
        target.extend_from_slice(&octets);
        target.extend_from_slice(&addr.port().to_be_bytes());
        let payload = b"ping-through-anytls";
        let mut push_data = target;
        push_data.extend_from_slice(payload);
        let push = Frame {
            command: Command::Push,
            stream_id,
            data: push_data,
        };
        // open_stream 已在状态机登记本地 SYN；accept 只解释服务器方向帧。
        stream
            .write_all(&syn.encode().expect("编码 SYN"))
            .await
            .expect("写 SYN");
        stream
            .write_all(&push.encode().expect("编码 PUSH"))
            .await
            .expect("写 PUSH");
        stream.flush().await.expect("flush push");

        // 读服务端方向：期待 SynAck(1) 与 Push(echo 数据)、心跳忽略。
        let mut acked = false;
        let mut echoed = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while echoed.is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "期限内未收到 SynAck+Push（SynAck={acked}）"
            );
            // 读一帧。
            let mut head = [0u8; 7];
            timeout(wait, stream.read_exact(&mut head))
                .await
                .expect("读帧头未超时")
                .expect("帧头完整");
            let command = Command::try_from(head[0])
                .unwrap_or_else(|_| panic!("未知命令字节 {:#x}", head[0]));
            let sid = u32::from_be_bytes(head[1..5].try_into().unwrap());
            let length = u16::from_be_bytes([head[5], head[6]]) as usize;
            let mut data = vec![0u8; length];
            if length > 0 {
                timeout(wait, stream.read_exact(&mut data))
                    .await
                    .expect("读帧体未超时")
                    .expect("帧体完整");
            }
            let frame = Frame {
                command,
                stream_id: sid,
                data,
            };
            match frame.command {
                Command::SynAck => {
                    assert_eq!(frame.stream_id, stream_id, "SynAck 绑定同一条流");
                    acked = true;
                    state.accept(&frame).expect("SynAck 进状态机");
                }
                Command::Push => {
                    assert_eq!(frame.stream_id, stream_id, "Push 绑定同一条流");
                    echoed = Some(frame.data.clone());
                    state.accept(&frame).expect("Push 进状态机");
                }
                Command::Alert => panic!("服务端 Alert：会话被拒"),
                other => {
                    let _ = state.accept(&frame);
                    println!("忽略帧 {other:?} sid={sid} len={}", frame.data.len());
                }
            }
        }
        assert!(acked, "必须先有 SynAck");
        assert_eq!(echoed.as_deref(), Some(&payload[..]), "echo 载荷逐字节一致");

        // FIN 收尾。
        state.close_stream(stream_id).expect("本地关流");
        let fin = Frame {
            command: Command::Fin,
            stream_id,
            data: Vec::new(),
        };
        stream
            .write_all(&fin.encode().expect("编码 FIN"))
            .await
            .expect("写 FIN");
    })
    .await
    .expect("互通总超时");

    drop(bridge_guard);
    let _ = std::fs::remove_file(&script_path);
    let code = server_proc.kill();
    println!("server exit code={code:?}");
    let log = support::read_log(&server_log);
    assert!(!log.contains("password"), "server 日志不得出现口令");
    support::remove_temp(&dir);
}
