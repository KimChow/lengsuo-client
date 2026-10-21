// 本仓 VMess 入站夹具：每连接一个线程；解码失败即 drop（关闭）连接，
// 处理体包在 catch_unwind 里，panic 记入标志。
// 本文件由 `tests/xray_multitier_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 本仓 VMess 入站夹具：每连接一个线程；解码失败即 drop（关闭）连接，
/// 处理体包在 catch_unwind 里，panic 记入标志。
struct VmessInbound {
    addr: SocketAddr,
    panicked: Arc<AtomicBool>,
}

/// 启动入站；`suite_override` 为 `Some` 时**强制**用该套件（忽略请求头里的
/// 档位），用于「档位错配必须失败」的负例。
fn start_vmess_inbound(
    users: Vec<[u8; 16]>,
    echo: Option<SocketAddr>,
    suite_override: Option<BodySuite>,
) -> VmessInbound {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("入站绑定 127.0.0.1:0");
    let addr = listener.local_addr().expect("入站地址");
    let sessions: Arc<Mutex<Vec<[u8; 48]>>> = Arc::new(Mutex::new(Vec::new()));
    let panicked = Arc::new(AtomicBool::new(false));
    let panic_flag = panicked.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let users = users.clone();
            let sessions = sessions.clone();
            let panic_flag = panic_flag.clone();
            let echo = echo;
            std::thread::spawn(move || {
                if std::panic::catch_unwind(move || {
                    handle_connection(stream, &users, &sessions, echo, suite_override)
                })
                .is_err()
                {
                    panic_flag.store(true, Ordering::SeqCst);
                }
            });
        }
    });
    VmessInbound { addr, panicked }
}

/// 本仓入站的单连接处理。
fn handle_connection(
    mut stream: TcpStream,
    users: &[[u8; 16]],
    sessions: &Mutex<Vec<[u8; 48]>>,
    echo: Option<SocketAddr>,
    suite_override: Option<BodySuite>,
) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let decoded = {
        let mut seen = sessions.lock().expect("会话表锁");
        let mut take = |user: &[u8; 16], key: &[u8; 16], iv: &[u8; 16]| {
            let mut entry = [0u8; 48];
            entry[..16].copy_from_slice(user);
            entry[16..32].copy_from_slice(key);
            entry[32..].copy_from_slice(iv);
            if seen.contains(&entry) {
                false
            } else {
                seen.push(entry);
                true
            }
        };
        decode_request_header(users, &mut stream, now_unix(), &mut take)
    };
    let decoded = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            eprintln!("[vmess-in] 拒绝：{error}");
            return; // drop 即关闭：认证失败不回任何字节
        }
    };

    if echo.is_none() {
        eprintln!("[vmess-in] 未配置后端，关闭");
        return;
    }
    // 档位：请求头里的 security 低 4 位（参考 `parseSecurityType`）。
    let suite = match suite_override {
        Some(forced) => forced,
        None => match decoded.security {
            HeaderSecurity::None => BodySuite::None,
            HeaderSecurity::Aes128Gcm => BodySuite::Aes128Gcm,
            HeaderSecurity::ChaCha20Poly1305 => BodySuite::ChaCha20Poly1305,
            HeaderSecurity::Zero => {
                eprintln!("[vmess-in] ZERO 档在体阶段拒绝");
                return;
            }
        },
    };
    let Some(TargetAddr::V4(ip, port)) = decoded.target.clone() else {
        eprintln!("[vmess-in] 夹具只接受 IPv4 目标");
        return;
    };
    let mut echo_sock = match TcpStream::connect(SocketAddrV4::new(ip.into(), port)) {
        Ok(sock) => sock,
        Err(error) => {
            eprintln!("[vmess-in] 连接后端失败：{error}");
            return;
        }
    };

    // 响应头先于任何体数据（对齐参考 `transferResponse` 顺序）。
    let mut header_wire = Vec::new();
    encode_response_header(
        decoded.response_header,
        &decoded.request_body_key,
        &decoded.request_body_iv,
        &ResponseHeader::new(),
        &mut header_wire,
    )
    .expect("响应头封装");
    if stream.write_all(&header_wire).is_err() {
        return;
    }

    let req_key = decoded.request_body_key;
    let req_iv = decoded.request_body_iv;
    let (resp_key, resp_iv) = response_key_iv(&req_key, &req_iv);
    let option = decoded.option;

    // 上行：客户端分帧 → 明文 → 后端。
    let mut up_reader = match stream.try_clone() {
        Ok(sock) => sock,
        Err(_) => return,
    };
    let mut echo_writer = match echo_sock.try_clone() {
        Ok(sock) => sock,
        Err(_) => return,
    };
    let up = std::thread::spawn(move || {
        if suite == BodySuite::None {
            // 参考的 NONE 分支：chunk-stream（明文载荷、无 padding）。
            let mut frame = ChunkStreamFrame::with_iv(option, &req_iv);
            loop {
                match frame.read_sync(&mut up_reader) {
                    Ok(Some(plain)) => {
                        if echo_writer.write_all(&plain).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = echo_writer.shutdown(Shutdown::Write);
                        break;
                    }
                    Err(error) => {
                        eprintln!("[vmess-in] 上行解帧失败：{error}");
                        break;
                    }
                }
            }
        } else {
            let mut frame =
                match BodyFrame::for_request(suite, &req_key, &req_iv, &req_key, &req_iv, option) {
                    Ok(frame) => frame,
                    Err(error) => {
                        eprintln!("[vmess-in] 构造数据段帧失败：{error}");
                        return;
                    }
                };
            loop {
                match frame.read_sync(&mut up_reader) {
                    Ok(Some(plain)) => {
                        if echo_writer.write_all(&plain).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = echo_writer.shutdown(Shutdown::Write);
                        break;
                    }
                    Err(error) => {
                        eprintln!("[vmess-in] 上行解帧失败：{error}");
                        break;
                    }
                }
            }
        }
    });

    // 下行：后端明文 → 分帧 → 客户端。
    if suite == BodySuite::None {
        let mut resp_frame = ChunkStreamFrame::with_iv(option, &resp_iv);
        let mut buffer = vec![0u8; 8192];
        loop {
            match echo_sock.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let mut frame = Vec::with_capacity(n + 2);
                    if resp_frame.seal(&mut frame, &buffer[..n]).is_err() {
                        return;
                    }
                    if stream.write_all(&frame).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = up.join();
        let mut eof_frame = Vec::new();
        if resp_frame.seal_eof(&mut eof_frame).is_ok() {
            let _ = stream.write_all(&eof_frame);
        }
        return;
    }

    let mut resp_frame =
        match BodyFrame::for_request(suite, &resp_key, &resp_iv, &req_key, &req_iv, option) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("[vmess-in] 构造响应帧失败：{error}");
                return;
            }
        };
    let mut buffer = vec![0u8; 8192];
    loop {
        match echo_sock.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let mut frame = Vec::with_capacity(n + 80);
                if resp_frame.seal(&mut frame, &buffer[..n]).is_err() {
                    return;
                }
                if stream.write_all(&frame).is_err() {
                    return;
                }
            }
            Err(_) => break,
        }
    }
    let _ = up.join();
    let mut eof_frame = Vec::new();
    if resp_frame.seal(&mut eof_frame, b"").is_ok() {
        let _ = stream.write_all(&eof_frame);
    }
}
