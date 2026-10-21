// 本仓 VMess 入站夹具：每连接一个线程；解码失败即 drop（关闭）连接，
// 处理体包在 catch_unwind 里，panic 记入标志。
// 本文件由 `tests/xray_vmess_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 本仓 VMess 入站夹具：每连接一个线程；解码失败即 drop（关闭）连接，
/// 处理体包在 catch_unwind 里，panic 记入标志。
struct VmessInbound {
    addr: SocketAddr,
    panicked: Arc<AtomicBool>,
}

fn start_vmess_inbound(users: Vec<[u8; 16]>, echo: Option<SocketAddr>) -> VmessInbound {
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
                    handle_connection(stream, &users, &sessions, echo)
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

fn handle_connection(
    mut stream: TcpStream,
    users: &[[u8; 16]],
    sessions: &Mutex<Vec<[u8; 48]>>,
    echo: Option<SocketAddr>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

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
    if decoded.security != HeaderSecurity::Aes128Gcm {
        eprintln!("[vmess-in] 夹具仅支持 AES-128-GCM 数据面");
        return;
    }
    let must = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING;
    if decoded.option & must != must || decoded.option & OPT_AUTHENTICATED_LENGTH != 0 {
        eprintln!("[vmess-in] 不支持的 option 组合：0x{:02x}", decoded.option);
        return;
    }
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

    // 响应头先于任何体数据（对齐 transferResponse 顺序）。
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
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &req_key, &req_iv);
        let mut mask = DataSizeParser::new(&req_iv);
        loop {
            let mut size_wire = [0u8; 2];
            if up_reader.read_exact(&mut size_wire).is_err() {
                break;
            }
            let (declared, padding) = read_padded_size(&mut mask, size_wire);
            let mut body = vec![0u8; declared as usize];
            if up_reader.read_exact(&mut body).is_err() {
                break;
            }
            match open_padded_chunk(&mut cipher, &body, padding) {
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
    });

    // 下行：后端明文 → 分帧 → 客户端。
    let mut resp_cipher = DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
    let mut resp_mask = DataSizeParser::new(&resp_iv);
    let mut buffer = vec![0u8; 8192 - 2 - 16 - 64]; // 参考单帧净载荷上限
    loop {
        match echo_sock.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let mut frame = Vec::with_capacity(n + 80);
                if seal_padded_chunk(&mut resp_cipher, &mut resp_mask, &mut frame, &buffer[..n])
                    .is_err()
                {
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
    if seal_padded_chunk(&mut resp_cipher, &mut resp_mask, &mut eof_frame, &[]).is_ok() {
        let _ = stream.write_all(&eof_frame);
    }
}
