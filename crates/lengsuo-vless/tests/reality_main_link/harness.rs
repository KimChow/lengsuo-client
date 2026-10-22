// ① 夹具：本仓 REALITY 服务端身份、记录层桥接与 ClientHello 走查。
/// 服务端身份（假值）。
struct Server {
    private_key: [u8; 32],
    config: RealityServerConfig,
}

impl Server {
    fn new() -> Self {
        let private_key = [0x5a; 32];
        Self {
            private_key,
            config: RealityServerConfig {
                private_key,
                short_ids: vec![SHORT_ID],
                server_names: vec![SERVER_NAME.to_owned()],
                max_time_diff: Duration::from_secs(60),
            },
        }
    }

    /// 客户端配置：公钥按参考格式（base64 raw-url 文本）给出。
    fn client_settings(&self) -> RealitySettings {
        RealitySettings {
            server_name: SERVER_NAME.to_owned(),
            password: String::new(),
            public_key: base64_url(&x25519_base(&self.private_key)),
            short_id: SHORT_ID_HEX.to_owned(),
            fingerprint: "chrome".to_owned(),
        }
    }
}

/// 把记录层读写器接到一个 `AsyncRead + AsyncWrite`：读任务解封记录摊平成字节、
/// 写任务把字节切片成应用数据记录。服务端侧用它与主链路函数对接。
fn bridge(
    mut reader: RecordReader,
    mut writer: RecordWriter,
    transport: TcpStream,
) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (transport_read, transport_write) = tokio::io::split(transport);
    let (app, inner) = tokio::io::duplex(16384);
    let (mut inner_read, mut inner_write) = tokio::io::split(inner);
    let mut transport_read = transport_read;
    let mut transport_write = transport_write;
    let task = tokio::spawn(async move {
        let pump_reads = async {
            loop {
                match reader.next_record(&mut transport_read).await {
                    Ok(Some(Inbound::Encrypted(framed))) if framed.first() == Some(&23) => {
                        if inner_write.write_all(&framed[1..]).await.is_err() {
                            return;
                        }
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => return,
                }
            }
        };
        let pump_writes = async {
            let mut buffer = [0u8; 16384];
            loop {
                let Ok(read) = inner_read.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if writer
                    .write(
                        &mut transport_write,
                        &Outbound::EncryptedApplication(buffer[..read].to_vec()),
                    )
                    .await
                    .is_err()
                {
                    return;
                }
            }
        };
        tokio::join!(pump_reads, pump_writes);
    });
    (app, task)
}

/// ClientHello 里服务端认证要用的两项（布局同 `reality/server.rs` 的走查）。
struct HelloView {
    server_name: Option<String>,
    key_share: Option<[u8; 32]>,
    random: [u8; 32],
}

/// 最小 ClientHello 扩展走查：type(1)+len(3)+version(2)+random(32)+
/// session_id(1+n)+suites(2+n)+compression(1+n)+extensions(2+n)。
fn parse_hello(raw: &[u8]) -> HelloView {
    let mut random = [0u8; 32];
    random.copy_from_slice(&raw[6..38]);
    let mut at = 6 + 32;
    at += 1 + usize::from(raw[at]);
    at += 2 + usize::from(u16::from_be_bytes([raw[at], raw[at + 1]]));
    at += 1 + usize::from(raw[at]);
    let end = raw.len();
    let mut server_name = None;
    let mut key_share = None;
    if at + 2 <= end {
        at += 2;
        while at + 4 <= end {
            let kind = u16::from_be_bytes([raw[at], raw[at + 1]]);
            let len = usize::from(u16::from_be_bytes([raw[at + 2], raw[at + 3]]));
            let data = &raw[at + 4..(at + 4 + len).min(end)];
            match kind {
                0x0000 if data.len() >= 5 => {
                    let name_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
                    server_name = std::str::from_utf8(&data[5..5 + name_len])
                        .ok()
                        .map(str::to_owned);
                }
                0x0033 if data.len() >= 6 + 32 => {
                    let mut share = [0u8; 32];
                    share.copy_from_slice(&data[6..6 + 32]);
                    key_share = Some(share);
                }
                _ => {}
            }
            at += 4 + len;
        }
    }
    HelloView {
        server_name,
        key_share,
        random,
    }
}

/// 本仓 REALITY 服务端：认证 → TLS 1.3 → 主链路读 VLESS 头 → 载荷交给 echo，
/// 把 echo 的结果按主链路写回响应头 + 载荷。
///
/// 返回服务端读到的载荷。
async fn serve_once(
    mut stream: TcpStream,
    server: &Server,
    now_unix: u32,
) -> Result<Vec<u8>, String> {
    let mut reader = RecordReader::new();
    let mut collector = HandshakeCollector::new();
    let raw = loop {
        match reader
            .next_record(&mut stream)
            .await
            .map_err(|e| e.to_string())?
        {
            Some(Inbound::PlainHandshake(payload)) => {
                collector.push(&payload);
                if let Some(message) = collector.take().map_err(|e| e.to_string())? {
                    break message;
                }
            }
            Some(_) => continue,
            None => return Err("ClientHello 前 EOF".to_owned()),
        }
    };
    accept_hello(&server.config, &raw, now_unix).map_err(|e| format!("REALITY 认证被拒: {e}"))?;
    let view = parse_hello(&raw);
    if view.server_name.as_deref() != Some(SERVER_NAME) {
        return Err("SNI 不匹配".to_owned());
    }
    let peer = view.key_share.ok_or("缺 X25519 key_share")?;
    let shared = x25519(&server.private_key, &peer).map_err(|e| e.to_string())?;
    let auth_key = lengsuo_vless::reality::auth::derive_auth_key(&shared, &view.random)
        .map_err(|e| e.to_string())?;
    let mut rng = SeededRng::from_label("server");
    let mut state = ServerHandshake::new(auth_key, [0x31; 32], [0x32; 32], &mut rng)
        .map_err(|e| format!("服务端状态机: {e}"))?;
    state
        .process_client_hello(&raw, &peer)
        .map_err(|e| format!("处理 ClientHello: {e}"))?;
    let outcome = server_handshake(&mut state, &mut stream, &view.random)
        .await
        .map_err(|e| format!("服务端握手: {e}"))?;
    let mut reader = RecordReader::new();
    reader.enable_cipher(outcome.reader);
    let mut writer = RecordWriter::new();
    writer.enable_cipher(outcome.writer);
    let (mut app, _bridge) = bridge(reader, writer, stream);

    // —— 以下走的是 VLESS 主链路函数 ——
    let request = stream::receive_request(&mut app, &KEY, WAIT)
        .await
        .map_err(|e| format!("主链路读 VLESS 头: {e}"))?;
    if request.command != Command::Tcp {
        return Err("命令不是 TCP".to_owned());
    }
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    while received.len() < PAYLOAD.len() {
        let read = app.read(&mut buffer).await.map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("载荷读到一半 EOF".to_owned());
        }
        received.extend_from_slice(&buffer[..read]);
    }
    if received != PAYLOAD {
        return Err("服务端读到的载荷不一致".to_owned());
    }
    // 「目标」建立成功后才写成功头（主链路契约）。
    stream::send_response(&mut app, WAIT)
        .await
        .map_err(|e| format!("主链路写响应头: {e}"))?;
    app.write_all(&received).await.map_err(|e| e.to_string())?;
    app.flush().await.map_err(|e| e.to_string())?;
    Ok(received)
}

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// 起一个只服务一次连接的本仓 REALITY 服务端。
async fn start_server(server: Arc<Server>, port: u16) -> tokio::task::JoinHandle<Vec<u8>> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        match serve_once(socket, &server, now_unix()).await {
            Ok(received) => received,
            Err(error) => panic!("服务端失败: {error}"),
        }
    })
}
