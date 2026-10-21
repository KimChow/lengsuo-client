// 协议动作：最小 SOCKS5 客户端、走法枚举、SS2022 会话建立、载荷切分写出、
// 响应固定头读取、有界回程读、逐档阶梯。
//
// 本文件由 `tests/vps_reassembly.rs` 用 `include!` 文本并入同一模块；
// 共享常量与环境探测在 `tests/vps_reassembly.rs` 入口文件，`use` 全部写在入口文件。
/// 最小 SOCKS5 客户端（无认证）：用于把 SS2022 线上字节送进 anytls-client。
async fn socks5_connect(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 协商失败",
        ));
    }
    let mut request = vec![0x05, 0x01, 0x00];
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 CONNECT 被拒",
        ));
    }
    // 丢弃 BND.ADDR/BND.PORT。
    match reply[3] {
        0x01 => {
            let mut bound = [0u8; 4 + 2];
            stream.read_exact(&mut bound).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bound = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut bound).await?;
        }
        0x04 => {
            let mut bound = [0u8; 16 + 2];
            stream.read_exact(&mut bound).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 地址类型未知",
            ))
        }
    }
    Ok(stream)
}

/// 公网链路的两条走法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// 本仓原语 → 本机 Xray SS2022 入站 → socks → anytls → 公网 → VPS 回显。
    LocalXray,
    /// 本仓原语 → socks → anytls → 公网 → VPS 参考 Xray SS2022 入站 → VPS 回显。
    VpsReference,
}

impl Transport {
    fn label(self) -> &'static str {
        match self {
            Self::LocalXray => "本机 Xray SS2022 入站 → anytls 隧道 → 公网 → VPS 回显",
            Self::VpsReference => "本机 socks → anytls 隧道 → 公网 → VPS 参考 Xray SS2022 入站",
        }
    }
}

/// 一条已建立的 SS2022 会话（本仓客户端方向）。
struct Session {
    stream: TcpStream,
    writer: Writer,
    reader: Reader,
    replay: SessionReplay,
    /// 本端请求 salt：响应固定头必须原样回传它。
    request_salt: Vec<u8>,
    /// 请求头写出的 Unix 秒：响应固定头的时间戳按此做 ±30 秒窗口校验。
    now: u64,
    /// 响应方向开场已收到的首批载荷（参考服务端把首批载荷并入响应固定头）。
    first_payload: Vec<u8>,
}

/// 按指定走法建立 SS2022 会话（只写请求头，**不**读响应）。
///
/// 参考 `shadowaead_2022/service.go` 的 `serverConn.writeResponse` 只有在上游
/// 真的产生数据时才写出响应固定头；所以请求侧必须先把载荷送出去，响应头才会在
/// 上游回数据时到达。开局与载荷写出解耦，见 [`Session::read_response_header`]。
async fn open_session(transport: Transport, target: &ss_core::target::TargetAddr) -> Session {
    let key = Key::new(Method::Aes128, &psk_bytes()).expect("口令长度必须匹配套件");
    let stream = match transport {
        Transport::LocalXray => TcpStream::connect(LOCAL_SS2022_INBOUND)
            .await
            .expect("连接本机 Xray SS2022 入站"),
        Transport::VpsReference => {
            let relay = vps_relay().expect("需要 SS2022_VPS_RELAY 指向 VPS 参考 Xray SS2022 入站");
            let (host, port) = relay.rsplit_once(':').expect("中继地址必须是 host:port");
            let port: u16 = port.parse().expect("中继端口必须是 u16");
            socks5_connect(LOCAL_SOCKS5, host, port)
                .await
                .expect("经 anytls socks 建立到 VPS 参考 Xray SS2022 入站的隧道")
        }
    };
    let mut stream = stream;
    let mut writer = Writer::random(&key, Direction::Request).expect("请求 writer");
    let request_salt = writer.salt().to_vec();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时钟")
        .as_secs();
    writer
        .write_request_header(&mut stream, target, b"", now, HEADER_PADDING)
        .await
        .expect("请求头");
    let reader = Reader::new(
        key,
        Direction::Response,
        Duration::from_secs(READ_TIMEOUT_SECS),
    )
    .expect("响应 reader");
    let replay = SessionReplay::new(Duration::from_secs(60)).expect("重放记忆池");
    Session {
        stream,
        writer,
        reader,
        replay,
        request_salt,
        now,
        first_payload: Vec::new(),
    }
}

/// 发出载荷：按 SIP022 `MaxPacketSize` 上限切分写出，首批留空。
///
/// 载荷 = `长度前缀(u32be) | 载荷体`。长度前缀是 VPS 侧回显服务的应用层协议：
/// 它据此知道何时收齐整段并回送，避免依赖「客户端半关闭」这种与服务端实现
/// 绑定的触发方式。
async fn send_payload(session: &mut Session, payload: &[u8]) {
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    let mut written = 0usize;
    while written < framed.len() {
        let take = framed.len().min(CHUNK_MAX).min(framed.len() - written);
        session
            .writer
            .write_payload(&mut session.stream, &framed[written..written + take])
            .await
            .expect("写出载荷 chunk");
        written += take;
    }
}

impl Session {
    /// 读取并认证响应固定头（参考服务端的响应固定头兼第一个 length chunk）。
    async fn read_response_header(&mut self) {
        let opened = self
            .reader
            .open(
                &mut self.stream,
                &mut self.replay,
                clock_at(self.now, Instant::now()),
                Some(self.request_salt.as_slice()),
            )
            .await
            .expect("公网响应头应通过认证");
        self.first_payload = opened.payload;
    }
}

/// 读回**恰好** `expected` 字节：有界读取，绝不 `read_to_end`。
///
/// 返回 (字节流, 收到的 chunk 数)。chunk 数用于证明大档位确实跨多个 chunk
/// 重组，而不是只读到首片。
async fn read_exact_bytes(session: &mut Session, expected: usize) -> (Vec<u8>, usize) {
    let mut received = Vec::with_capacity(expected);
    let mut chunks = 0usize;
    if !session.first_payload.is_empty() {
        received.extend_from_slice(&session.first_payload);
        chunks += 1;
    }
    while received.len() < expected {
        match session.reader.read_payload(&mut session.stream).await {
            Ok(Some(chunk)) => {
                received.extend_from_slice(&chunk);
                chunks += 1;
            }
            Ok(None) => break,
            Err(error) => panic!(
                "读取回程载荷失败（已收 {} 字节）：{error:?}",
                received.len()
            ),
        }
    }
    (received, chunks)
}

/// 逐档跑完长度阶梯并逐字节断言。
async fn run_ladder(transport: Transport) {
    let target = parse_target(&echo_target());
    for size in SIZE_LADDER {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut session = open_session(transport, &target).await;
        // 先发载荷：参考 SS2022 服务端只有在上游产生数据后才写响应固定头。
        send_payload(&mut session, &payload).await;
        session.read_response_header().await;
        let (received, chunks) = read_exact_bytes(&mut session, size).await;
        assert_eq!(
            received.len(),
            size,
            "长度 {size} 档：回程字节数应与发出载荷相同"
        );
        assert_eq!(
            received, payload,
            "长度 {size} 档：回程重组后的字节流必须与发出载荷逐字节相等"
        );
        // 参考写侧按 `MaxPacketSize = 65535` 切分 ⇒ 超过该长度的档位回程必然跨
        // 多个 SS2022 chunk（进而跨多个 TCP 分片）。chunk 数 ≥ 2 即证明断言验的是
        // **重组**而不是「读首片就当全部」。
        if size > CHUNK_MAX {
            assert!(
                chunks >= 2,
                "长度 {size} 档：回程应跨多个 SS2022 chunk，实际只有 {chunks} 个"
            );
        }
        println!(
            "长度 {size} 档：回程重组 {size} 字节（{chunks} 个 SS2022 chunk），逐字节相等 ✓（{}）",
            transport.label()
        );
        // 关闭连接，让 VPS 侧回显服务的读侧收尾。
        drop(session);
    }
}
