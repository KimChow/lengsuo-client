// 客户端半、UoT 报文编解码助手与「不得回落」探针。
//
// 本文件由 `tests/udp_over_tcp_server.rs` 用 `include!` 文本并入同一模块；`use` 与
// 常量都在入口文件，本文件只放夹具。

/// 单次读写等待上限。
const WAIT: Duration = Duration::from_secs(2);
/// 整个用例的上限。
const TOTAL: Duration = Duration::from_secs(10);
/// 测试口令（**假凭据**：只用回环地址与临时端口，不含任何真实口令）。
const PASSWORD: &[u8] = b"uot-server-test-password";

/// 客户端半：一个已认证、已发 Settings 的 anytls 连接。
struct Client {
    stream: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<Result<server::SessionStats, Error>>,
}

impl Client {
    /// 建连接并完成认证（客户端侧）。
    async fn start(password: &[u8]) -> Self {
        let (stream, server_side) = tokio::io::duplex(64 * 1024);
        let config = ServerConfig::new(password, WAIT);
        let task = tokio::spawn(server::serve(server_side, config));
        let mut harness = Self { stream, task };
        Credential::new(password)
            .send(&mut harness.stream, b"", WAIT)
            .await
            .expect("认证发送");
        harness
    }

    /// 发 Settings（`v` 决定服务端看到的协商版本）。
    async fn settings(&mut self, version: u8) {
        let md5 = PaddingScheme::default_scheme().md5().to_owned();
        let frame = Frame {
            command: Command::Settings,
            stream_id: 0,
            data: format!("v={version}\nclient=lengsuo-test\npadding-md5={md5}").into_bytes(),
        };
        frame
            .write(&mut self.stream, WAIT)
            .await
            .expect("写 Settings");
    }

    /// 写一帧。
    async fn send(&mut self, frame: Frame) {
        frame.write(&mut self.stream, WAIT).await.expect("写帧");
    }

    /// 写裸字节（构造截断帧等非法输入用）。
    async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("写裸字节");
        self.stream.flush().await.expect("刷裸字节");
    }

    /// 读一帧，跳过 Waste（参考 recvLoop 对 cmdWaste 静默丢弃）。
    async fn recv(&mut self) -> Frame {
        loop {
            let frame = Frame::read(&mut self.stream, u16::MAX, WAIT)
                .await
                .unwrap_or_else(|err| panic!("读帧失败：{err}"));
            if frame.command != Command::Waste {
                return frame;
            }
        }
    }

    /// 读到指定命令的帧（跳过中间的 ServerSettings 等）。
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

    /// 关闭写端（让服务端读到干净 EOF）。
    async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    /// 等服务端会话结束。
    async fn wait_session(&mut self) -> Result<server::SessionStats, Error> {
        timeout(TOTAL, &mut self.task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic")
    }
}

/// 开一条 UoT 流：SYN + 首帧 PUSH（魔法域首地址 + UoT 请求头）。
///
/// 字节布局对齐参考：首地址由 `inbound_tcp.go` 的 `ReadAddrPort` 消费，
/// 紧接着的字节由 `proxyOutboundUoT` 的 `uot.ReadRequest(conn)` 消费。
async fn open_uot(client: &mut Client, sid: u32, magic: &str, request: &UotRequest) {
    client
        .send(Frame {
            command: Command::Syn,
            stream_id: sid,
            data: Vec::new(),
        })
        .await;
    let mut payload = magic_address_bytes(magic);
    payload.extend_from_slice(&request.encode().expect("请求头可编码"));
    client
        .send(Frame {
            command: Command::Push,
            stream_id: sid,
            data: payload,
        })
        .await;
}

/// 发一批报文字节（一条 PUSH 帧）。
async fn push_bytes(client: &mut Client, sid: u32, bytes: &[u8]) {
    client
        .send(Frame {
            command: Command::Push,
            stream_id: sid,
            data: bytes.to_vec(),
        })
        .await;
}

/// 读回程：累积该流的 PUSH 载荷并按 UoT 报文切分，返回报文列表。
async fn collect_replies(
    client: &mut Client,
    sid: u32,
    association: &Association,
    want: usize,
) -> Vec<Datagram> {
    let mut buffer = Vec::new();
    let mut out = Vec::new();
    while out.len() < want {
        let frame = client.recv().await;
        if frame.command != Command::Push || frame.stream_id != sid {
            continue;
        }
        buffer.extend_from_slice(&frame.data);
        loop {
            match association.decode_datagram(&buffer) {
                Ok((datagram, used)) => {
                    buffer.drain(..used);
                    out.push(datagram);
                }
                Err(StreamError::Incomplete) => break,
                Err(err) => panic!("回程报文非法：{err}"),
            }
        }
    }
    out
}

/// 魔法域首地址（SOCKS5 域名 ATYP，端口 0 —— 参考 `uot.RequestDestination` 不带端口）。
fn magic_address_bytes(magic: &str) -> Vec<u8> {
    SocksAddr::Fqdn(magic.to_owned(), 0)
        .encode()
        .expect("魔法域可编码")
}

/// 手工拼一个 UoT 报文（用于注入非法地址族字节）。
fn raw_datagram(address_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = address_bytes.to_vec();
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// 合法 UoT 报文（非 connect 模式带地址）。
fn uot_datagram(address: &Address, payload: &[u8]) -> Vec<u8> {
    Datagram {
        address: Some(address.clone()),
        payload: payload.to_vec(),
    }
    .encode(false)
    .expect("报文可编码")
}

/// 回环 UDP echo：收到什么原样回什么。
async fn spawn_udp_echo(bind: &str) -> SocketAddr {
    let socket = UdpSocket::bind(bind).await.expect("udp echo 监听");
    let addr = socket.local_addr().expect("udp echo 地址");
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            let Ok((count, source)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            if socket.send_to(&buffer[..count], source).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// 探针：记录 TCP 连接数与 UDP 报文数。
///
/// 若服务端把 UoT 字节当成普通 PUSH 走 TCP 拨号，就会连上 `tcp` 那个监听；
/// 若服务端静默直连目标，就往往 `udp` 那个套接字发包。
#[derive(Clone, Default)]
struct Probe {
    tcp_conns: Arc<AtomicUsize>,
    udp_packets: Arc<AtomicUsize>,
}

/// 起探针：返回 `(探针, TCP 监听地址, UDP 套接字地址)`。
async fn spawn_probe() -> (Probe, SocketAddr, SocketAddr) {
    let probe = Probe::default();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("tcp 探针");
    let tcp_addr = listener.local_addr().expect("tcp 探针地址");
    let counter = Arc::clone(&probe.tcp_conns);
    tokio::spawn(async move {
        while let Ok((_socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp 探针");
    let udp_addr = socket.local_addr().expect("udp 探针地址");
    let counter = Arc::clone(&probe.udp_packets);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        while let Ok((_count, _source)) = socket.recv_from(&mut buffer).await {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    (probe, tcp_addr, udp_addr)
}

/// 断言探针没有被碰到：既没有 TCP 连接，也没有 UDP 报文。
async fn assert_no_fallback(probe: &Probe, what: &str) {
    // 给「若发生」的事件一点落地时间。
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        probe.tcp_conns.load(Ordering::SeqCst),
        0,
        "{what}：不得回落成 TCP 拨号"
    );
    assert_eq!(
        probe.udp_packets.load(Ordering::SeqCst),
        0,
        "{what}：不得静默直连"
    );
}
