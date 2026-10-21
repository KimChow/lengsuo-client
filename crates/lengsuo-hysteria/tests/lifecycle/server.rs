// 服务端与客户端：伪随机载荷 / `Server` 句柄 / 建连 / 轮询等待。
/// 确定性伪随机载荷（逐字节比对用）。
pub(crate) fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// 已绑定的本仓服务端。
pub(crate) struct Server {
    pub(crate) addr: SocketAddr,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) auth: String,
    /// 临时目录（证书落盘处）；保留引用以便调试时定位。
    #[allow(dead_code)]
    pub(crate) dir: PathBuf,
    pub(crate) inner: Arc<HysteriaServer>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        // accept_loop 会在 endpoint 关闭后退出；不强杀。
    }
}

impl Server {
    /// 服务端端点上的 QUIC 连接数（服务端**连接级**会话表计数）。
    pub(crate) fn open_connections(&self) -> usize {
        self.inner.endpoint().open_connections()
    }

    /// 服务端主动关闭整个端点（对齐参考 `Listener.Close()`：关 listener +
    /// 关 pktConn ⇒ 所有连接随之关闭）。
    pub(crate) fn close(&self) {
        self.inner.close();
    }
}

/// 起一个本仓服务端（UDP 端口由系统分配）+ 返回（地址、证书 DER 与保活的
/// accept 任务句柄）。`udp_idle_timeout_secs` 控制服务端 UDP 会话的空闲
/// 回收阈值（回收动作由 `quic::server::UDP_IDLE_CLEANUP_INTERVAL_SECS`
/// 的 ticker 驱动）。
pub(crate) async fn start_server(tag: &str, udp_idle_timeout_secs: u64) -> Server {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let key_der = key_der(&key);
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let auth = fake_auth(tag);
    let config = ServerConfig {
        listen_addr: listen,
        cert_chain_der: vec![der.clone()],
        key_der,
        auth: auth.clone(),
        brutal_down: 0,
        brutal_up: 0,
        udp_enabled: true,
        udp_idle_timeout_secs,
        congestion: String::new(),
    };
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let addr = server.local_addr().expect("读取监听地址");
    let srv = Arc::clone(&server);
    let task = tokio::spawn(async move { srv.accept_loop().await });
    Server {
        addr,
        cert_der: der,
        auth,
        dir,
        inner: server,
        task,
    }
}

pub(crate) fn client_config(server: &Server, auth: &str) -> ClientConfig {
    ClientConfig {
        server_addr: server.addr,
        server_name: SERVER_NAME.to_string(),
        auth: auth.to_string(),
        roots_der: vec![server.cert_der.clone()],
        brutal_down: 0,
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    }
}

pub(crate) async fn connect_with(
    server: &Server,
    auth: &str,
) -> Result<HysteriaClient, ConnectError> {
    HysteriaClient::connect(client_config(server, auth)).await
}

/// 轮询等待条件成立：每次尝试都有单次上限，总时长不超过 `deadline`。
///
/// 禁止「固定 sleep 后直接断言」：这里每次尝试都套 `timeout`，
/// 条件不成立就等到总截止时间。
pub(crate) async fn wait_until<F, Fut>(deadline: Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        match tokio::time::timeout(left.min(IO_TIMEOUT), cond()).await {
            Ok(true) => return true,
            Ok(false) => {}
            Err(_) => return false,
        }
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        tokio::time::sleep(left.min(POLL_INTERVAL)).await;
    }
}
