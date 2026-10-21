// 测试身份（自签证书）与回环业务目标（accept 计数是唯一的“抵达业务”观测面）。
//
// 本文件由 `tests/transport_matrix/harness.rs` 以 `include!` 拼入该模块。

/// 测试身份：运行时自签证书（叶子 `localhost`），客户端与服务端共用。
pub struct Identity {
    cert: rcgen::CertifiedKey,
    client: TlsClient,
}

impl Identity {
    /// 生成自签身份；证书只在回环测试里使用。
    pub fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        Self { cert, client }
    }

    /// 已配置信任锚的 TLS 客户端。
    pub fn client(&self) -> &TlsClient {
        &self.client
    }

    /// TLS 服务端接入器（供本仓服务端侧使用）。
    pub fn server(&self) -> TlsServer {
        TlsServer::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }

    /// 证书 PEM（供参考服务端配置使用）。
    pub fn cert_pem(&self) -> String {
        self.cert.cert.pem()
    }

    /// 私钥 PEM（供参考服务端配置使用）。
    pub fn key_pem(&self) -> String {
        self.cert.key_pair.serialize_pem()
    }
}

/// 回环业务目标的**回写时机**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyWhen {
    /// 读满请求载荷后**立刻**回写。
    Immediately,
    /// 读满请求载荷后**等对端关写端**（读到 EOF）才回写。
    ///
    /// 这让“半关闭”成为**可判定**的事实：回程只可能在客户端关写端之后才
    /// 产生。若外层在半关闭时拆掉会话（参考的 WS 外层就是这样），回程必然
    /// 收不到——这正是要区分的两种语义。
    AfterEof,
}

/// 回环业务目标：读满请求载荷后按 `ReplyWhen` 回写固定回程并关写端。
///
/// accept 计数是“是否抵达业务”的**唯一**观测面；每条连接的处理任务登记在
/// `workers` 里，回收时逐个 await，不留悬挂任务。
pub struct Target {
    port: u16,
    accepted: Arc<AtomicUsize>,
    accept_task: Option<JoinHandle<()>>,
    workers: Arc<Mutex<JoinSet<()>>>,
}

impl Target {
    /// 绑定一个回环业务目标；`reply` 是回写内容，读满载荷即回写。
    pub async fn bind(reply: Vec<u8>) -> Self {
        Self::bind_with(reply, ReplyWhen::Immediately).await
    }

    /// 绑定一个回环业务目标，显式指定回写时机。
    pub async fn bind_with(reply: Vec<u8>, when: ReplyWhen) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let workers = Arc::new(Mutex::new(JoinSet::new()));
        let counter = accepted.clone();
        let body = Arc::new(reply);
        let pool = workers.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();
                let worker = serve(socket, body, when);
                pool.lock().unwrap().spawn(worker);
            }
        });
        Self {
            port,
            accepted,
            accept_task: Some(accept_task),
            workers,
        }
    }

    /// 业务目标端口。
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 已 accept 的连接数（“抵达业务”的计数）。
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// 显式回收：断 accept 循环并 await 每连接任务。
    pub async fn stop(mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = timeout(CLOSE_BOUND, task).await;
        }
        let mut batch = std::mem::take(&mut *self.workers.lock().unwrap());
        loop {
            match timeout(CLOSE_BOUND, batch.join_next()).await {
                Ok(None) => break,
                Ok(Some(_)) => {}
                Err(_) => panic!("业务目标任务未在回收预算内退出，任务泄漏"),
            }
        }
    }
}

/// 单条业务连接：读满请求载荷 →（按 `when` 决定何时）回写 → flush → 关写端。
async fn serve(mut socket: TcpStream, reply: Arc<Vec<u8>>, when: ReplyWhen) {
    let mut request = vec![0u8; PAYLOAD.len()];
    if !matches!(
        timeout(WAIT, socket.read_exact(&mut request)).await,
        Ok(Ok(_))
    ) {
        return;
    }
    if request != PAYLOAD {
        return;
    }
    if when == ReplyWhen::AfterEof {
        // 等对端关写端：把“半关闭”变成可判定的事实。
        let mut sink = Vec::new();
        let _ = timeout(WAIT, socket.read_to_end(&mut sink)).await;
    }
    let _ = bounded_write(&mut socket, &reply).await;
    let _ = bounded_flush(&mut socket).await;
    let _ = bounded_shutdown(&mut socket).await;
}
