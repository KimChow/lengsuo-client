// 测试脚手架：测试身份（自签证书）、单连接服务端夹具、回显后端、
// 断言辅助与合法请求头构造。
//
// 本文件由 `tests/exception_matrix.rs` 以 `include!` 拼入该测试目标的根模块，
// 因此共享的导入与常量都在入口文件里。

struct Identity {
    client: TlsClient,
    cert: rcgen::CertifiedKey,
}

impl Identity {
    fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        Self { client, cert }
    }

    fn inbound(&self) -> Inbound {
        Inbound::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }

    async fn connect(&self, port: u16) -> impl AsyncReadExt + AsyncWriteExt + Unpin {
        self.client
            .connect(([127, 0, 0, 1], port).into())
            .await
            .unwrap()
    }
}

/// 单连接服务端：accept 一条 → `handle_tcp` → 返回其结果。带任务计数观测。
struct Harness {
    port: u16,
    live: Arc<AtomicUsize>,
}

impl Harness {
    async fn start(
        identity: &Identity,
        password: &str,
    ) -> (Harness, tokio::task::JoinHandle<Result<(), Error>>) {
        let mut validator = Validator::new();
        validator.add("matrix@example.com", password).unwrap();
        let server = Server::with_tls(
            validator,
            Timeouts::new(HANDSHAKE, WAIT).unwrap(),
            identity.inbound(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let live = Arc::new(AtomicUsize::new(0));
        let counter = live.clone();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let outcome = server.handle_tcp(socket).await;
            counter.fetch_sub(1, Ordering::SeqCst);
            outcome
        });
        (Harness { port, live }, task)
    }
}

/// 回显后端：读满 `len` 字节后原样回写并关写端，accept 计数。
async fn spawn_echo(len: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; len];
                if socket.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let _ = socket.write_all(&buf).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, accepted)
}

/// 断言对端在 `within` 内**主动结束**连接：读到 `Ok(0)` 或 `Err`。
/// 只读到超时即 panic（超时不算拒绝证据）。
async fn assert_peer_closed<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, within: Duration) {
    let mut buf = [0u8; 32];
    let outcome = timeout(within, stream.read(&mut buf))
        .await
        .expect("对端必须在观察上限内主动结束连接（超时不算拒绝证据）");
    assert!(
        matches!(outcome, Ok(0) | Err(_)),
        "不得收到应答：{outcome:?}"
    );
}

/// 完整合法请求头字节（正确密码，TCP → 127.0.0.1:port）。
fn valid_header(port: u16) -> Vec<u8> {
    codec::encode(
        &Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], port),
        },
        &Credential::new(PASSWORD),
    )
    .unwrap()
}
