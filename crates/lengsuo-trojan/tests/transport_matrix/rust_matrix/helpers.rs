// 跑腿助手：本仓服务端夹具（`RustServer`）、单连接处理与客户端建流。
//
// 本文件由 `tests/transport_matrix/rust_matrix.rs` 以 `include!` 拼入该模块，
// 因此共享的导入都在入口文件里。

/// 本仓服务端：TLS 接入 → （按外层）升级 → trojan `server::process`。
///
/// 每条连接的处理结果被记录下来，作为拒绝类用例的“可判别错误变体”证据。
struct RustServer {
    port: u16,
    outcomes: std::sync::Arc<std::sync::Mutex<Vec<Verdict>>>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl RustServer {
    async fn start(identity: &Identity, outer: Outer) -> Self {
        let mut validator = lengsuo_trojan::server::Validator::new();
        validator.add("matrix@example.com", PASSWORD).unwrap();
        let server = lengsuo_trojan::server::Server::new(
            validator,
            lengsuo_trojan::server::Timeouts::new(HANDSHAKE, WAIT).unwrap(),
        );
        let tls = identity.server();
        let config = transport_server::Config::new(PATH, "");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let outcomes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = outcomes.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let tls = tls.clone();
                let server = server.clone();
                let config = config.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    let outcome = run_connection(socket, tls, server, config, outer).await;
                    sink.lock().unwrap().push(outcome);
                });
            }
        });
        Self {
            port,
            outcomes,
            accept_task: Some(accept_task),
        }
    }

    /// 已完成的每连接处理判定（按完成顺序）。
    fn outcomes(&self) -> Vec<Verdict> {
        self.outcomes.lock().unwrap().clone()
    }

    async fn stop(mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = timeout(CLOSE_BOUND, task).await;
        }
    }
}

/// 单条连接的处理：按外层建流，然后交给 trojan `process`。
///
/// 升级失败（路径/头不匹配）发生在 trojan 协议层**之前**，归类为
/// `Verdict::UpgradeFailed`；其余按 `server::Error` 的变体归一。
async fn run_connection(
    socket: TcpStream,
    tls: lengsuo_tls::TlsServer,
    server: lengsuo_trojan::server::Server,
    config: transport_server::Config,
    outer: Outer,
) -> Verdict {
    let stream = match tls.accept(socket).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = error;
            return Verdict::Other;
        }
    };
    match outer {
        Outer::Tcp => match server.process(stream).await {
            Ok(()) => Verdict::Completed,
            Err(error) => Verdict::of(&error),
        },
        Outer::Ws => match transport_server::accept_ws(stream, &config, WAIT).await {
            Ok(conn) => match server.process(conn).await {
                Ok(()) => Verdict::Completed,
                Err(error) => Verdict::of(&error),
            },
            Err(_) => Verdict::UpgradeFailed,
        },
        Outer::HttpUpgrade => {
            match transport_server::accept_httpupgrade(stream, &config, WAIT).await {
                Ok(conn) => match server.process(conn).await {
                    Ok(()) => Verdict::Completed,
                    Err(error) => Verdict::of(&error),
                },
                Err(_) => Verdict::UpgradeFailed,
            }
        }
    }
}

/// 客户端在给定外层上建流（TLS → 升级）并跑一次动作。
///
/// 三个分支的流类型不同，但都喂给同一个泛型 `client_action`。
async fn run_client(
    identity: &Identity,
    port: u16,
    outer: Outer,
    action: Action,
    target_port: u16,
) -> Outcome {
    let endpoint = ([127, 0, 0, 1], port).into();
    match outer {
        Outer::Tcp => {
            let mut stream = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::Ws => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = ws::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("WS 升级失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::HttpUpgrade => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = httpupgrade::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("HTTPUpgrade 升级失败");
            client_action(&mut stream, action, target_port).await
        }
    }
}
