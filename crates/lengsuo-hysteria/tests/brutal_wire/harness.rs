// 共享夹具：临时目录 / openssl 现场自签 / 服务端与客户端构造 / 实跑测量。
fn test_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hy-bw-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

fn openssl(args: &[&str]) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("执行 openssl");
    assert!(
        out.status.success(),
        "openssl 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// openssl 现场自签（SAN=DNS/IP localhost）；返回 (证书 DER, 私钥 DER)。
fn gen_cert(dir: &Path) -> (Vec<u8>, Vec<u8>) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let (c, k) = (cert.to_str().expect("UTF-8"), key.to_str().expect("UTF-8"));
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        k,
        "-out",
        c,
        "-days",
        "2",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "extendedKeyUsage=serverAuth",
    ]);
    (
        openssl(&["x509", "-in", c, "-outform", "DER"]),
        openssl(&["pkey", "-in", k, "-outform", "DER"]),
    )
}

struct Server {
    addr: SocketAddr,
    cert_der: Vec<u8>,
}

/// 起本仓服务端。`brutal_up` = 服务端发送速率（参考 `BrutalUp`），
/// `brutal_down` = 回给客户端的 `Hysteria-CC-RX`（参考 `BrutalDown`）。
async fn start_server(tag: &str, brutal_up: u64, brutal_down: u64, congestion: &str) -> Server {
    let (cert_der, key_der) = gen_cert(&test_dir(tag));
    let mut config = ServerConfig::new(
        "127.0.0.1:0".parse().expect("监听地址"),
        vec![cert_der.clone()],
        key_der,
        AUTH.to_string(),
    );
    config.brutal_up = brutal_up;
    config.brutal_down = brutal_down;
    config.congestion = congestion.to_string();
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let addr = server.local_addr().expect("读取监听地址");
    tokio::spawn(async move { server.accept_loop().await });
    Server { addr, cert_der }
}

fn client_config(server: &Server, up: u64, down: u64) -> ClientConfig {
    ClientConfig {
        server_addr: server.addr,
        server_name: "localhost".to_string(),
        auth: AUTH.to_string(),
        roots_der: vec![server.cert_der.clone()],
        brutal_down: down,
        brutal_up: up,
        congestion: "brutal".to_string(),
        peer_cc_rx: None,
    }
}

/// 回灌端：先读掉 `warmup` 字节请求，再按 `rate` 字节/秒回灌 `total` 字节。
///
/// `obey = false` 时不节拍、全速回灌（CUBIC 对照需要突破上界）。
fn spawn_sink(warmup: usize, total: usize, rate: f64, obey: bool) -> u16 {
    // 回灌端返回 (端口, 发送时刻通道)；本用例只用端口，通道随句柄一起丢弃。
    support::spawn_paced_sink(warmup, total, rate, obey, Duration::from_secs(5)).0
}

/// 一次实跑的结果。
struct Run {
    /// 闭环（请求写完 + 回程收齐）耗时。
    elapsed: Duration,
    /// 回程收到的字节数。
    got: usize,
}

/// 跑一次「客户端上传 `REQUEST_BYTES` → 目标端回灌 `RESPONSE_BYTES`」。
///
/// `negotiated` = 协商速率（字节/秒）；服务端 `BrutalUp`/`BrutalDown` 与
/// 客户端 `up`/`down` 都取该值 ⇒ 协商结果就是它。
async fn measure(tag: &str, negotiated: u64, client_congestion: &str) -> Run {
    let server = start_server(tag, negotiated, negotiated, "brutal").await;
    let body = async {
        let mut config = client_config(&server, negotiated, negotiated);
        config.congestion = client_congestion.to_string();
        // 探测连接读服务端 `Hysteria-CC-RX`（quinn 只能建连前装配拥塞器）。
        let peer = HysteriaClient::probe_peer_cc_rx(&config, Default::default())
            .await
            .expect("探测连接失败");
        eprintln!("[{tag}] 服务端协商头 Hysteria-CC-RX = {peer:?}");
        config.peer_cc_rx = Some(peer);
        let client = HysteriaClient::connect_with_negotiated(config, Default::default())
            .await
            .expect("建连失败");
        // 回灌端：先读掉请求，再回灌固定量。
        let sink_port = spawn_sink(REQUEST_BYTES, RESPONSE_BYTES, negotiated as f64, true);
        let sink_addr = format!("127.0.0.1:{sink_port}");
        let mut stream = proxy::tcp_connect(&client, &sink_addr)
            .await
            .expect("tcp_connect 失败");
        // 单连接双向： 同时持有 QUIC 的 send/recv 两半，
        // 不提供 ，因此**不能**用两个闭包同时借  并发读写
        // （E0499）。这里分两个阶段：
        //   ① 上传：写完请求字节后立即  关上传方向；
        //   ② 回程：再排空响应（目标端按协商速率回灌）。
        // 回灌端  先把请求读干净再回灌，故顺序执行不会死锁；
        // 计时覆盖两阶段总耗时，与「并发」口径对吞吐的影响已在文档中如实说明。
        let started = Instant::now();
        let chunk = vec![0x5au8; 64 * 1024];
        let mut sent = 0usize;
        while sent < REQUEST_BYTES {
            let n = chunk.len().min(REQUEST_BYTES - sent);
            stream.write_all(&chunk[..n]).await.expect("写入失败");
            sent += n;
        }
        stream.finish().expect("关闭上传方向失败");
        let mut got = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while got < RESPONSE_BYTES {
            match tokio::time::timeout(READ_LIMIT, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => got += n,
            }
        }
        let elapsed = started.elapsed();
        (elapsed, got)
    };
    let (elapsed, got) = tokio::time::timeout(BUDGET, body)
        .await
        .expect("实跑总超时（>300s：Brutal 明显未生效）");
    eprintln!("[{tag}] 闭环 {REQUEST_BYTES} B 用时 {elapsed:?}；回程 {got} B");
    Run { elapsed, got }
}

/// 上传吞吐 = 请求字节 / 闭环耗时。
fn upload_rate(run: &Run) -> f64 {
    REQUEST_BYTES as f64 / run.elapsed.as_secs_f64()
}

fn in_band(tag: &str, measured: f64, negotiated: f64) {
    assert!(
        measured >= negotiated / 8.0 && measured <= negotiated * 3.0,
        "{tag}: 实测 {measured:.0} B/s 未落在协商值 {negotiated:.0} B/s 的 [1/8, 3x] 区间内"
    );
    eprintln!("[{tag}] 实测 {measured:.0} B/s（协商 {negotiated:.0} B/s）");
}
