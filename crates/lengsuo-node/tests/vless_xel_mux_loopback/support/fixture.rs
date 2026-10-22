fn hex_bytes(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..compact.len() / 2)
        .map(|index| u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).expect("十六进制"))
        .collect()
}

/// 回环服务端的三件套：端口、信任锚 PEM、监听器 + TLS 服务端。
pub struct ServerFixture {
    /// 监听端口（node 侧连它）。
    pub port: u16,
    /// 自签证书的 PEM（node 侧的信任锚）。
    pub ca_pem: String,
    listener: TcpListener,
    tls: TlsServer,
}

/// 备好一个只服务一次连接的 TLS 服务端（尚未 accept）。
pub async fn server_fixture() -> ServerFixture {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca_pem = cert.cert.pem().to_owned();
    let tls = TlsServer::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .expect("TLS 服务端");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环监听");
    let port = listener.local_addr().unwrap().port();
    ServerFixture {
        port,
        ca_pem,
        listener,
        tls,
    }
}

/// 起一个**只 accept** 的监听器：用于「坏配置下没有建立连接」的判定。
///
/// 返回（端口，accept 计数句柄，观察任务）。观察任务在**没有连接**时一直挂着
/// （直到调用方的截止时间到），有连接则记一次数并立刻返回。
pub async fn accept_only_watcher() -> (
    u16,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&accepted);
    let watcher = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(socket);
        }
    });
    (port, accepted, watcher)
}

/// node 配置：vless + TLS（可选 `xel` 段 / `mux` 段）。
#[must_use]
pub fn vless_node(
    port: u16,
    ca_pem: &str,
    xel: Option<serde_json::Value>,
    mux: bool,
) -> NodeConfig {
    let mut value = json!([{
        "name": "vless-xel-mux-loopback",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": {
            "server_name": "localhost",
            "ca_pem": ca_pem
        },
        "auth": { "password": UUID }
    }]);
    if let Some(xel) = xel {
        value[0]["xel"] = xel;
    }
    if mux {
        value[0]["mux"] = json!({ "concurrency": 8, "max_connections": 128 });
    }
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}

/// `xel` 配置段（客户端视角：上行 = 本端发出）。
#[must_use]
pub fn xel_section(uplink_hex: &str, downlink_hex: &str) -> serde_json::Value {
    json!({
        "cipher": "aes-256-gcm",
        "uplink_key": uplink_hex,
        "downlink_key": downlink_hex
    })
}

// --------------------------------------------------------------------------------------
// XEL 服务端
// --------------------------------------------------------------------------------------

/// 服务端侧的 XEL 记录层配置（密钥方向以**服务端**为基准）。
fn xel_server_config(uplink_hex: &str, downlink_hex: &str) -> XelWireConfig {
    XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: XelKey::new(&hex_bytes(uplink_hex)).expect("服务端上行密钥"),
        downlink_key: XelKey::new(&hex_bytes(downlink_hex)).expect("服务端下行密钥"),
        xor: None,
    }
}

/// XEL 服务端：TLS → XEL 记录层 → 读 VLESS 请求头 → 写成功响应头 → 回环。
///
/// 判据与 node 侧**一致**：只有拿到成功响应头（`[0, 0]`）才算认证通过
/// （参考 `proxy/vless/inbound/inbound.go:619`）。
///
/// 密钥以**服务端视角**给出（`uplink` = 服务端发出）；与客户端的方向必须对调，
/// 否则 AEAD 必然认证失败（负例正是靠这个不匹配）。
///
/// `expect` = 期望读到的上行载荷长度；读完即原样回送（下行方向也逐字节比对）。
///
/// `tamper_offset` = `Some(n)` ⇒ 在**记录层与传输层之间**插入篡改：记录层输出
/// 的第 `n` 个字节被翻一个比特 ⇒ 对端的 **AEAD 认证必然失败**（而不是被 TLS
/// 层的 MAC 先抓出来）。
pub async fn serve_xel(
    fixture: ServerFixture,
    uuid: [u8; 16],
    server_uplink_hex: &str,
    server_downlink_hex: &str,
    expect: usize,
    tamper_offset: Option<usize>,
) -> Result<Vec<u8>, String> {
    let ServerFixture { listener, tls, .. } = fixture;
    let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
    let tls_stream = tls.accept(socket).await.map_err(|e| e.to_string())?;
    let config = xel_server_config(server_uplink_hex, server_downlink_hex);
    let mut stream = match tamper_offset {
        None => XelStream::new(tls_stream, config).map_err(|e| e.to_string())?,
        Some(offset) => {
            // 在**记录层**与传输层之间架一段桥：记录层写出的字节先过桥（在这里
            // 翻一个比特）再进 TLS ⇒ 线上被改的是**记录层的密文** ⇒ 对端的
            // 记录层 AEAD 认证失败（而不是 TLS 的 MAC 失败）。
            let (xel_side, bridge_side) = tokio::io::duplex(BRIDGE_CAPACITY);
            let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_side);
            let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);
            // 记录层 → TLS（下行方向，篡改点）。
            tokio::spawn(async move {
                let _ = copy_flipping(&mut bridge_read, &mut tls_write, offset).await;
            });
            // TLS → 记录层（上行方向，原样）。
            tokio::spawn(async move {
                let _ = copy_plain(&mut tls_read, &mut bridge_write).await;
            });
            XelStream::new(xel_side, config).map_err(|e| e.to_string())?
        }
    };
    // 请求头走记录层：AEAD 认证不过 ⇒ 这里直接失败（fail-closed）。
    receive_request(&mut stream, &uuid, WAIT)
        .await
        .map_err(|e| format!("读请求头失败：{e}"))?;
    send_response(&mut stream, WAIT)
        .await
        .map_err(|e| format!("写响应头失败：{e}"))?;
    let mut uplink = vec![0u8; expect];
    tokio::time::timeout(WAIT, stream.read_exact(&mut uplink))
        .await
        .map_err(|_| "读上行超时".to_owned())?
        .map_err(|e| format!("读上行失败：{e}"))?;
    stream
        .write_all(&uplink)
        .await
        .map_err(|e| format!("写下行失败：{e}"))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("刷下行失败：{e}"))?;
    // 记录层的写是**后台任务**（`pump_writes`：`pipe → seal → transport.write_all`），
    // `flush()` 只刷应用侧管道、不等传输层 ⇒ 直接 drop 会 `abort` 写任务，回显记录
    // 可能永远没上线。`shutdown()` 等写任务收尾（EOF 时它会 `transport.shutdown()`
    // ⇒ TLS close_notify 顺带把待发记录刷上 socket）。
    stream
        .shutdown()
        .await
        .map_err(|e| format!("下行收尾失败：{e}"))?;
    Ok(uplink)
}
