const AUTH: &str = "lengsuo-interop-password";
const SERVER_NAME: &str = "localhost";
const PSK: &str = "lengsuo-obfs-psk";
const WRONG_PSK: &str = "lengsuo-obfs-psk-wrong";
const PAYLOAD: &[u8] = b"lengsuo-salamander-interop-payload";

fn xray_bin() -> PathBuf {
    let path = std::env::var_os("LENGSUO_XRAY")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_XRAY 未设置（参考 /home/ubuntu/ref/bin/xray）");
    assert!(path.is_file(), "LENGSUO_XRAY 指向的文件不存在: {path:?}");
    path
}

fn test_dir(tag: &str) -> PathBuf {
    let name = format!("lengsuo-hy-obfshop-{}-{}", tag, std::process::id());
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

/// 生成自签证书（DER 落到 `dir/cert.der`，供客户端当 root / 算指纹）。
fn gen_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args(["-days", "2", "-subj", "/CN=localhost"])
        .args(["-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
        .args(["-addext", "basicConstraints=critical,CA:FALSE"])
        .args(["-addext", "keyUsage=digitalSignature,keyEncipherment"])
        .args(["-addext", "extendedKeyUsage=serverAuth"])
        .output()
        .expect("执行 openssl");
    assert!(out.status.success(), "openssl 生成自签证书失败");
    (cert, key)
}

fn cert_der(cert: &Path, dir: &Path) -> Vec<u8> {
    let der = dir.join("cert.der");
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-outform", "DER", "-out"])
        .arg(&der)
        .output()
        .expect("执行 openssl x509");
    assert!(out.status.success(), "openssl 转 DER 失败");
    std::fs::read(&der).expect("读取 DER 证书")
}

/// 证书 DER 的 SHA-256 指纹（小写 hex，无冒号）。
///
/// 参考 xray 26.x 移除了 `allowInsecure`（`infra/conf/transport_internet.go:709-715`），
/// 改用 `pinnedPeerCertSha256`（同文件 `:660/717`），取值 = 证书 ASN.1 DER 的
/// SHA-256（`transport/internet/tls/pin.go` 的 `GenerateCertHash`）；命中**叶子**
/// 证书时直接放行（`transport/internet/tls/config.go:299-303`）⇒ 自签证书可直接用。
fn cert_sha256_hex(dir: &Path) -> String {
    let out = Command::new("openssl")
        .args(["dgst", "-sha256", "-hex"])
        .arg(dir.join("cert.der"))
        .output()
        .expect("执行 openssl dgst");
    assert!(out.status.success(), "openssl dgst 失败");
    let hex = String::from_utf8_lossy(&out.stdout);
    let tail = hex.rsplit('=').next().unwrap_or_default();
    tail.trim().to_string()
}

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定随机 UDP 端口");
    s.local_addr().expect("读取端口").port()
}

fn free_tcp_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定随机 TCP 端口");
    let port = l.local_addr().expect("读取端口").port();
    drop(l);
    port
}

/// 参考侧 `finalmask` 片段（`None` ⇒ 不下发该段）。
// JSON 模板一律用 `@占位符@` + `String::replace`：`format!` 下满屏 `{{`/`}}`
// 极易漏转义（本文件就吃过一次 unmatched `}`）。
fn fill(tpl: &str, subs: &[(&str, &str)]) -> String {
    let mut out = tpl.to_string();
    for (k, v) in subs {
        out = out.replace(k, v);
    }
    out
}

fn finalmask_json(psk: Option<&str>) -> String {
    match psk {
        Some(p) => fill(
            r#","finalmask":{"udp":[{"type":"salamander","settings":{"password":"@PSK@"}}]}"#,
            &[("@PSK@", &support::json_escape(p))],
        ),
        None => String::new(),
    }
}

/// 参考**服务端**配置：`finalmask.udp` 里放 Salamander 口令。
fn ref_server_config(port: u16, cert: &Path, key: &Path, psk: Option<&str>) -> String {
    let cert = support::json_escape(&cert.to_string_lossy());
    let key = support::json_escape(&key.to_string_lossy());
    fill(
        r#"{"log":{"loglevel":"warning"},
"inbounds":[{"listen":"127.0.0.1","port":@PORT@,"protocol":"hysteria",
"settings":{"version":2,"clients":[{"auth":"@AUTH@"}]},
"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"@AUTH@"},
"security":"tls","tlsSettings":{"serverName":"@SERVER_NAME@","alpn":["h3"],
"certificates":[{"certificateFile":"@CERT@","keyFile":"@KEY@"}]}@MASK@}}],
"outbounds":[{"protocol":"freedom"}]}"#,
        &[
            ("@PORT@", &port.to_string()),
            ("@AUTH@", AUTH),
            ("@SERVER_NAME@", SERVER_NAME),
            ("@CERT@", &cert),
            ("@KEY@", &key),
            ("@MASK@", &finalmask_json(psk)),
        ],
    )
}

/// 参考**客户端**配置：socks 入站 + hysteria 出站（带 Salamander）。
///
/// `pin` = 服务端证书 DER 的 SHA-256（参考 xray 26.x 已移除 `allowInsecure`）。
fn ref_client_config(socks_port: u16, server_port: u16, psk: Option<&str>, pin: &str) -> String {
    let pin = support::json_escape(pin);
    fill(
        r#"{"log":{"loglevel":"warning"},
"inbounds":[{"listen":"127.0.0.1","port":@SOCKS_PORT@,"protocol":"socks","settings":{"udp":false}}],
"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"127.0.0.1","port":@SERVER_PORT@},
"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"@AUTH@"},
"security":"tls","tlsSettings":{"serverName":"@SERVER_NAME@","alpn":["h3"],
"pinnedPeerCertSha256":"@PIN@"}@MASK@}}]}"#,
        &[
            ("@SOCKS_PORT@", &socks_port.to_string()),
            ("@SERVER_PORT@", &server_port.to_string()),
            ("@AUTH@", AUTH),
            ("@SERVER_NAME@", SERVER_NAME),
            ("@PIN@", &pin),
            ("@MASK@", &finalmask_json(psk)),
        ],
    )
}

/// 参考进程（服务端或客户端）。`Drop` 时杀掉它。
struct RefProc {
    child: Child,
}

impl Drop for RefProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_ref(dir: &Path, cfg_name: &str, cfg: &str) -> RefProc {
    let cfg_path = dir.join(cfg_name);
    std::fs::write(&cfg_path, cfg).expect("写参考配置");
    let log_out = std::fs::File::create(dir.join("xray-stdout.log")).expect("建日志");
    let log_err = std::fs::File::create(dir.join("xray-stderr.log")).expect("建日志");
    let child = Command::new(xray_bin())
        .args(["run", "-c"])
        .arg(&cfg_path)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("启动参考 xray");
    RefProc { child }
}

/// 参考服务端世界（证书 + 端口 + 进程）。
#[allow(dead_code)] // `proc` 只作 `Drop` 守护，不主动读取。
struct RefServer {
    proc: RefProc,
    port: u16,
    der: Vec<u8>,
}

/// 轮询 `f` 直到成功；每次尝试自带墙钟上限（Windows 上 UDP 静默丢弃会架空总预算）。
async fn retry_until<T, F, Fut>(attempts: usize, budget: Duration, f: F) -> Result<T, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut last = String::new();
    for _ in 0..attempts {
        match tokio::time::timeout(budget, f()).await {
            Ok(Ok(v)) => return Ok(v),
            Ok(Err(e)) => last = e,
            Err(_) => last = "单次尝试超时".to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(last)
}

async fn start_ref_server(tag: &str, psk: Option<&str>) -> RefServer {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let port = free_udp_port();
    let cfg = ref_server_config(port, &cert, &key, psk);
    let proc = spawn_ref(&dir, "xray.json", &cfg);
    let world = RefServer { proc, port, der };
    // 等端口可连（UDP 无连接 ⇒ 用一次**真实握手**探测）。探测必须用**与服务端
    // 相同的混淆参数**：服务端开了 Salamander 时不混淆的握手永远等不到回应。
    let ready = retry_until(80, support::PROBE_ATTEMPT_TIMEOUT, || async {
        connect_ref_server(&world, psk)
            .await
            .map_err(|e| e.to_string())
    })
    .await;
    match ready {
        Ok(_) => world,
        Err(last) => panic!(
            "参考服务端 20s 内未就绪；最后错误 {last}；日志:\n{}",
            support::server_logs(&dir)
        ),
    }
}

/// 本仓客户端 → 参考服务端。`psk` = `None` ⇒ 不混淆（基线用）。
async fn connect_ref_server(
    world: &RefServer,
    psk: Option<&str>,
) -> Result<HysteriaClient, lengsuo_hysteria::quic::ConnectError> {
    let obfs = match psk {
        Some(p) => ObfsHopConfig::obfs(p.as_bytes().to_vec()).expect("口令长度合法"),
        None => ObfsHopConfig::none(),
    };
    HysteriaClient::connect_with_obfs(
        ClientConfig {
            server_addr: SocketAddr::from(([127, 0, 0, 1], world.port)),
            server_name: SERVER_NAME.to_string(),
            auth: AUTH.to_string(),
            roots_der: vec![world.der.clone()],
            brutal_down: 0,
            brutal_up: 0,
            congestion: String::new(),
            peer_cc_rx: None,
        },
        obfs,
    )
    .await
}

/// 本仓服务端（可带混淆）+ 参考客户端。
struct OurServer {
    addr: SocketAddr,
    /// 服务端证书 DER 的 SHA-256 指纹（参考客户端用 `pinnedPeerCertSha256` 接受本仓自签证书）。
    pin: String,
    #[allow(dead_code)]
    handle: tokio::task::JoinHandle<()>,
}
