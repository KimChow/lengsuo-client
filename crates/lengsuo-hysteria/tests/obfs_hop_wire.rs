//! Hysteria2 的 **Salamander 混淆** 与 **端口跳跃** 接入真实链路后的互通取证。
//!
//! 全部 `#[ignore]`：须用 `--ignored` 实跑（需要参考二进制 `LENGSUO_XRAY`）。
//!
//! 五个方向：① **可证伪基线**（参考服务端开掩码 ⇒ 本仓不混淆的客户端必须
//! 连不上）；② 本仓客户端 → 参考服务端；③ 参考客户端 → 本仓服务端；
//! ④ 口令不符必须失败（先立对照组）；⑤ 端口跳跃的 socket 层取证。
//!
//! 参考侧配置（`streamSettings.finalmask.udp[].settings.password`）来自
//! `infra/conf/transport_internet.go:1720/1889` 与
//! `transport/internet/finalmask/salamander/config.proto`（`password`）。
//!
//! # 参考侧的线上格式
//!
//! `finalmask.go` 走 **header 分支**（`salamander/config.go:18` 的 `HeaderConn()`）：
//! `headerManagerConn.WriteTo` 把载荷拷到 `writeBuf[8:]`（留 8 字节头部余量），
//! 交给 `salamanderConn.WriteTo` 做 `Obfuscate(p[8:], p)` —— **用头部余量装盐**。
//! 上线路字节 = `[8 字节盐][载荷 ^ BLAKE2b256(PSK||盐)]`，与本仓
//! `transport/wire.rs` 逐字节一致。

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use lengsuo_hysteria::obfs::Obfuscator;
use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::{
    ClientConfig, HysteriaClient, HysteriaServer, ObfsHopConfig, ServerConfig,
};
use lengsuo_hysteria::transport::{HopSpec, MaskedUdpSocket, OsRng, WireMask};

mod support;

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

async fn start_our_server(tag: &str, psk: Option<&str>) -> OurServer {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let pin = cert_sha256_hex(&dir);
    let out = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&key)
        .args(["-outform", "DER", "-out", "-"])
        .output()
        .expect("执行 openssl pkey");
    assert!(out.status.success(), "openssl 转私钥 DER 失败");
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let config = ServerConfig::new(listen, vec![der], out.stdout, AUTH.to_string());
    let server = match psk {
        Some(p) => HysteriaServer::bind_with_obfs(config, p.as_bytes().to_vec()),
        None => HysteriaServer::bind(config),
    }
    .expect("服务端绑定失败");
    let addr = server.local_addr().expect("读取监听地址");
    // `accept_loop` 的接收者是 `Arc<Self>`（对齐 `keepAccepting` 的共享端点）。
    let server = Arc::new(server);
    let handle = tokio::spawn(async move { server.accept_loop().await });
    OurServer { addr, pin, handle }
}

/// 起参考客户端（socks 入站 → hysteria 出站）。
async fn start_ref_client(tag: &str, port: u16, psk: Option<&str>, pin: &str) -> (RefProc, u16) {
    let dir = test_dir(tag);
    let socks_port = free_tcp_port();
    let cfg = ref_client_config(socks_port, port, psk, pin);
    let proc = spawn_ref(&dir, "xray-client.json", &cfg);
    (proc, socks_port)
}

/// SOCKS5 的 ATYP + 地址字节（1 = IPv4，4 = IPv6）。
fn socks_atyp(addr: IpAddr) -> (u8, Vec<u8>) {
    match addr {
        IpAddr::V4(v4) => (0x01, v4.octets().to_vec()),
        IpAddr::V6(v6) => (0x04, v6.octets().to_vec()),
    }
}

/// 通过参考客户端的 socks 入站做一次 TCP 回显，返回读到的字节。
///
/// 失败（socks 协商失败 / CONNECT 被拒 / 读写错误）统一返回 `Err`，
/// 由调用方决定是重试还是判失败 —— 「口令不符」时参考客户端会**拒绝**
/// SOCKS CONNECT，这属于预期失败，不能 panic。
fn io_err(e: std::io::Error) -> String {
    e.to_string()
}

async fn socks_roundtrip(
    socks_port: u16,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .map_err(|e| format!("连参考客户端 socks: {e}"))?;
    // SOCKS5 握手：认证协商（只支持「无认证」）。
    sock.write_all(&[5, 1, 0]).await.map_err(io_err)?;
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.map_err(io_err)?;
    if resp[0] != 0x05 {
        return Err(format!("socks 版本不符: {resp:?}"));
    }
    if resp[1] != 0x00 {
        return Err(format!("socks 认证方法不接受: {resp:?}"));
    }
    // SOCKS5 CONNECT 请求：ATYP 由目标地址族决定。
    let (atyp, ip) = socks_atyp(target.ip());
    let mut req = vec![5, 1, 0, atyp];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    sock.write_all(&req).await.map_err(io_err)?;
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != 0x05 {
        return Err(format!("socks 版本不符: {head:?}"));
    }
    if head[1] != 0x00 {
        return Err(format!("socks CONNECT 被拒（状态 {:#04x}）", head[1]));
    }
    // 绑定地址长度随 ATYP 变化（IPv4 6 / IPv6 18 / 域名 1+n）⇒ 读掉即可。
    let bound = match head[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await.map_err(io_err)?;
            l[0] as usize + 2
        }
        other => return Err(format!("socks atyp 非法: {other}")),
    };
    let mut rest = vec![0u8; bound];
    sock.read_exact(&mut rest).await.map_err(io_err)?;
    sock.write_all(payload).await.map_err(io_err)?;
    sock.flush().await.map_err(io_err)?;
    let mut got = vec![0u8; payload.len()];
    sock.read_exact(&mut got).await.map_err(io_err)?;
    Ok(got)
}

/// 本仓客户端 → 目标 TCP 的回显（走 Hysteria 代理）。
async fn proxy_roundtrip(client: &HysteriaClient, target: SocketAddr) -> Vec<u8> {
    let mut stream = proxy::tcp_connect(client, &target.to_string())
        .await
        .expect("tcp_connect 失败");
    stream.write_all(PAYLOAD).await.expect("写载荷");
    stream.finish().expect("半关闭");
    // `TcpProxyStream` 提供的是**固有方法** `read`（不是 `AsyncRead`），
    // 没有 `read_exact` ⇒ 这里手工读满。
    let mut got = vec![0u8; PAYLOAD.len()];
    let mut filled = 0usize;
    while filled < got.len() {
        let n = stream.read(&mut got[filled..]).await.expect("读回显");
        if n == 0 {
            break;
        }
        filled += n;
    }
    assert_eq!(filled, PAYLOAD.len(), "回显长度不足");
    got
}

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 echo");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// 方向⓪（可证伪基线）：参考服务端开了 Salamander，本仓客户端**不**混淆
/// ⇒ 必须连不上。若这条能连上，说明「混淆层根本没生效」，后续用例全无意义。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn baseline_plain_client_cannot_talk_to_masked_ref_server() {
    let world = start_ref_server("baseline", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    // 不混淆 ⇒ 必须连不上。「连不上」有两种形态，**都算失败**：快速报错；
    // 或超时（参考服务端解不开混淆 ⇒ 丢包 ⇒ 握手永远完不成）—— 这恰恰是
    // 混淆层生效的表现，因此**不能**把超时当测试错误。
    let res = tokio::time::timeout(Duration::from_secs(10), connect_ref_server(&world, None)).await;
    match res {
        Ok(Ok(_)) => panic!("基线必须失败：不混淆却连上了参考服务端"),
        Ok(Err(e)) => assert!(
            !matches!(e, lengsuo_hysteria::quic::ConnectError::Bind(_)),
            "失败原因应是握手/认证层，而不是本地绑定: {e}"
        ),
        Err(_) => {}
    }
    // 混淆后同一服务端必须能连上（证明基线失败源于混淆层，而非服务端本身坏了）。
    let client = connect_ref_server(&world, Some(PSK))
        .await
        .expect("混淆后应能连上");
    let got = proxy_roundtrip(&client, echo).await;
    assert_eq!(got, PAYLOAD, "混淆后回显应逐字节一致");
}

/// 方向①：本仓客户端（真混淆）→ 参考服务端（参考 Salamander）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn our_client_obfuscates_towards_ref_server() {
    let world = start_ref_server("dir1", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    let client = connect_ref_server(&world, Some(PSK))
        .await
        .expect("建连失败（本仓混淆 ↔ 参考 Salamander）");
    let got = proxy_roundtrip(&client, echo).await;
    assert_eq!(got, PAYLOAD, "回显应逐字节一致");
}

/// 方向②：参考客户端（参考 Salamander）→ 本仓服务端（真解混淆）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn ref_client_obfuscates_towards_our_server() {
    let server = start_our_server("dir2", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    let (_ok_proc, socks_port) =
        start_ref_client("dir2", server.addr.port(), Some(PSK), &server.pin).await;
    // 参考客户端起来需要一点时间（socks 端口要能连）。
    let d = Duration::from_secs(3);
    let got = retry_until(80, d, || socks_roundtrip(socks_port, echo, PAYLOAD))
        .await
        .unwrap_or_else(|e| panic!("参考客户端 → 本仓服务端 未能完成回显；最后错误 {e}"));
    assert_eq!(got, PAYLOAD, "回显应逐字节一致");
}

/// 方向③：口令不符 ⇒ 必须失败。
///
/// 三个方向，**先立对照组**再测失败，否则「失败」无法归因：
/// - A：本仓服务端（正确口令）+ 参考客户端（**正确**口令）⇒ **必须成功**；
/// - B：同一个本仓服务端 + 参考客户端（**错误**口令）⇒ 必须失败；
/// - C：参考服务端（正确口令）+ 本仓客户端（**错误**口令）⇒ 必须失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn wrong_password_is_rejected() {
    // ── 方向 A：对照组，必须成功。
    let server = start_our_server("dir3b", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    let (_ok_proc, ok_port) =
        start_ref_client("dir3b-ok", server.addr.port(), Some(PSK), &server.pin).await;
    let d = Duration::from_secs(3);
    let got = retry_until(80, d, || socks_roundtrip(ok_port, echo, PAYLOAD))
        .await
        .unwrap_or_else(|e| panic!("对照组失败：本仓服务端 + 正确口令的参考客户端 未能回显；{e}"));
    assert_eq!(got, PAYLOAD, "回显应逐字节一致");

    // ── 方向 B：同一个本仓服务端 + 错误口令的参考客户端 ⇒ 必须失败。
    let (_bad_proc, bad_port) = start_ref_client(
        "dir3b-bad",
        server.addr.port(),
        Some(WRONG_PSK),
        &server.pin,
    )
    .await;
    let bad = retry_until(10, d, || socks_roundtrip(bad_port, echo, PAYLOAD)).await;
    assert!(
        bad.is_err(),
        "错误口令时参考客户端竟能通过本仓服务端完成回显（解混淆没有 fail-closed）"
    );

    // ── 方向 C：参考服务端（正确口令）+ 本仓客户端（错误口令）⇒ 必须失败。
    let world = start_ref_server("dir3", Some(PSK)).await;
    let ten = Duration::from_secs(10);
    let res = tokio::time::timeout(ten, connect_ref_server(&world, Some(WRONG_PSK))).await;
    match res {
        Ok(Ok(_)) => panic!("错误口令必须失败：却连上了参考服务端"),
        Ok(Err(e)) => assert!(
            !matches!(e, lengsuo_hysteria::quic::ConnectError::Bind(_)),
            "失败原因应是握手/认证层（服务端解混淆丢弃了报文），而不是本地绑定: {e}"
        ),
        Err(_) => {}
    }
}

/// 端口跳跃 + 混淆的**socket 层取证**（不需要网络）。
///
/// 用假 socket 驱动 [`MaskedUdpSocket`]：① `try_send` 的**目的端口**必须
/// 随跳变；② 发出的字节必须带 8 字节盐前缀；③ 收侧必须能解混淆还原明文，
/// 口令不符的包**不得**还原成原文。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hop_rotates_destination_port_on_the_wire() {
    /// 记录 `try_send` 的目的地址与内容，并可注入待收报文。
    #[derive(Debug, Default)]
    struct FakeSocket {
        sent: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
        inbox: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    }

    impl AsyncUdpSocket for FakeSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unimplemented!("本用例只驱动 try_send/poll_recv")
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
            let mut sent = self.sent.lock().expect("锁");
            sent.push((transmit.destination, transmit.contents.to_vec()));
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            let mut inbox = self.inbox.lock().expect("锁");
            if inbox.is_empty() {
                return Poll::Pending;
            }
            let (addr, data) = inbox.remove(0);
            bufs[0][..data.len()].copy_from_slice(&data);
            meta[0] = RecvMeta {
                addr,
                len: data.len(),
                stride: data.len(),
                ..RecvMeta::default()
            };
            Poll::Ready(Ok(1))
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().expect("固定地址"))
        }
    }

    /// 造一条待发报文。
    fn tx(dest: SocketAddr, contents: &'static [u8]) -> Transmit<'static> {
        Transmit {
            destination: dest,
            contents,
            segment_size: None,
            ecn: None,
            src_ip: None,
        }
    }

    /// 从包装 socket 收一条报文，返回 (条数, 明文字节)。
    fn recv_one(socket: &MaskedUdpSocket) -> Option<(usize, Vec<u8>)> {
        let mut store = [0u8; 2048];
        let mut bufs = [IoSliceMut::new(&mut store)];
        let mut meta = [RecvMeta::default(); 1];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let ready = socket.poll_recv(&mut cx, &mut bufs, &mut meta);
        let Poll::Ready(Ok(n)) = ready else {
            return None;
        };
        Some((n, bufs[0][..meta[0].len].to_vec()))
    }

    /// 用给定口令造一份密文（模拟对端）。
    fn peer_cipher(psk: &str, plain: &[u8]) -> Vec<u8> {
        let o = Obfuscator::new(psk.as_bytes().to_vec(), Arc::new(OsRng)).expect("口令合法");
        let mut out = vec![0u8; plain.len() + 8];
        let n = o.obfuscate(plain, &mut out).expect("缓冲足够");
        out.truncate(n);
        out
    }

    let base: SocketAddr = "127.0.0.1:4433".parse().expect("固定地址");
    let other: u16 = 8443;
    let spec = HopSpec::new(vec![base.port(), other], 5, 5).expect("跳端口规格");
    let psk = PSK.as_bytes().to_vec();
    let rng = Arc::new(OsRng);
    let mask = Arc::new(WireMask::new(base, Some(psk), Some(spec), rng).expect("掩码构造"));
    let fake = Arc::new(FakeSocket::default());
    // 目标类型已知 ⇒ `Arc<FakeSocket>` 到 `Arc<dyn AsyncUdpSocket>` 的
    // 无形化协变在这里生效（`Arc::clone(&fake)` 反而会按期望类型推断
    // `T = dyn AsyncUdpSocket` 而不匹配）。
    let inner: Arc<dyn AsyncUdpSocket> = fake.clone();
    let socket = MaskedUdpSocket::new(inner, mask.clone());

    // ① 跳之前：目的端口 = 配置端口。
    socket.try_send(&tx(base, b"hello-obfs")).expect("发送");
    let sent = fake.sent.lock().expect("锁").clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, base, "跳之前目的端口必须是配置端口");
    assert_eq!(sent[0].1.len(), b"hello-obfs".len() + 8, "8 字节盐 + 明文");
    assert_ne!(&sent[0].1[..8], &b"hello-obf"[..], "盐前缀不得是明文");

    // ② 跳之后：目的端口必须换成端口集合里的另一个。
    let hopped = mask.next_hop().expect("应能跳一次");
    assert_eq!(mask.current_remote(), hopped, "当前目标应随跳更新");
    let ports = [base.port(), other];
    assert!(ports.contains(&hopped.port()), "端口必须来自端口集合");
    socket.try_send(&tx(base, b"after-hop")).expect("发送");
    let sent = fake.sent.lock().expect("锁").clone();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].0.port(), hopped.port(), "跳后必须发往新的目的端口");

    // ③ 收侧：解混淆还原明文。
    let plain = b"payload-from-peer";
    let cipher = peer_cipher(PSK, plain);
    fake.inbox.lock().expect("锁").push((base, cipher));
    let (n, got) = recv_one(&socket).expect("应收到一条");
    assert_eq!(n, 1, "一条合法密文应解出");
    assert_eq!(got, plain, "解混淆应还原明文");

    // 错误口令的密文 ⇒ **不得**还原成原文。注意：Salamander **没有 MAC**
    // （参考 `salamander.go` 的 `Obfuscate`/`Deobfuscate` 只做 XOR，无校验），
    // 因此结构上无法判定「口令不符」；可判定的是「解出来的字节必然不是
    // 原文」。参考也是同样语义（`hub.go` 侧收到乱码后由 QUIC 层丢弃）。
    let wrong = peer_cipher(WRONG_PSK, plain);
    fake.inbox.lock().expect("锁").push((base, wrong));
    if let Some((n, got)) = recv_one(&socket) {
        assert_eq!(n, 1, "长度足够的密文在结构上仍会被解混淆（无 MAC）");
        assert_ne!(got, plain, "口令不符的密文不得被还原成原文");
    }

    // ④ 归一：同 IP 的回包地址归一到规范地址（quinn 客户端禁止迁移）。
    let same_ip = SocketAddr::from(([127, 0, 0, 1], other));
    let other_ip = SocketAddr::from(([10, 0, 0, 1], other));
    assert_eq!(mask.normalize_peer(same_ip), Some(base), "同 IP 应归一");
    assert_eq!(mask.normalize_peer(other_ip), None, "不同 IP 必须拒绝");
}
