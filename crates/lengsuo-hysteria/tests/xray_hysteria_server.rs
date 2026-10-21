//! 与参考 Xray 的**服务端方向**互通验收（本仓服务端 ← 官方 Xray 客户端）。
//! 全部 `#[ignore]`：须用 `--ignored` 实跑，禁止用自家 roundtrip 冒充。
//!
//! 形态：本仓 `HysteriaServer` 监听 QUIC（ALPN=h3、openssl 现场自签证书进
//! 临时目录）；官方 Xray 以**客户端**身份运行（socks 入站 + hysteria v2
//! outbound，`streamSettings.network=hysteria` + `security=tls`，`serverName`
//! 指向自签证书 SAN），Xray 的 freedom... 不，客户端 outbound 把 socks 流量
//! 打到本仓服务端，服务端直连目标 echo。
//!
//! - 用例 A：TCP echo，1B / 4KiB / 256KiB 逐字节（经 socks 客户端 → 本仓服务端）。
//! - 用例 B：UDP 往返（socks UDP associate）。
//! - 用例 C：错误 auth —— Xray 客户端会因 404 建连失败；断言本仓服务端
//!   对该连接不建立任何承载（由客户端日志/失败体现）。
//!
//! 注：用例 C 的「错误 auth → masquerade 404」断言在本仓服务端侧由
//! `tests/rust_roundtrip.rs::wrong_auth_rust_roundtrip` 直接锁定（同一条参考
//! 路径）；此处以 Xray 官方客户端复验，断言其**无法**完成建连。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream as StdTcpStream, UdpSocket as StdUdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig};

mod support;

const AUTH: &str = "lengsuo-interop-password";
const SERVER_NAME: &str = "localhost";

fn xray_bin() -> PathBuf {
    let path = std::env::var_os("LENGSUO_XRAY")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_XRAY 未设置（参考 /home/ubuntu/ref/bin/xray）");
    assert!(path.is_file(), "LENGSUO_XRAY 指向的文件不存在: {path:?}");
    path
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hy-srv-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

/// openssl 现场自签（SAN=DNS:localhost），证书与私钥只写临时目录。
fn gen_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ])
        .output()
        .expect("执行 openssl");
    assert!(
        out.status.success(),
        "openssl 生成自签证书失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
    std::fs::read(der).expect("读取 DER 证书")
}

fn key_der(key: &Path) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(key)
        .args(["-outform", "DER"])
        .output()
        .expect("执行 openssl pkey");
    assert!(out.status.success(), "openssl 转私钥 DER 失败");
    out.stdout
}

fn free_tcp_port() -> u16 {
    let s = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定随机 TCP 端口");
    s.local_addr().expect("读取端口").port()
}

/// Xray 客户端配置：socks 入站 → hysteria v2 outbound（连本仓服务端）。
fn xray_client_config(socks_port: u16, server_port: u16, auth: &str, cert: &Path) -> String {
    format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{"udp": true}}
  }}],
  "outbounds": [{{
    "protocol": "hysteria",
    "settings": {{
      "version": 2,
      "address": "127.0.0.1",
      "port": {server_port}
    }},
    "streamSettings": {{
      "network": "hysteria",
      "hysteriaSettings": {{"version": 2, "auth": "{auth}"}},
      "security": "tls",
      "tlsSettings": {{
        "serverName": "{SERVER_NAME}",
        "alpn": ["h3"],
        "disableSystemRoot": true,
        "certificates": [{{"certificateFile": "{cert}"}}]
      }}
    }}
  }}]
}}"#,
        cert = support::json_escape(&cert.to_string_lossy())
    )
}

/// 本仓服务端 + 官方 Xray 客户端（socks）的世界。
struct World {
    client: Child,
    socks_port: u16,
    #[allow(dead_code)]
    server: Arc<HysteriaServer>,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = self.client.kill();
        let _ = self.client.wait();
        self.server.close();
    }
}

async fn start_world(tag: &str, server_auth: &str, client_auth: &str) -> World {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    // 本仓服务端：UDP 端口由系统分配后写进 Xray 客户端配置。
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let config = ServerConfig {
        listen_addr: listen,
        cert_chain_der: vec![der],
        key_der: key_der(&key),
        auth: server_auth.to_string(),
        brutal_down: 0,
        brutal_up: 0,
        udp_enabled: true,
        udp_idle_timeout_secs: 60,
        congestion: String::new(),
    };
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let server_port = server.local_addr().expect("读取监听地址").port();
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.accept_loop().await });

    let socks_port = free_tcp_port();
    let cfg_path = dir.join("xray.json");
    std::fs::write(
        &cfg_path,
        xray_client_config(socks_port, server_port, client_auth, &cert),
    )
    .expect("写 xray 配置");
    let log_out = std::fs::File::create(dir.join("xray-stdout.log")).expect("建日志文件");
    let log_err = std::fs::File::create(dir.join("xray-stderr.log")).expect("建日志文件");
    let client = Command::new(xray_bin())
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("启动 xray");
    let world = World {
        client,
        socks_port,
        server,
        dir,
    };
    // 就绪探测：socks 端口可连。
    for _ in 0..80 {
        if StdTcpStream::connect(("127.0.0.1", socks_port)).is_ok() {
            return world;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "xray socks 端口 20s 内未就绪；参考服务端日志:\n{}",
        support::server_logs(&world.dir)
    );
}

/// 本地 TCP echo（本仓服务端直连出站的目标）。
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 echo 端口");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// SOCKS5 CONNECT 到 `target`，返回已连接的 TCP 流。
fn socks5_connect(socks_port: u16, target: SocketAddr) -> StdTcpStream {
    let mut s = StdTcpStream::connect(("127.0.0.1", socks_port)).expect("连 socks 端口");
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("设读超时");
    // 问候：无认证
    s.write_all(&[0x05, 0x01, 0x00]).expect("写问候");
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).expect("读问候响应");
    assert_eq!(resp, [0x05, 0x00], "socks 未接受无认证");
    // CONNECT（IPv4）
    let ip = match target {
        SocketAddr::V4(v4) => v4.ip().octets(),
        SocketAddr::V6(_) => panic!("仅支持 IPv4 目标"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).expect("写 CONNECT");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).expect("读 CONNECT 响应头");
    assert_eq!(head[1], 0x00, "socks CONNECT 失败，reply={}", head[1]);
    // 消费绑定地址（IPv4 = 4 + 2）
    let mut tail = [0u8; 6];
    s.read_exact(&mut tail).expect("读绑定地址");
    s
}

/// 用例 A：TCP echo 三档载荷，经官方 Xray 客户端 → 本仓服务端。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn a_tcp_echo_via_xray_client() {
    let world = start_world("tcp-a", AUTH, AUTH).await;
    let echo_addr = spawn_tcp_echo().await;
    let socks = world.socks_port;
    for size in [1usize, 4 * 1024, 256 * 1024] {
        let payload = pattern(size);
        let echo = echo_addr;
        let to_send = payload.clone();
        let got = tokio::task::spawn_blocking(move || {
            let mut s = socks5_connect(socks, echo);
            s.write_all(&to_send).expect("写载荷");
            s.shutdown(std::net::Shutdown::Write).expect("半关闭");
            let mut out = Vec::with_capacity(to_send.len());
            s.read_to_end(&mut out).expect("读回包");
            out
        })
        .await
        .expect("join");
        assert_eq!(got.len(), payload.len(), "回包长度不符（size={size}）");
        assert_eq!(got, payload, "回包内容不符（size={size}）");
    }
}

/// 用例 B：UDP 往返（socks5 UDP associate），经官方 Xray 客户端 → 本仓服务端。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn b_udp_echo_via_xray_client() {
    let world = start_world("udp-b", AUTH, AUTH).await;
    // 本地 UDP echo（本仓服务端直连出站的目标）。
    let echo = StdUdpSocket::bind("127.0.0.1:0").expect("绑定 UDP echo");
    let echo_addr = echo.local_addr().expect("echo 地址");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = echo.recv_from(&mut buf) {
            if echo.send_to(&buf[..n], from).is_err() {
                return;
            }
        }
    });
    let socks = world.socks_port;
    let payload = pattern(64);
    let to_send = payload.clone();
    let got = tokio::task::spawn_blocking(move || {
        // TCP 控制连接申请 UDP associate
        let mut ctrl = StdTcpStream::connect(("127.0.0.1", socks)).expect("连 socks");
        ctrl.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("读超时");
        ctrl.write_all(&[0x05, 0x01, 0x00]).expect("写问候");
        let mut resp = [0u8; 2];
        ctrl.read_exact(&mut resp).expect("读问候响应");
        assert_eq!(resp, [0x05, 0x00]);
        // UDP ASSOCIATE，绑定地址 0.0.0.0:0
        ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("写 ASSOCIATE");
        let mut head = [0u8; 4];
        ctrl.read_exact(&mut head).expect("读 ASSOCIATE 响应头");
        assert_eq!(head[1], 0x00, "UDP ASSOCIATE 失败，reply={}", head[1]);
        let mut tail = [0u8; 6];
        ctrl.read_exact(&mut tail).expect("读中继地址");
        let relay = SocketAddr::from((
            [tail[0], tail[1], tail[2], tail[3]],
            u16::from_be_bytes([tail[4], tail[5]]),
        ));
        // 经中继发一条 UDP 报文到 echo
        let udp = StdUdpSocket::bind("127.0.0.1:0").expect("绑定本地 UDP");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("读超时");
        let ip = match echo_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(_) => panic!("仅支持 IPv4"),
        };
        let mut pkt = vec![0x00, 0x00, 0x00, 0x01];
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&echo_addr.port().to_be_bytes());
        pkt.extend_from_slice(&to_send);
        udp.send_to(&pkt, relay).expect("发 UDP 报文");
        let mut buf = [0u8; 4096];
        let (n, _) = udp.recv_from(&mut buf).expect("收 UDP 回包");
        // SOCKS5 UDP 响应头：RSV(2) FRAG(1) ATYP(1) + 地址 + 数据
        assert!(n > 10, "UDP 回包过短: {n}");
        let atyp = buf[3];
        let hdr = match atyp {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => 1 + buf[4] as usize + 2,
            other => panic!("未知 ATYP {other:#x}"),
        };
        buf[4 + hdr..n].to_vec()
    })
    .await
    .expect("join");
    assert_eq!(got, payload, "UDP 回包内容不符");
}

/// 用例 C：错误 auth。官方 Xray 客户端用错口令 → 本仓服务端回 masquerade
/// 404，客户端无法完成 SOCKS CONNECT（连接被关闭/拒绝）。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn c_wrong_auth_no_tunnel() {
    // 服务端口令与客户端口令**不同**：客户端应被拒。
    let world = start_world("auth-c", "server-side-secret", "wrong-client-secret").await;
    // 目标用真实 echo：若认证被绕过，客户端能连通并回包，用例即失败。
    let echo_addr = spawn_tcp_echo().await;
    let socks = world.socks_port;
    let payload = pattern(16);
    let tunneled = tokio::task::spawn_blocking(move || {
        let mut s = StdTcpStream::connect(("127.0.0.1", socks)).expect("连 socks");
        s.set_read_timeout(Some(Duration::from_secs(15)))
            .expect("读超时");
        s.write_all(&[0x05, 0x01, 0x00]).expect("写问候");
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).expect("读问候响应");
        // CONNECT 到真实 echo（IPv4 + 端口）
        let ip = match echo_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(_) => panic!("仅支持 IPv4"),
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        s.write_all(&req).expect("写 CONNECT");
        let mut head = [0u8; 4];
        let Ok(()) = s.read_exact(&mut head) else {
            return false; // 连接被关闭 = 未建立隧道
        };
        if head[1] != 0x00 {
            return false; // 明确拒绝
        }
        // 声称成功，再验数据是否真能往返（防「假成功」）
        let mut tail = [0u8; 6];
        if s.read_exact(&mut tail).is_err() {
            return false;
        }
        if s.write_all(&payload).is_err() {
            return false;
        }
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut out = Vec::new();
        s.read_to_end(&mut out).is_ok() && out == payload
    })
    .await
    .expect("join");
    assert!(
        !tunneled,
        "错误 auth 下不应建立可用隧道（认证未 fail-closed：回包成功）"
    );
}
