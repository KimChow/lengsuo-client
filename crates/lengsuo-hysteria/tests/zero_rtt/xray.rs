// Xray 参考实跑（`#[ignore]`）：官方 Xray 作服务端，本仓客户端两次建连的 0-RTT 取证。
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::{
    EarlyDataConfig, HysteriaClient, MemorySessionCache, SessionCache, ZeroRttOutcome,
};
use quinn::rustls::pki_types::ServerName;

const AUTH: &str = "lengsuo-0rtt-password";
const SERVER_NAME: &str = "localhost";

fn xray_bin() -> PathBuf {
    let path = std::env::var_os("LENGSUO_XRAY")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_XRAY 未设置（参考 /path/to/xray）");
    assert!(path.is_file(), "LENGSUO_XRAY 指向的文件不存在: {path:?}");
    path
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-0rtt-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

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
    let der_path = dir.join("cert.der");
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-outform", "DER", "-out"])
        .arg(&der_path)
        .output()
        .expect("执行 openssl x509");
    assert!(out.status.success(), "openssl 转 DER 失败");
    std::fs::read(der_path).expect("读取 DER 证书")
}

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定随机 UDP 端口");
    s.local_addr().expect("读取端口").port()
}

fn xray_config(port: u16, cert: &Path, key: &Path) -> String {
    format!(
        r#"{{
  "log": {{"loglevel": "warning"}},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {port},
    "protocol": "hysteria",
    "settings": {{"version": 2, "clients": [{{"auth": "{AUTH}"}}]}},
    "streamSettings": {{
      "network": "hysteria",
      "hysteriaSettings": {{"version": 2, "auth": "{AUTH}"}},
      "security": "tls",
      "tlsSettings": {{
        "serverName": "{SERVER_NAME}",
        "enableSessionResumption": true,
        "alpn": ["h3"],
        "certificates": [{{"certificateFile": "{}", "keyFile": "{}"}}]
      }}
    }}
  }}],
  "outbounds": [{{"protocol": "freedom"}}]
}}"#,
        crate::support::json_escape(&cert.to_string_lossy()),
        crate::support::json_escape(&key.to_string_lossy())
    )
}

struct World {
    child: Child,
    port: u16,
    cert_der: Vec<u8>,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn config(world: &World) -> lengsuo_hysteria::quic::ClientConfig {
    lengsuo_hysteria::quic::ClientConfig {
        server_addr: SocketAddr::from(([127, 0, 0, 1], world.port)),
        server_name: SERVER_NAME.to_string(),
        auth: AUTH.to_string(),
        roots_der: vec![world.cert_der.clone()],
        brutal_down: 0,
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    }
}

async fn start_world(tag: &str) -> World {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let port = free_udp_port();
    let cfg_path = dir.join("xray.json");
    std::fs::write(&cfg_path, xray_config(port, &cert, &key)).expect("写 xray 配置");
    let child = Command::new(xray_bin())
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("xray-stderr.log")).expect("建日志文件"),
        ))
        .spawn()
        .expect("启动 xray");
    let world = World {
        child,
        port,
        cert_der: der,
        dir,
    };
    // 单次尝试自带墙钟上限：Windows 上向未监听端口发 UDP 是**静默丢弃**，
    // `connect()` 会无限等待，把 20s 总预算架空 ⇒ 用例永久挂起。
    for _ in 0..80 {
        match crate::support::with_attempt_timeout(HysteriaClient::connect(config(&world))).await {
            Ok(Ok(_)) => return world,
            Ok(Err(_)) => {}
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "xray 20s 内未就绪；参考服务端日志:\n{}",
        crate::support::server_logs(&world.dir)
    );
}

/// 本地 TCP echo（回环目标；参考的 freedom 出站）。
///
/// 自终止形状：收满 `expected` 字节 → 原样回写 → 关闭。不依赖「客户端
/// FIN 能传到 echo」（参考的 freedom 出站在入站流 EOF 时只结束拷贝，
/// 不对目标 TCP 调 `CloseWrite`），否则回程永远等不到 EOF。
async fn spawn_tcp_echo(expected: usize) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 echo 端口");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
        let mut got = 0usize;
        while got < expected {
            let want = (expected - got).min(buf.len());
            match sock.read(&mut buf[..want]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    got += n;
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sock.shutdown().await;
    });
    addr
}

/// 同一客户端配置连两次：第一次落票据，第二次尝试 0-RTT。
///
/// **取证语义**（不是「要求参考接受 0-RTT」）：参考服务端**结构上不授予
/// 早数据许可** —— 参考 Xray 的 `quic.Config` 字面量未设 `Allow0RTT`
/// （quic-go 默认关闭该开关），于是它下发的 TLS 1.3 会话票据
/// **不带早数据许可**（`max_early_data_size == 0`）⇒ 本端 `into_0rtt`
/// 无早数据可发 ⇒ 第二次连接落入 `NotAttempted`。
///
/// 因此本用例断言的是**「参考侧不支持 ⇒ 如实回退 1-RTT 且业务不中断」**
/// 这条正解，而不是把参考侧未实现的能力当成本仓缺陷：
/// - 服务端票据早数据上限 == `Some(0)`（参考侧不支持的直接证据）；
/// - 第二次连接的 0-RTT 结果**不是** `Accepted`（实测 `NotAttempted`）；
/// - 第二次连接**仍能**完成握手并正常转发业务（回退 1-RTT，业务不中断）；
/// - 全程 TLS（对端证书已校验、ALPN 仍为 h3），不因 0-RTT 不可用而跳过 TLS。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn xray_0rtt_second_connection() {
    let world = start_world("second").await;
    let cache = Arc::new(MemorySessionCache::new(16));
    let early = EarlyDataConfig {
        enabled: true,
        ..Default::default()
    };

    // 第一次：无票据，into_0rtt 应回退 1-RTT；握手后服务端下发票据。
    let first =
        HysteriaClient::connect_with_session_cache(config(&world), early.clone(), cache.clone())
            .await
            .expect("第一次建连失败");
    assert_eq!(
        first.zero_rtt_outcome().await,
        ZeroRttOutcome::NotAttempted,
        "首次连接无票据，不得宣称 0-RTT"
    );

    let name = ServerName::try_from(SERVER_NAME.to_owned()).unwrap();
    let mut tickets = 0;
    for _ in 0..100 {
        tickets = cache.ticket_count(&name);
        if tickets > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        tickets > 0,
        "第一次连接后未收到 TLS 1.3 会话票据，无法尝试 0-RTT"
    );
    // 证据：票据**存在**，但**未授予早数据权限** ⇒ 参考侧不发 0-RTT 许可
    // （参考的 quic.Config 未设 Allow0RTT）。这一条把「参考侧不支持」
    // 钉成可复现的事实，而不是靠注释断言。
    let max_early_data = cache.ticket_max_early_data(&name);
    println!("票据数={tickets}，服务端票据早数据上限={max_early_data:?}");
    assert_eq!(
        max_early_data,
        Some(0),
        "参考服务端未授予 0-RTT 早数据许可（票据早数据上限必须为 0）"
    );
    first.connection().close(quinn::VarInt::from_u32(0), b"");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 第二次：同一缓存命中票据，进入 into_0rtt 并立即发送认证。
    let before = cache.ticket_count(&name);
    let second = tokio::time::timeout(
        Duration::from_secs(20),
        HysteriaClient::connect_with_session_cache(config(&world), early, cache.clone()),
    )
    .await
    .expect("第二次建连超时")
    .expect("第二次建连失败");
    let after = cache.ticket_count(&name);
    let outcome = second.zero_rtt_outcome().await;
    // 票据被取走（before > after）说明 rustls 确实尝试了会话恢复；
    // 若此时 into_0rtt 仍返回 Err，则卡点在于服务端票据未授予早数据权限。
    println!("票据 before={before} after={after}；第二次连接 0-RTT 结果: {outcome:?}");
    assert_ne!(
        outcome,
        ZeroRttOutcome::Accepted,
        "参考服务端未开启 0-RTT 许可，第二次连接不得宣称早数据被接受"
    );
    assert_eq!(
        outcome,
        ZeroRttOutcome::NotAttempted,
        "本端无早数据许可（票据 max_early_data_size=0）⇒ 未尝试 0-RTT"
    );

    // 全程 TLS：ALPN 仍协商出 h3（说明 TLS 握手确实完成、证书已按注入的
    // 根证书校验过），且本端没因 0-RTT 不可用而跳过 TLS / 降级明文。
    let handshake = second
        .connection()
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .expect("0-RTT 不可用也不得跳过 TLS 握手");
    assert_eq!(
        handshake.protocol.as_deref(),
        Some(&b"h3"[..]),
        "ALPN 必须仍为 h3（不得因 0-RTT 不可用而降级）"
    );
    // 对端证书：本端已按注入的根证书做过完整验证链校验（证书不匹配时
    // 握手根本不会成功），这里再确认一次「确实拿到了对端证书」。
    let peer_certs = second
        .connection()
        .peer_identity()
        .and_then(|d| {
            d.downcast::<Vec<quinn::rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .expect("必须完成证书校验");
    assert!(
        !peer_certs.is_empty(),
        "必须完成 TLS 握手并校验对端证书（不得因 0-RTT 不可用而跳过 TLS）"
    );

    // 业务不中断：回退 1-RTT 后业务转发照常可用。
    let payload: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let echo_addr = spawn_tcp_echo(payload.len()).await;
    let mut stream = proxy::tcp_connect(&second, &echo_addr.to_string())
        .await
        .expect("回退 1-RTT 后业务转发必须可用");
    stream.write_all(&payload).await.expect("写入载荷失败");
    stream.finish().expect("半关闭失败");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = stream.read(&mut buf).await {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, payload, "回退 1-RTT 后的业务数据必须原样往返");
}
