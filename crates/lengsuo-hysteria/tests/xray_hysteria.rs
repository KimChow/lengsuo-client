//! 与参考 Xray 服务端（`LENGSUO_XRAY` 指定的二进制）的真实互通验收。
//! 全部 `#[ignore]`：须用 `--ignored` 实跑，禁止用自家 roundtrip 冒充。
//!
//! 服务端形态：inbound `hysteria`（version=2、clients.auth）、
//! streamSettings `network=hysteria` + `security=tls`（ALPN=h3、openssl
//! 现场自签证书进临时目录）、masquerade 缺省 404；outbound freedom。
//!
//! - 用例 A：TCP echo，1B / 4KiB / 256KiB 三档。
//! - 用例 B：UDP 往返（发送经 `h3_auth::SeedFiller` 桥，依赖冻结的
//!   bytes 限制见 docs 偏离清单）。
//! - 用例 C：错误 auth 被拒（期望 masquerade 404）。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::{ClientConfig, ConnectError, HysteriaClient};

mod support;

const AUTH: &str = "lengsuo-interop-password";
const SERVER_NAME: &str = "localhost";
/// 用例 A 的三档 echo 载荷。
const TCP_ECHO_SIZES: [usize; 3] = [1, 4 * 1024, 256 * 1024];

fn xray_bin() -> PathBuf {
    let path = std::env::var_os("LENGSUO_XRAY")
        .map(PathBuf::from)
        .expect("环境变量 LENGSUO_XRAY 未设置（参考 /home/ubuntu/ref/bin/xray）");
    assert!(path.is_file(), "LENGSUO_XRAY 指向的文件不存在: {path:?}");
    path
}

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hysteria-{}-{}", tag, std::process::id()));
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
            // rustls/webpki 拒绝把 CA:TRUE 的自签证书当终端实体
            // （CaUsedAsEndEntity），也要求 serverAuth EKU
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

/// 证书 DER 形式（rustls 根证书注入用）。
fn cert_der(cert: &Path, dir: &Path) -> Vec<u8> {
    let der_path = dir.join("cert.der");
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-outform", "DER"])
        .arg("-out")
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
    "settings": {{
      "version": 2,
      "clients": [{{"auth": "{AUTH}", "email": "interop@lengsuo"}}]
    }},
    "streamSettings": {{
      "network": "hysteria",
      "hysteriaSettings": {{"version": 2, "auth": "{AUTH}"}},
      "security": "tls",
      "tlsSettings": {{
        "serverName": "{SERVER_NAME}",
        "alpn": ["h3"],
        "certificates": [{{"certificateFile": "{}", "keyFile": "{}"}}]
      }}
    }}
  }}],
  "outbounds": [{{"protocol": "freedom"}}]
}}"#,
        // ⚠️ 必须 JSON 转义：Windows 路径 `C://Users//...` 的反斜杠
        // 未转义会让 Xray 直接拒绝配置（`invalid character 'U' in string
        // escape code`）⇒ 服务端根本没起来，Linux 路径无反斜杠所以一直掩盖。
        support::json_escape(&cert.to_string_lossy()),
        support::json_escape(&key.to_string_lossy())
    )
}

/// 一个独立的一次性 Xray 服务端世界（证书、配置、进程）。
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

async fn start_world(tag: &str) -> (World, HysteriaClient) {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let port = free_udp_port();
    let cfg_path = dir.join("xray.json");
    std::fs::write(&cfg_path, xray_config(port, &cert, &key)).expect("写 xray 配置");
    let log_out = std::fs::File::create(dir.join("xray-stdout.log")).expect("建日志文件");
    let log_err = std::fs::File::create(dir.join("xray-stderr.log")).expect("建日志文件");
    let child = Command::new(xray_bin())
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("启动 xray");
    let world = World {
        child,
        port,
        cert_der: der,
        dir,
    };
    // 就绪探测：用正确 auth 反复完整建连（握手 + H3 认证）。
    //
    // ⚠️ 单次尝试自带墙钟上限：Windows 上向未监听端口发 UDP 是**静默丢弃**
    // （不是 ECONNREFUSED），`connect()` 会无限等一个不会到的回应，把 20s
    // 总预算完全架空 ⇒ 整条用例永久挂起（CI 表现：600s 超时）。
    //
    // ⚠️⚠️ 探测成功的那条连接**必须复用**，不能丢掉重建：
    // `HysteriaClient` 持有 `quinn::Endpoint`，而 quinn 的 `Endpoint` 是
    // **spawn 型任务**——被 drop 时会把该 endpoint 上所有连接的收发任务一起
    // 终止。第一版把探测结果丢进 `Ok(_)` 就返回，等于刚连上就掐断，
    // 后续 `tcp_connect` 永远等不到服务端。
    let mut last_err = String::new();
    for _ in 0..80 {
        match support::with_attempt_timeout(connect_with(&world, AUTH)).await {
            Ok(Ok(client)) => return (world, client),
            Ok(Err(e)) => last_err = format!("{e}"),
            Err(_) => {
                last_err = format!(
                    "单次建连超过 {}s 无响应",
                    support::PROBE_ATTEMPT_TIMEOUT.as_secs()
                )
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "xray 20s 内未就绪；最后一次探测错误: {last_err}；参考服务端日志:\n{}",
        support::server_logs(&world.dir)
    );
}

fn client_config(world: &World, auth: &str) -> ClientConfig {
    ClientConfig {
        server_addr: SocketAddr::from(([127, 0, 0, 1], world.port)),
        server_name: SERVER_NAME.to_string(),
        auth: auth.to_string(),
        roots_der: vec![world.cert_der.clone()],
        brutal_down: 0,
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    }
}

async fn connect_with(world: &World, auth: &str) -> Result<HysteriaClient, ConnectError> {
    HysteriaClient::connect(client_config(world, auth)).await
}

/// 本地 TCP echo 服务器（freedom 出站的真实回环目标）。
///
/// **自终止形状**：收满 `expected` 字节 → 原样回写 → `shutdown`。
/// 不依赖「客户端 FIN 能传到本 echo」——参考 Xray 的 freedom `requestDone`
/// 在入站流 EOF 时**只结束拷贝，不对目标 TCP 调 `CloseWrite`**
/// （`proxy/freedom/freedom.go` 的 `requestDone` 结尾只有 `return nil`），
/// 所以 FIN 到不了 echo；若 echo 等客户端关闭才收工，回程就永远收不到 EOF，
/// 用例必然超时。这正是「跟参考实现一致」的语义要求。
async fn spawn_tcp_echo(expected: usize) -> SocketAddr {
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
                let mut got = 0usize;
                loop {
                    if got >= expected {
                        let _ = sock.shutdown().await;
                        return;
                    }
                    let want = expected.saturating_sub(got).min(buf.len());
                    match sock.read(&mut buf[..want]).await {
                        Ok(0) | Err(_) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            got += n;
                            if sock.write_all(&buf[..n]).await.is_err() {
                                let _ = sock.shutdown().await;
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

/// 用例 A：TCP echo 三档载荷经 Xray 往返。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn a_tcp_echo_through_xray() {
    // 就绪探测成功的那条连接直接复用（端点被 drop 会连带杀掉连接）。
    let (_world, client) = start_world("tcp-a").await;
    for size in TCP_ECHO_SIZES {
        let echo_addr = spawn_tcp_echo(size).await;
        let payload = pattern(size);
        let fut = async {
            let mut stream = proxy::tcp_connect(&client, &echo_addr.to_string())
                .await
                .expect("tcp_connect 失败");
            stream.write_all(&payload).await.expect("写入载荷失败");
            stream.finish().expect("半关闭失败");
            let mut got = Vec::with_capacity(size);
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("读取回包失败");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            got
        };
        let got = tokio::time::timeout(Duration::from_secs(30), fut)
            .await
            .expect("echo 超时");
        assert_eq!(got.len(), payload.len(), "回包长度不符（size={size}）");
        assert_eq!(got, payload, "回包内容不符（size={size}）");
    }
}

/// 用例 B：UDP 往返。发送走 SeedFiller 桥（复用认证/接收路径的独占
/// `Bytes` 缓冲；依赖冻结无法直接构造 `bytes::Bytes`，见偏离清单）。
/// 若种子耗尽会得到 `NoSeedBuffer`——失败时不得宣称 UDP 互通。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn b_udp_roundtrip_through_xray() {
    // 复用就绪探测成功的那条连接（端点被 drop 会连带杀掉连接）。
    let (_world, client) = start_world("udp-b").await;
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("绑定本地 UDP echo");
    let echo_addr = echo.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            if echo.send_to(&buf[..n], from).await.is_err() {
                return;
            }
        }
    });
    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    let payload = pattern(64);
    let addr_bytes = echo_addr.to_string().into_bytes();
    let dgrams =
        proxy::udp_out_datagrams(session.id, &addr_bytes, &payload, 1200).expect("组 UDP datagram");
    assert_eq!(dgrams.len(), 1);
    session
        .send_raw(&dgrams[0])
        .expect("UDP 发送失败（种子耗尽或对端拒绝，见 docs/hysteria-status.md）");
    let mut defrag = proxy::OwnedDefragger::default();
    let got = tokio::time::timeout(
        Duration::from_secs(10),
        proxy::udp_recv(&mut session, &mut defrag),
    )
    .await
    .expect("等待 UDP 回包超时")
    .expect("会话关闭")
    .expect("UDP 报文解析失败");
    assert_eq!(got.data, payload);
}

/// 用例 C：错误 auth 被拒（masquerade 缺省 404）。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn c_wrong_auth_rejected() {
    // `_ready` 只是就绪探测留下的健康连接；错误 auth 必须**新开**一条。
    let (world, _ready) = start_world("auth-c").await;
    let err = match connect_with(&world, "definitely-wrong-password").await {
        Err(e) => e,
        Ok(_) => panic!("错误 auth 不应建连成功"),
    };
    let status = err
        .rejected_status()
        .unwrap_or_else(|| panic!("错误 auth 应表现为认证被拒（HTTP 状态），实际: {err:?}"));
    assert_eq!(status, 404, "masquerade 缺省应回 404，实际 {status}");
}
