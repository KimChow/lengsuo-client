// `#[ignore]` 参考互通：官方 anytls-client v0.0.13 → 本仓服务端。
//
// 方向说明：本卡交付的是**服务端**承载，因此参考对手方是官方**客户端**。
// （本仓客户端 → 官方服务端的方向已由 `tests/interop_udp.rs` 覆盖，不在此重复。）
//
// 链路：官方客户端 SOCKS5 UDP ASSOCIATE →
//   `cmd/client/inbound.go::NewPacketConnection`（`uot.RequestDestination(2)` + `uot.NewLazyConn`）
//   → TLS → 本仓 `server::serve`（`src/server/udp.rs` 承载）→ 本机 UDP echo → 原路回程。
//
// 这不是自家 roundtrip：UoT 线格式两端各自独立实现，字节不一致立刻失败。
//
// ⚠️ 官方客户端固定 `InsecureSkipVerify=true`（示例客户端），故本用例只证明
// 「协议/UoT 线格式互通」，**不**证明证书校验（那条由 Rust↔Rust 用例覆盖）。
//
// 默认 `#[ignore]`；需要 `LENGSUO_ANYTLS` 指向官方 `anytls-client` 与 `openssl`。
use std::path::PathBuf;
use std::process::{Child, Stdio};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// 互通用例的等待上限（进程启动 + 两次握手）。
const INTEROP_WAIT: Duration = Duration::from_secs(10);
/// 参考客户端环境变量：与仓库既有互通用例一致。
const BIN_ENV: &str = "LENGSUO_ANYTLS";

/// 参考客户端路径。`LENGSUO_ANYTLS` 可以是二进制本身，也可以是含它的目录。
fn client_binary() -> PathBuf {
    let path = std::env::var(BIN_ENV)
        .unwrap_or_else(|_| "/home/ubuntu/ref/bin/anytls/anytls-client".to_owned());
    let path = PathBuf::from(path);
    let binary = if path.is_dir() {
        path.join("anytls-client")
    } else {
        path
    };
    assert!(
        binary.is_file(),
        "参考客户端不存在：{}（设置 {BIN_ENV}）",
        binary.display()
    );
    binary
}

/// 参考客户端子进程守卫：drop 时 kill 并回收。
struct ClientProcess(Child);

impl Drop for ClientProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 测试用一次 PKI：自签叶子证书（官方客户端跳过校验，无需 CA 链）。
///
/// 全部为一次性测试凭据：回环、1 天有效、临时目录，用后即删，不提交仓库。
struct Pki {
    chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    key: Vec<u8>,
    dir: PathBuf,
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_openssl(args: &[&str]) {
    let output = std::process::Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl 不可用");
    assert!(
        output.status.success(),
        "openssl {:?} 失败：{}",
        args.first().unwrap_or(&""),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn test_pki() -> Pki {
    let dir =
        std::env::temp_dir().join(format!("lengsuo-uot-server-interop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("建临时目录");
    let path = |name: &str| dir.join(name).to_str().unwrap_or_default().to_owned();
    run_openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &path("key.pem"),
        "-out",
        &path("cert.pem"),
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]);
    run_openssl(&[
        "x509",
        "-in",
        &path("cert.pem"),
        "-outform",
        "DER",
        "-out",
        &path("cert.der"),
    ]);
    run_openssl(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        &path("key.pem"),
        "-outform",
        "DER",
        "-out",
        &path("key.der"),
    ]);
    let cert = std::fs::read(dir.join("cert.der")).expect("读证书");
    let key = std::fs::read(dir.join("key.der")).expect("读私钥");
    Pki {
        chain: vec![tokio_rustls::rustls::pki_types::CertificateDer::from(cert)],
        key,
        dir,
    }
}

/// 起本仓 TLS 服务端（`server::tls` + `server::serve`），返回监听端口。
async fn start_server(password: &[u8], pki: &Pki) -> u16 {
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let acceptor = server::tls::acceptor(
        pki.chain.clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.clone())),
    )
    .expect("TLS 接受器");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听回环");
    let port = listener.local_addr().expect("读取端口").port();
    let password = password.to_vec();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let password = password.clone();
            tokio::spawn(async move {
                // 握手失败即断开（无明文回退）。
                if let Ok(stream) = server::tls::handshake(&acceptor, socket, INTEROP_WAIT).await {
                    let _ = server::serve(stream, ServerConfig::new(&password, INTEROP_WAIT)).await;
                }
            });
        }
    });
    port
}

/// 分配一个空闲回环 TCP 端口（临时监听后立即释放）。
fn free_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("分配端口");
    socket.local_addr().expect("读取端口").port()
}

/// 轮询等待端口可连（参考客户端启动后才会监听）。
async fn wait_listening(addr: SocketAddr) {
    let started = std::time::Instant::now();
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(
            started.elapsed() < INTEROP_WAIT,
            "参考客户端未在期限内监听 {addr}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// 读一个 SOCKS5 地址（ATYP 已在调用方之后）。
async fn read_socks_addr<R: AsyncReadExt + Unpin>(stream: &mut R) -> SocketAddr {
    let atyp = stream.read_u8().await.expect("读 ATYP");
    let ip = match atyp {
        0x01 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await.expect("读 IPv4");
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(raw))
        }
        0x04 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await.expect("读 IPv6");
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(raw))
        }
        other => panic!("参考客户端回程地址族非预期：0x{other:02X}"),
    };
    let port = stream.read_u16().await.expect("读端口");
    SocketAddr::from((ip, port))
}

/// 对参考客户端完成 SOCKS5 无认证 + UDP ASSOCIATE，返回控制连接与中继地址。
async fn socks5_udp_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut tcp = TcpStream::connect(proxy)
        .await
        .expect("连参考客户端 SOCKS 入口");
    tcp.write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("SOCKS 问候");
    let mut hello = [0u8; 2];
    tcp.read_exact(&mut hello).await.expect("读问候应答");
    assert_eq!(hello, [0x05, 0x00], "参考客户端应选择无认证");
    // UDP ASSOCIATE，目的地址 0.0.0.0:0（sing 只把它记作 metadata）。
    tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("UDP ASSOCIATE");
    let mut head = [0u8; 3];
    tcp.read_exact(&mut head).await.expect("读 ASSOCIATE 应答");
    assert_eq!((head[0], head[1]), (0x05, 0x00), "UDP ASSOCIATE 应成功");
    let bind = read_socks_addr(&mut tcp).await;
    (tcp, bind)
}

/// 发一个 SOCKS5 UDP 报文到参考客户端的中继地址，返回回程载荷。
async fn udp_echo_once(bind: SocketAddr, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("UDP 客户端");
    let mut packet = vec![0x00, 0x00, 0x00];
    match target {
        SocketAddr::V4(v4) => {
            packet.push(0x01);
            packet.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            packet.push(0x04);
            packet.extend_from_slice(&v6.ip().octets());
        }
    }
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    socket.send_to(&packet, bind).await.expect("发送 UDP 报文");

    let mut buffer = vec![0u8; 65535];
    let (count, _) = timeout(INTEROP_WAIT, socket.recv_from(&mut buffer))
        .await
        .expect("等待 UDP 回程超时")
        .expect("读 UDP 回程");
    // 回程 = [RSV(2)][FRAG(1)][ATYP][addr][port][payload]。
    assert_eq!(&buffer[..3], &[0, 0, 0], "回程 RSV/FRAG 应为 0");
    let addr_len = match buffer[3] {
        0x01 => 4,
        0x04 => 16,
        other => panic!("回程地址族非预期：0x{other:02X}"),
    };
    buffer[3 + 1 + addr_len + 2..count].to_vec()
}

/// 官方 anytls-client → 本仓服务端：UDP-over-TCP（v2）单报文往返。
///
/// 断言：官方客户端发出的 UoT 报文经本仓服务端到达 UDP echo，回程逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_ANYTLS 指向官方 anytls-client，以及 openssl"]
async fn official_client_udp_over_tcp_reaches_repo_server() {
    let client = client_binary();
    let password = std::str::from_utf8(PASSWORD).expect("口令为 ASCII");
    let pki = test_pki();
    let server_port = start_server(PASSWORD, &pki).await;
    let echo = spawn_udp_echo("127.0.0.1:0").await;
    let socks_port = free_port();
    let log_path = pki.dir.join("client.log");
    let log = std::fs::File::create(&log_path).expect("创建日志文件");
    let stderr = log.try_clone().expect("复制日志句柄");

    let process = ClientProcess(
        std::process::Command::new(&client)
            .args([
                "-l",
                &format!("127.0.0.1:{socks_port}"),
                "-s",
                &format!("127.0.0.1:{server_port}"),
                "-p",
                password,
                "-sni",
                "localhost",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap_or_else(|err| panic!("启动参考客户端失败：{err}")),
    );

    wait_listening(SocketAddr::from(([127, 0, 0, 1], socks_port))).await;
    let (control, bind) =
        socks5_udp_associate(SocketAddr::from(([127, 0, 0, 1], socks_port))).await;
    let payload = b"uot-v2-official-client-roundtrip";
    let got = udp_echo_once(bind, echo, payload).await;
    assert_eq!(
        got, payload,
        "官方客户端 ↔ 本仓服务端的 UDP-over-TCP 回程应逐字节一致"
    );

    drop(control);
    drop(process);
    let text = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!text.contains(password), "参考客户端日志不得输出口令");
    println!("interop: 官方 anytls-client ↔ 本仓服务端 UoT v2 往返逐字节一致");
}
