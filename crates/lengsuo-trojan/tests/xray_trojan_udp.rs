//! Rust Trojan UDP 客户端 → **真实 Xray Trojan 服务端** 的 UDP 关联互通（默认忽略）。
//!
//! 三个用例（A/B/C）都要求 `LENGSUO_XRAY` 指向固定基线 `~/ref/bin/xray`
//! （`support::launch` 会断言版本 26.3.27 / d2758a0）。证书用 `openssl` 现场自签，
//! 显式信任，不跳过校验。观测面取自**真实 UDP 回显后端**：
//! 后端在 Xray 侧经 `freedom` 出站抵达，回程必须经 Trojan UDP 帧原样回到 Rust。
//!
//! - A：1 / 512 / 8192 三档载荷经 Xray UDP echo 逐字节回环。
//! - B：同一关联内先后打两个不同目标的独立 UDP 回显，回程地址不得是首包地址。
//! - C：错误密码：Xray 不得建立 UDP 关联，且回显后端零收包（独立观测面），
//!   连接观察到被主动断开；用正确密码同配置对照组证明观测面有效。

mod support;

use std::path::PathBuf;
use std::process::Command as Process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::{CertificateDer, TlsClient};
use lengsuo_trojan::stream::{receive_datagram, send_datagram};
use lengsuo_trojan::Command;
use lengsuo_trojan::{codec, Credential, Request, TargetAddr};
use serde_json::{json, Value};
use support::{free_port, launch, WAIT};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const PASSWORD: &str = "trojan-udp-interop-password";
const BAD_PASSWORD: &str = "trojan-udp-interop-wrong";
const TOTAL: Duration = Duration::from_secs(60);
/// 实测参考服务端 UDP 回显的稳定最大载荷：8180 字节。Xray 的 `PacketReader` 把整帧
/// 读入 `buf.Size = 8192` 的缓冲，帧头（地址 7 + 长度 2 + CRLF 2 = 11）占用后余量
/// 有限，边界附近（8182 起）回程开始不稳定失败——这是**参考侧**上限，不是本仓限制；
/// 本仓 `udp::MAX_PAYLOAD_LEN` 仍按协议线上的 65535。三档取 1 / 512 / 该实测值，
/// 覆盖参考实际能稳定回显的最长帧。
const REF_MAX: usize = 8180;

/// 现场用 openssl 自签的一组证书/私钥文件，Drop 时删除临时目录。
struct Certs {
    directory: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    der: CertificateDer<'static>,
}

impl Certs {
    fn generate() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "lengsuo-trojan-udp-{}-{}",
            std::process::id(),
            free_port()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let cert = directory.join("cert.pem");
        let cert_der = directory.join("cert.der");
        let key = directory.join("key.pem");
        // 现场自签：CN=localhost + SAN=DNS:localhost，显式声明为叶子证书
        // （OpenSSL 3 的 `-x509` 默认加 basicConstraints=CA:TRUE，rustls 会以
        // CaUsedAsEndEntity 拒绝）。证书即自签根，客户端显式信任其 DER。
        let status = Process::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext",
                "extendedKeyUsage=serverAuth",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("必须能调用 openssl 现场自签");
        assert!(status.success(), "openssl 自签失败");
        // 另存 DER 供 Rust 客户端显式信任（rustls 要 DER，不是 PEM 文本）。
        let status = Process::new("openssl")
            .args(["x509", "-in"])
            .arg(&cert)
            .args(["-outform", "der", "-out"])
            .arg(&cert_der)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("必须能调用 openssl 转 DER");
        assert!(status.success(), "openssl 转 DER 失败");
        let der = CertificateDer::from(std::fs::read(&cert_der).unwrap());
        Self {
            directory,
            cert,
            key,
            der,
        }
    }

    fn client(&self) -> TlsClient {
        TlsClient::new("localhost", [self.der.clone()], WAIT).unwrap()
    }

    /// Xray 服务端 TLS 设置：直接给文件路径，由 Xray 自己读取证书与私钥。
    fn server_settings(&self) -> Value {
        json!({"security":"tls","tlsSettings":{"certificates":[{
            "certificateFile": self.cert.to_string_lossy(),
            "keyFile": self.key.to_string_lossy() }]}})
    }
}

impl Drop for Certs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// 独立 UDP 回显后端：原样回写收到的数据报，`received` 计数包数。
async fn spawn_udp_echo() -> (u16, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let counter = Arc::new(AtomicUsize::new(0));
    let seen = counter.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (port, counter)
}

/// Xray Trojan 入站（network: udp）+ freedom 出站；`listen_port` 为入站端口。
fn xray_config(port: u16, password: &str, certs: &Certs) -> Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
            "settings":{"clients":[{"password":password}]},
            "streamSettings":certs.server_settings()}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 打开一条 Trojan UDP 关联：TLS 连接 + command=0x03 请求头。
/// 返回 `lengsuo-tls` 决定的具体流类型（调用方按 `AsyncRead + AsyncWrite` 使用）。
async fn open_association(
    certs: &Certs,
    port: u16,
    password: &str,
) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    let mut stream = certs
        .client()
        .connect((std::net::Ipv4Addr::LOCALHOST, port).into())
        .await
        .unwrap();
    let request = Request {
        command: Command::Udp,
        target: TargetAddr::V4([0, 0, 0, 0], 0),
    };
    lengsuo_trojan::stream::send_request(&mut stream, &request, &Credential::new(password), WAIT)
        .await
        .unwrap();
    stream
}

/// A：三档载荷经 Xray UDP echo 逐字节回环。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn udp_associate_echo_three_sizes() {
    timeout(TOTAL, async {
        let certs = Certs::generate();
        let (echo_port, _seen) = spawn_udp_echo().await;
        let port = free_port();
        let reference = launch(xray_config(port, PASSWORD, &certs), port).await;

        let mut stream = open_association(&certs, port, PASSWORD).await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);
        for size in [1usize, 512, REF_MAX] {
            let payload = vec![0x42u8; size];
            send_datagram(&mut stream, &target, &payload, WAIT)
                .await
                .unwrap();
            let (address, packet) = receive_datagram(&mut stream, 65535, WAIT).await.unwrap();
            assert_eq!(address, target, "{size} 字节：回程地址须与请求一致");
            assert_eq!(packet, payload, "{size} 字节：回程须逐字节一致");
        }
        drop(stream);
        drop(reference);
    })
    .await
    .unwrap();
}

/// B：同一关联内先后打两个不同目标的独立 UDP 回显，回程地址不得缓存首包地址。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn udp_associate_two_targets_same_session() {
    timeout(TOTAL, async {
        let certs = Certs::generate();
        let (first_port, first_seen) = spawn_udp_echo().await;
        let (second_port, second_seen) = spawn_udp_echo().await;
        let port = free_port();
        let reference = launch(xray_config(port, PASSWORD, &certs), port).await;

        let mut stream = open_association(&certs, port, PASSWORD).await;
        for (echo_port, tag) in [(first_port, 0x11u8), (second_port, 0x22u8)] {
            let target = TargetAddr::V4([127, 0, 0, 1], echo_port);
            let payload = vec![tag; 16];
            send_datagram(&mut stream, &target, &payload, WAIT)
                .await
                .unwrap();
            let (address, packet) = receive_datagram(&mut stream, 65535, WAIT).await.unwrap();
            assert_eq!(address, target, "第 {tag:#x} 包回程地址不得被首包地址覆盖");
            assert_eq!(packet, payload);
        }
        // 两个独立后端各收到恰一个包：证明确实是两个不同目标，不是同一后端复用。
        assert_eq!(first_seen.load(Ordering::SeqCst), 1, "首目标须收到一包");
        assert_eq!(second_seen.load(Ordering::SeqCst), 1, "次目标须收到一包");
        drop(stream);
        drop(reference);
    })
    .await
    .unwrap();
}

/// C：错误密码时 UDP 关联被拒；用正确密码对照组证明观测面有效。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn udp_associate_wrong_password_rejected() {
    timeout(TOTAL, async {
        let certs = Certs::generate();
        let (echo_port, seen) = spawn_udp_echo().await;
        let port = free_port();
        let reference = launch(xray_config(port, PASSWORD, &certs), port).await;

        // 对照组：正确密码真的建立关联并把包送到业务后端。
        {
            let mut stream = open_association(&certs, port, PASSWORD).await;
            let target = TargetAddr::V4([127, 0, 0, 1], echo_port);
            send_datagram(&mut stream, &target, b"probe", WAIT)
                .await
                .unwrap();
            let (address, packet) = receive_datagram(&mut stream, 65535, WAIT).await.unwrap();
            assert_eq!(address, target);
            assert_eq!(packet, b"probe");
        }
        assert_eq!(seen.load(Ordering::SeqCst), 1, "对照组必须抵达业务后端");

        // 错误密码：Xray 不得建立关联——回环回显零收包，且连接被主动断开。
        let before = seen.load(Ordering::SeqCst);
        let mut stream = certs
            .client()
            .connect((std::net::Ipv4Addr::LOCALHOST, port).into())
            .await
            .unwrap();
        let target = TargetAddr::V4([127, 0, 0, 1], echo_port);
        // 用错误密码写请求头；随后报文本可能被 TLS 接受或直接断开，两种都必须 fail-closed。
        let bad = codec::encode(
            &Request {
                command: Command::Udp,
                target: TargetAddr::V4([0, 0, 0, 0], 0),
            },
            &Credential::new(BAD_PASSWORD),
        )
        .unwrap();
        let wrote = async {
            use tokio::io::AsyncWriteExt;
            stream.write_all(&bad).await?;
            stream.flush().await?;
            send_datagram(&mut stream, &target, b"leak", WAIT).await
        }
        .await;
        // 无论写是否成功，读侧必须观察到主动断开（而不是静默回显）。
        let mut buf = [0u8; 64];
        let closed = match timeout(WAIT, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => true,
            Ok(Ok(_)) => false,
            Err(_) => panic!("错误密码连接必须在观察上限内被主动断开"),
        };
        assert!(closed, "错误密码必须导致连接被断开（写了 {wrote:?}）");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            seen.load(Ordering::SeqCst),
            before,
            "错误密码不得把包送到业务后端"
        );
        drop(reference);
    })
    .await
    .unwrap();
}
