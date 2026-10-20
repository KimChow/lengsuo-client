//! 本仓 REALITY 客户端 → 固定参考 REALITY **服务端** 的互通用例。
//!
//! 客户端编排照搬 `tests/reality_e2e/support/e2e.rs`：
//! `build_reality_client_hello` → `RealityClient::from_built` → 发 ClientHello →
//! `client_handshake` → `RecordReader`/`RecordWriter` 收发应用数据。
//!
//! 服务端由参考二进制提供（门禁经 `LENGSUO_XRAY` 注入，例如
//! `LENGSUO_XRAY=/path/to/xray`），入站为 `vless` + `security: "reality"`：
//!
//! ```json
//! {"inbounds":[{"protocol":"vless","port":<N>,
//!   "streamSettings":{"security":"reality","realitySettings":{
//!     "show":false,"dest":"<回环 TLS 目标>","xver":0,
//!     "serverNames":["www.example.com"],"privateKey":"<base64url>",
//!     "shortIds":["<16 位十六进制 = 8 字节短 ID>"]}}}],
//!  "outbounds":[{"protocol":"freedom"}]}
//! ```
//!
//! 全部用例 `#[ignore]`：没有参考二进制时跑不出任何结论。运行：
//!
//! ```sh
//! LENGSUO_XRAY=/path/to/xray \
//!   cargo test -p lengsuo-vless --test reality_xray_server -- --ignored --nocapture
//! ```
//!
//! **硬约束**：只用回环地址、临时端口、运行时生成的假凭据；日志不输出私钥。
//!
//! 参考配置要点（逐条对齐 `transport/internet/reality/config.go`）：
//! `shortIds` 是**十六进制字符串**，解析成 `[8]byte` 键；`privateKey` 取
//! base64 raw-url **无 padding**。首轮实跑把短 ID 写成了 `"12345678"`（8 字节
//! 不是 16 个十六进制字符）：参考静默接受配置，认证通过后按 0 字节键查表失败，
//! 把本已认证的连接镜像转发到 `dest`。正例随即可见地失败（客户端拿到的不是
//! REALITY 证书），因此本文件用 `HEX_SHORT_ID`，并在正例里断言对端是 REALITY
//! 伪造的 Ed25519 证书。
//!
//! 端口：`free_ports` 一次预留服务端与 dest 的端口；客户端与 echo 使用
//! `TcpListener` 绑定后的真实端口。每个网络操作都有截止时间，整用例 ≤ 30s。

/// 启动夹具子模块（见 `reality_xray_server/fixture.rs`）。
mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lengsuo_vless::header::{self, Command, Request};
use lengsuo_vless::reality::client::{
    build_reality_client_hello, parse_reality_certificate, BuiltClientHello, RealityClient,
};
use lengsuo_vless::reality::hash::sha::sha256;
use lengsuo_vless::reality::session::client_handshake;
use lengsuo_vless::reality::tls13::io::{Inbound, Outbound, RecordReader, RecordWriter};
use lengsuo_vless::reality::x25519::x25519_base;
use lengsuo_vless::reality::ClientVersion;
use serde_json::json;
use ss_core::target::TargetAddr;
use support::{free_ports, launch, ID, KEY, WAIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 用例总截止时间（卡片要求 ≤ 30s）。
const DEADLINE: Duration = Duration::from_secs(30);
/// 客户端 TLS 1.3 飞行截止时间。
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const SERVER_NAME: &str = "www.example.com";
const SHORT_ID: [u8; 8] = *b"12345678";
/// 参考 `realitySettings.shortIds` 是**十六进制字符串**，配置解析时转成 8 字节
/// 键（`transport/internet/reality/config.go`：`*(*[8]byte)(shortId)`），
/// 即 JSON 里的短 ID 字节数必须是 16。
const HEX_SHORT_ID: &str = "3132333435363738";
/// 不在参考 `shortIds` 白名单内的短 ID。
const WRONG_SHORT_ID: [u8; 8] = *b"87654321";
const PAYLOAD: &[u8] = b"reality->reference payload\0\xff\xfe binary";

/// base64 raw-url（RFC 4648 §5，无 padding）。参考 `realitySettings.privateKey`
/// 用这一编码；crate 内无 base64 依赖，测试侧自带。
fn base64_url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 0x3f] as char);
        }
    }
    out
}

/// 回环 TLS 目标：参考 REALITY 服务端在放行连接前**总是**先拨 `dest`
/// （`xtls/reality` `tls.go:167`），未认证连接被镜像转发到这里。
/// 自签名证书、逐连接应答，读失败即结束。
async fn start_dest() -> (u16, tokio::task::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
    let server = lengsuo_tls::TlsServer::new(
        vec![cert.cert.der().clone()],
        lengsuo_tls::PrivateKeyDer::Pkcs8(lengsuo_tls::PrivatePkcs8KeyDer::from(
            cert.key_pair.serialize_der(),
        )),
        Duration::from_secs(5),
    )
    .expect("目标 TLS 服务端");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = server.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut buffer = [0u8; 512];
                    let _ = stream.read(&mut buffer).await;
                }
            });
        }
    });
    (port, task)
}

/// 参考服务端配置（`secret` 是运行时生成的假私钥）。
fn reference_config(port: u16, dest_port: u16, secret: &[u8; 32]) -> serde_json::Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": ID}], "decryption": "none"},
            "streamSettings": {
                "security": "reality",
                "realitySettings": {
                    // 参考的 `show: true` 会把认证密钥前缀打到 stdout，禁用。
                    "show": false,
                    "dest": format!("127.0.0.1:{dest_port}"),
                    "xver": 0,
                    "serverNames": [SERVER_NAME],
                    "privateKey": base64_url(secret),
                    "shortIds": [HEX_SHORT_ID]
                }
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 运行一次客户端飞行：连参考端 → 构造 ClientHello → TLS 1.3 握手。
///
/// 成功时返回带应用数据密钥的记录读写器、底层流与对端叶子证书 DER。
async fn rust_client_flight(
    port: u16,
    secret: &[u8; 32],
    short_id: [u8; 8],
    sni: &str,
) -> Result<(RecordReader, RecordWriter, TcpStream, Vec<u8>), String> {
    let mut stream = timeout(DEADLINE, TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| "连接参考端超时".to_owned())?
        .map_err(|e| format!("连接参考端失败: {e}"))?;
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as u32;
    let public_key = x25519_base(secret);
    let mut rng = FixedRng::new(sha256(&[port as u8, sni.len() as u8]));
    let mut built: BuiltClientHello = build_reality_client_hello(
        &public_key,
        sni,
        &short_id,
        ClientVersion { x: 26, y: 3, z: 27 },
        unix_time,
        &mut rng,
    )
    .map_err(|e| format!("ClientHello 构造: {e}"))?;
    let raw = built.raw.clone();
    let mut state = RealityClient::from_built(&mut built).map_err(|e| format!("状态机: {e}"))?;
    let mut writer = RecordWriter::new();
    writer
        .write(&mut stream, &Outbound::PlainHandshake(raw))
        .await
        .map_err(|e| format!("发 ClientHello: {e}"))?;
    let outcome = client_handshake(&mut state, &mut stream, HANDSHAKE_DEADLINE)
        .await
        .map_err(|e| format!("客户端握手: {e}"))?;
    let mut reader = RecordReader::new();
    reader.enable_cipher(outcome.reader);
    let mut writer = RecordWriter::new();
    writer.enable_cipher(outcome.writer);
    Ok((reader, writer, stream, outcome.peer_certificate))
}

/// 读一条应用数据记录（`framed[0]` 是内容类型，其余是明文载荷）。
async fn read_application(
    reader: &mut RecordReader,
    stream: &mut TcpStream,
) -> Result<Vec<u8>, String> {
    loop {
        match reader
            .next_record(stream)
            .await
            .map_err(|e| format!("读应用数据: {e}"))?
        {
            Some(Inbound::Encrypted(framed)) => return Ok(framed[1..].to_vec()),
            Some(_) => continue,
            None => return Err("应用数据阶段遇到 EOF".to_owned()),
        }
    }
}

/// 确定性熵源：`fill_bytes` 用 SHA-256 计数器模式展开种子
/// （与 `reality_e2e/support` 的 `SeededRng` 同构，但本目标不共享那个模块）。
struct FixedRng {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

impl FixedRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: Vec::new(),
        }
    }
}

impl aes_gcm::aead::rand_core::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), aes_gcm::aead::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        while self.buffer.len() < dest.len() {
            let mut input = [0u8; 40];
            input[..32].copy_from_slice(&self.seed);
            input[32..].copy_from_slice(&self.counter.to_be_bytes());
            self.buffer.extend_from_slice(&sha256(&input));
            self.counter = self.counter.wrapping_add(1);
        }
        dest.copy_from_slice(&self.buffer[..dest.len()]);
        self.buffer.drain(..dest.len());
    }
}

impl aes_gcm::aead::rand_core::CryptoRng for FixedRng {}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reality_rust_client_to_xray_server_tcp() {
    timeout(DEADLINE, async {
        // 与 dest 的端口一并一次性预留，避免任何相邻口/重用抖动。
        let ports = free_ports(3);
        let xray_port = ports[0];
        let (dest_port, dest_task) = start_dest().await;
        assert!(ports[1] != xray_port && ports[2] != dest_port);
        let secret = [0x5a; 32];
        let reference = launch(reference_config(xray_port, dest_port, &secret), xray_port).await;

        // 回环 echo：逐字节取回客户端载荷。
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo.accept().await.unwrap();
            let mut buffer = vec![0u8; PAYLOAD.len()];
            socket.read_exact(&mut buffer).await.unwrap();
            socket.write_all(&buffer).await.unwrap();
            socket.shutdown().await.unwrap();
            buffer
        });

        let (mut reader, mut writer, mut stream, peer_certificate) =
            rust_client_flight(xray_port, &secret, SHORT_ID, SERVER_NAME)
                .await
                .expect("REALITY + TLS 1.3 握手应成功");
        // 对端必须是 REALITY 伪造的 Ed25519 证书（RFC 8410 SPKI 前缀）；
        // 它的认证标签已由 `client_handshake` 用本仓派生的 auth_key 校验过。
        assert!(
            peer_certificate
                .windows(12)
                .any(|w| w
                    == [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
            "对端不是 Ed25519 证书（{} 字节）",
            peer_certificate.len()
        );
        assert!(parse_reality_certificate(&peer_certificate).is_ok());

        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], echo_port),
        };
        let mut wire = header::encode(&request, &KEY).unwrap();
        wire.extend_from_slice(PAYLOAD);
        writer
            .write(&mut stream, &Outbound::EncryptedApplication(wire))
            .await
            .unwrap();

        // 响应头（无附加字段、2 字节）后紧跟 echo 返回的载荷。
        let mut received = read_application(&mut reader, &mut stream).await.unwrap();
        while received.len() < 2 + PAYLOAD.len() {
            received.extend(read_application(&mut reader, &mut stream).await.unwrap());
        }
        assert_eq!(&received[..2], &[0, 0], "响应头必须是成功");
        assert_eq!(&received[2..], PAYLOAD);

        assert_eq!(echo_task.await.unwrap(), PAYLOAD);
        drop(reference);
        dest_task.abort();
    })
    .await
    .expect("用例总超时");
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reality_rust_client_wrong_short_id_is_rejected() {
    timeout(DEADLINE, async {
        // 与 dest 的端口一并一次性预留，避免任何相邻口/重用抖动。
        let ports = free_ports(3);
        let xray_port = ports[0];
        let (dest_port, dest_task) = start_dest().await;
        assert!(ports[1] != xray_port && ports[2] != dest_port);
        let secret = [0x6b; 32];
        // 白名单与正确用例相同，只有客户端短 ID 不同：正例已在该配置下通过，
        // 说明本用例的失败只可能来自短 ID，而不是配置本身。
        let reference = launch(reference_config(xray_port, dest_port, &secret), xray_port).await;

        // 先确认是「端口通了但认证被拒」，不是端口没起来。
        timeout(WAIT, TcpStream::connect(("127.0.0.1", xray_port)))
            .await
            .expect("探活超时")
            .expect("参考端口必须可连");

        let result = rust_client_flight(xray_port, &secret, WRONG_SHORT_ID, SERVER_NAME).await;
        let error = result.err().expect("错误短 ID 必须失败");
        // 认证失败时参考把连接镜像转发到 dest：客户端必须在本仓的 REALITY
        // 证书校验处拒绝 dest 的真实 TLS 证书（不是被 RST、也不是本地构造失败）。
        assert!(
            error.contains("not an Ed25519") || error.contains("tag mismatch"),
            "错误短 ID 应在 REALITY 证书校验处失败：{error}"
        );
        println!("错误短 ID 失败原因：{error}");
        drop(reference);
        dest_task.abort();
    })
    .await
    .expect("用例总超时");
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reality_rust_client_wrong_server_name_is_rejected() {
    timeout(DEADLINE, async {
        // 与 dest 的端口一并一次性预留，避免任何相邻口/重用抖动。
        let ports = free_ports(3);
        let xray_port = ports[0];
        let (dest_port, dest_task) = start_dest().await;
        assert!(ports[1] != xray_port && ports[2] != dest_port);
        let secret = [0x7c; 32];
        // 白名单与正确用例相同，只有客户端 SNI 不同。
        let reference = launch(reference_config(xray_port, dest_port, &secret), xray_port).await;

        let result = rust_client_flight(xray_port, &secret, SHORT_ID, "wrong.example.org").await;
        let error = result.err().expect("错误 SNI 必须失败");
        // 参考在 SNI 不在白名单时把连接镜像转发到 dest：客户端看到的是 dest
        // 的真实自签证书，`client_handshake` 的 REALITY 标签校验必须拒绝它
        // （不是端口 RST）。dest 只在收到 ClientHello 后才完成 TLS 握手，故
        // 失败点必定在拿到 dest 的证书之后。
        assert!(
            error.contains("not an Ed25519") || error.contains("tag mismatch"),
            "错误 SNI 应在 REALITY 证书校验处失败：{error}"
        );
        println!("错误 SNI 失败原因：{error}");
        drop(reference);
        dest_task.abort();
    })
    .await
    .expect("用例总超时");
}
