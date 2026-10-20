//! REALITY 接入 VLESS **主连接链路** 的实跑取证。
//!
//! 与 `reality_xray_server.rs`（→ 参考服务端）不同，这里对端是**本仓**的
//! REALITY + TLS 1.3 服务端；两端都走 `lengsuo_vless::stream` 的**主链路**函数：
//!
//! ```text
//! 客户端：RealitySettings → RealityConfig::from_settings → RealityStream::connect
//!        → stream::send_request（VLESS 头）→ 载荷 → stream::receive_response
//! 服务端：accept_hello → TLS 1.3 → stream::receive_request → 回环 echo
//!        → stream::send_response → 载荷
//! ```
//!
//! 全部回环地址、临时端口、运行时生成的假凭据；每个网络操作都有截止时间。
//! 日志不输出任何密钥材料。

mod support;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lengsuo_vless::header::{Command, Request};
use lengsuo_vless::reality::server::{accept_hello, RealityServerConfig};
use lengsuo_vless::reality::session::server_handshake;
use lengsuo_vless::reality::tls13::io::{
    HandshakeCollector, Inbound, Outbound, RecordReader, RecordWriter,
};
use lengsuo_vless::reality::tls13::server::ServerHandshake;
use lengsuo_vless::reality::x25519::{x25519, x25519_base};
use lengsuo_vless::reality_config::{ConfigError, RealityConfig, RealitySettings};
use lengsuo_vless::reality_link::RealityStream;
use lengsuo_vless::stream;
use ss_core::target::TargetAddr;
use support::{base64_url, free_ports, SeededRng, KEY, WAIT};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// 用例总截止时间。
const DEADLINE: Duration = Duration::from_secs(30);
/// 单次建流的截止时间。
const HANDSHAKE: Duration = Duration::from_secs(10);
const SERVER_NAME: &str = "www.example.com";
/// 服务端白名单里的短 ID（配置里的十六进制文本 → `[0x31..0x38]`）。
const SHORT_ID_HEX: &str = "3132333435363738";
const SHORT_ID: [u8; 8] = *b"12345678";
const PAYLOAD: &[u8] = b"reality main-link payload\0\xff\xfe binary";

/// 服务端身份（假值）。
struct Server {
    private_key: [u8; 32],
    config: RealityServerConfig,
}

impl Server {
    fn new() -> Self {
        let private_key = [0x5a; 32];
        Self {
            private_key,
            config: RealityServerConfig {
                private_key,
                short_ids: vec![SHORT_ID],
                server_names: vec![SERVER_NAME.to_owned()],
                max_time_diff: Duration::from_secs(60),
            },
        }
    }

    /// 客户端配置：公钥按参考格式（base64 raw-url 文本）给出。
    fn client_settings(&self) -> RealitySettings {
        RealitySettings {
            server_name: SERVER_NAME.to_owned(),
            password: String::new(),
            public_key: base64_url(&x25519_base(&self.private_key)),
            short_id: SHORT_ID_HEX.to_owned(),
            fingerprint: "chrome".to_owned(),
        }
    }
}

/// 把记录层读写器接到一个 `AsyncRead + AsyncWrite`：读任务解封记录摊平成字节、
/// 写任务把字节切片成应用数据记录。服务端侧用它与主链路函数对接。
fn bridge(
    mut reader: RecordReader,
    mut writer: RecordWriter,
    transport: TcpStream,
) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (transport_read, transport_write) = tokio::io::split(transport);
    let (app, inner) = tokio::io::duplex(16384);
    let (mut inner_read, mut inner_write) = tokio::io::split(inner);
    let mut transport_read = transport_read;
    let mut transport_write = transport_write;
    let task = tokio::spawn(async move {
        let pump_reads = async {
            loop {
                match reader.next_record(&mut transport_read).await {
                    Ok(Some(Inbound::Encrypted(framed))) if framed.first() == Some(&23) => {
                        if inner_write.write_all(&framed[1..]).await.is_err() {
                            return;
                        }
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => return,
                }
            }
        };
        let pump_writes = async {
            let mut buffer = [0u8; 16384];
            loop {
                let Ok(read) = inner_read.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if writer
                    .write(
                        &mut transport_write,
                        &Outbound::EncryptedApplication(buffer[..read].to_vec()),
                    )
                    .await
                    .is_err()
                {
                    return;
                }
            }
        };
        tokio::join!(pump_reads, pump_writes);
    });
    (app, task)
}

/// ClientHello 里服务端认证要用的两项（布局同 `reality/server.rs` 的走查）。
struct HelloView {
    server_name: Option<String>,
    key_share: Option<[u8; 32]>,
    random: [u8; 32],
}

/// 最小 ClientHello 扩展走查：type(1)+len(3)+version(2)+random(32)+
/// session_id(1+n)+suites(2+n)+compression(1+n)+extensions(2+n)。
fn parse_hello(raw: &[u8]) -> HelloView {
    let mut random = [0u8; 32];
    random.copy_from_slice(&raw[6..38]);
    let mut at = 6 + 32;
    at += 1 + usize::from(raw[at]);
    at += 2 + usize::from(u16::from_be_bytes([raw[at], raw[at + 1]]));
    at += 1 + usize::from(raw[at]);
    let end = raw.len();
    let mut server_name = None;
    let mut key_share = None;
    if at + 2 <= end {
        at += 2;
        while at + 4 <= end {
            let kind = u16::from_be_bytes([raw[at], raw[at + 1]]);
            let len = usize::from(u16::from_be_bytes([raw[at + 2], raw[at + 3]]));
            let data = &raw[at + 4..(at + 4 + len).min(end)];
            match kind {
                0x0000 if data.len() >= 5 => {
                    let name_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
                    server_name = std::str::from_utf8(&data[5..5 + name_len])
                        .ok()
                        .map(str::to_owned);
                }
                0x0033 if data.len() >= 6 + 32 => {
                    let mut share = [0u8; 32];
                    share.copy_from_slice(&data[6..6 + 32]);
                    key_share = Some(share);
                }
                _ => {}
            }
            at += 4 + len;
        }
    }
    HelloView {
        server_name,
        key_share,
        random,
    }
}

/// 本仓 REALITY 服务端：认证 → TLS 1.3 → 主链路读 VLESS 头 → 载荷交给 echo，
/// 把 echo 的结果按主链路写回响应头 + 载荷。
///
/// 返回服务端读到的载荷。
async fn serve_once(
    mut stream: TcpStream,
    server: &Server,
    now_unix: u32,
) -> Result<Vec<u8>, String> {
    let mut reader = RecordReader::new();
    let mut collector = HandshakeCollector::new();
    let raw = loop {
        match reader
            .next_record(&mut stream)
            .await
            .map_err(|e| e.to_string())?
        {
            Some(Inbound::PlainHandshake(payload)) => {
                collector.push(&payload);
                if let Some(message) = collector.take().map_err(|e| e.to_string())? {
                    break message;
                }
            }
            Some(_) => continue,
            None => return Err("ClientHello 前 EOF".to_owned()),
        }
    };
    accept_hello(&server.config, &raw, now_unix).map_err(|e| format!("REALITY 认证被拒: {e}"))?;
    let view = parse_hello(&raw);
    if view.server_name.as_deref() != Some(SERVER_NAME) {
        return Err("SNI 不匹配".to_owned());
    }
    let peer = view.key_share.ok_or("缺 X25519 key_share")?;
    let shared = x25519(&server.private_key, &peer).map_err(|e| e.to_string())?;
    let auth_key = lengsuo_vless::reality::auth::derive_auth_key(&shared, &view.random)
        .map_err(|e| e.to_string())?;
    let mut rng = SeededRng::from_label("server");
    let mut state = ServerHandshake::new(auth_key, [0x31; 32], [0x32; 32], &mut rng)
        .map_err(|e| format!("服务端状态机: {e}"))?;
    state
        .process_client_hello(&raw, &peer)
        .map_err(|e| format!("处理 ClientHello: {e}"))?;
    let outcome = server_handshake(&mut state, &mut stream, &view.random)
        .await
        .map_err(|e| format!("服务端握手: {e}"))?;
    let mut reader = RecordReader::new();
    reader.enable_cipher(outcome.reader);
    let mut writer = RecordWriter::new();
    writer.enable_cipher(outcome.writer);
    let (mut app, _bridge) = bridge(reader, writer, stream);

    // —— 以下走的是 VLESS 主链路函数 ——
    let request = stream::receive_request(&mut app, &KEY, WAIT)
        .await
        .map_err(|e| format!("主链路读 VLESS 头: {e}"))?;
    if request.command != Command::Tcp {
        return Err("命令不是 TCP".to_owned());
    }
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    while received.len() < PAYLOAD.len() {
        let read = app.read(&mut buffer).await.map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("载荷读到一半 EOF".to_owned());
        }
        received.extend_from_slice(&buffer[..read]);
    }
    if received != PAYLOAD {
        return Err("服务端读到的载荷不一致".to_owned());
    }
    // 「目标」建立成功后才写成功头（主链路契约）。
    stream::send_response(&mut app, WAIT)
        .await
        .map_err(|e| format!("主链路写响应头: {e}"))?;
    app.write_all(&received).await.map_err(|e| e.to_string())?;
    app.flush().await.map_err(|e| e.to_string())?;
    Ok(received)
}

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// 起一个只服务一次连接的本仓 REALITY 服务端。
async fn start_server(server: Arc<Server>, port: u16) -> tokio::task::JoinHandle<Vec<u8>> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        match serve_once(socket, &server, now_unix()).await {
            Ok(received) => received,
            Err(error) => panic!("服务端失败: {error}"),
        }
    })
}

/// **1. 主链路贯通**：本仓 VLESS 服务端为对端，本仓 REALITY 客户端经
/// `RealityStream` 走主链路（`stream::send_request` → 载荷 → `receive_response`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_main_link_roundtrip_to_own_server() {
    timeout(DEADLINE, async {
        let server = Arc::new(Server::new());
        let server_port = free_ports(1)[0];
        let server_task = start_server(server.clone(), server_port).await;

        // 配置（参考格式的 base64 raw-url 公钥 + 十六进制短 ID）。
        let config = RealityConfig::from_settings(server.client_settings()).expect("合法配置");
        // 建流：TCP → REALITY ClientHello → TLS 1.3 → 记录层。
        let mut reality =
            RealityStream::connect(&format!("127.0.0.1:{server_port}"), &config, HANDSHAKE)
                .await
                .expect("REALITY 建流");

        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], 9),
        };
        stream::send_request(&mut reality, &request, &KEY, WAIT)
            .await
            .expect("VLESS 请求头");
        reality.write_all(PAYLOAD).await.expect("载荷");
        stream::receive_response(&mut reality, WAIT)
            .await
            .expect("VLESS 成功响应头");
        let mut received = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, reality.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        assert_eq!(received, PAYLOAD, "回环载荷必须逐字节一致");
        assert_eq!(server_task.await.unwrap(), PAYLOAD);
        println!("REALITY 主链路贯通：{} 字节逐字节一致", received.len());
    })
    .await
    .expect("用例总超时");
}

/// **2. 配置缺省不变**：不配置 REALITY 时，主链路仍按「裸 TCP」走通——
/// 连接由调用方直接给出（这里是参考端 VLESS 入站、`security: "none"`），
/// `stream::*` 不感知安全层，与既有默认套件同一条路径。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn main_link_without_reality_stays_bare_tcp() {
    timeout(DEADLINE, async {
        // 裸 TCP 对端：只做「按 VLESS 头读请求 → 回响应头 → 回显载荷」。
        // 不依赖参考二进制（`LENGSUO_XRAY`）——本用例验证的是**默认路径不变**，
        // 即不配置 REALITY 时主链路仍是「调用方给定裸连接 + 既有 stream 读写」。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = stream::receive_request(&mut socket, &KEY, WAIT)
                .await
                .expect("读 VLESS 请求头");
            assert!(matches!(request.command, Command::Tcp));
            let mut received = vec![0u8; PAYLOAD.len()];
            socket.read_exact(&mut received).await.expect("读载荷");
            stream::send_response(&mut socket, WAIT)
                .await
                .expect("写 VLESS 响应头");
            socket.write_all(&received).await.expect("回显载荷");
            socket.flush().await.expect("flush");
            received
        });
        // 不经 REALITY：调用方直接给出裸 TCP 连接交给主链路。
        let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], 9),
        };
        stream::send_request(&mut plain, &request, &KEY, WAIT)
            .await
            .unwrap();
        plain.write_all(PAYLOAD).await.unwrap();
        stream::receive_response(&mut plain, WAIT).await.unwrap();
        let mut received = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, plain.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .unwrap();
        assert_eq!(received, PAYLOAD, "默认路径载荷必须逐字节一致");
        assert_eq!(server_task.await.unwrap(), PAYLOAD);
        println!(
            "默认路径（无 REALITY）：裸 TCP 逐字节一致 {}",
            received.len()
        );
    })
    .await
    .expect("用例总超时");
}

/// **3. 非法配置 fail-closed**：启动即报错，**不**降级成「无 REALITY 直连」。
#[test]
fn invalid_reality_config_fails_at_startup() {
    let server = Server::new();
    let valid = server.client_settings();

    let mut bad_base64 = valid.clone();
    bad_base64.public_key = "not*base64*at*all".to_owned();
    let mut short_key = valid.clone();
    short_key.public_key = base64_url(&[7u8; 31]);
    let mut long_key = valid.clone();
    long_key.public_key = base64_url(&[7u8; 33]);
    let mut empty_key = valid.clone();
    empty_key.public_key.clear();
    let mut unknown_fp = valid.clone();
    unknown_fp.fingerprint = "curl".to_owned();
    let mut unsafe_fp = valid.clone();
    unsafe_fp.fingerprint = "unsafe".to_owned();
    let mut bad_short_id = valid.clone();
    bad_short_id.short_id = "zz".to_owned();

    let cases = [
        (bad_base64, ConfigError::InvalidPublicKey),
        (short_key, ConfigError::InvalidPublicKey),
        (long_key, ConfigError::InvalidPublicKey),
        (empty_key, ConfigError::EmptyPublicKey),
        (unknown_fp, ConfigError::UnknownFingerprint),
        (unsafe_fp, ConfigError::InvalidFingerprint),
        (bad_short_id, ConfigError::InvalidShortId),
    ];
    for (settings, expected) in cases {
        let error = RealityConfig::from_settings(settings).expect_err("必须拒绝");
        assert_eq!(error, expected);
        println!("fail-closed：{error}");
    }
    // 合法配置仍可解析（证明上面的失败只来自被改坏的字段）。
    assert!(RealityConfig::from_settings(valid).is_ok());
}
