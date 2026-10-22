//! VLESS + REALITY **中继**服务端（不是定长 echo）。
//!
//! `tests/vless_reality_support/mod.rs` 里的 `serve_once` 是「读满定长载荷 →
//! 原样回写」的固定夹具，只能证明握手可达；本卡要证明**业务载荷穿过转发器**
//! 并逐字节往返，所以这里照抄它的握手编排（`accept_hello` → TLS 1.3 →
//! 主链路），但主链路之后**连真实目标并双向转发**。
//!
//! 握手部分全部用协议 crate 的公开原语（`reality::server::accept_hello`、
//! `reality::session::server_handshake`、`reality::tls13::*`、
//! `reality::x25519::*`），不复制密码学。夹具自带的服务端私钥是固定假值
//! （`[0x5a; 32]`），与既有 REALITY 夹具一致。

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lengsuo_node::config::NodeConfig;
use lengsuo_vless::header::Command;
use lengsuo_vless::reality::server::{accept_hello, RealityServerConfig};
use lengsuo_vless::reality::session::server_handshake;
use lengsuo_vless::reality::tls13::io::{
    HandshakeCollector, Inbound, Outbound, RecordReader, RecordWriter,
};
use lengsuo_vless::reality::tls13::messages::parse_client_hello;
use lengsuo_vless::reality::tls13::server::ServerHandshake;
use lengsuo_vless::reality::x25519::{x25519, x25519_base};
use lengsuo_vless::stream;
use md5::digest::crypto_common::rand_core::{CryptoRng, RngCore};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};

/// 单步截止时间（建流 / 帧读写）。
pub const WAIT: Duration = Duration::from_secs(8);
/// SNI（服务端白名单）。
pub const SERVER_NAME: &str = "www.example.com";
/// 服务端白名单里的短 ID（配置里的十六进制文本 → `[0x31..0x38]`）。
pub const SHORT_ID_HEX: &str = "3132333435363738";
/// 短 ID 展开后的 8 字节。
pub const SHORT_ID: [u8; 8] = *b"12345678";
/// 测试用 UUID（假凭据）；服务端用它当 VLESS 凭据。
pub const UUID: &str = "11111111-1111-1111-1111-111111111111";
/// VLESS 凭据字节（UUID 去掉连字符后的前 16 字节：`0x11` × 16）。
pub const KEY: [u8; 16] = [0x11; 16];

/// 当前 Unix 秒（REALITY 认证载荷的时间戳）。
#[must_use]
pub fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("时钟在 Unix 纪元之后")
        .as_secs() as u32
}

/// base64 raw-url 编码（REALITY 公钥文本格式，与参考 `realitySettings.publicKey` 一致）。
#[must_use]
pub fn base64_url(bytes: &[u8]) -> String {
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

/// 确定性熵源：SHA-256 计数器模式展开种子（服务端握手状态机要 `RngCore + CryptoRng`）。
pub struct SeededRng {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

impl SeededRng {
    /// 用标签派生种子（标签 ≤ 32 字节，超出部分忽略）。
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let mut seed = [0u8; 32];
        let bytes = label.as_bytes();
        seed[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        Self {
            seed,
            counter: 0,
            buffer: Vec::new(),
        }
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        while self.buffer.len() < dest.len() {
            let mut input = [0u8; 40];
            input[..32].copy_from_slice(&self.seed);
            input[32..].copy_from_slice(&self.counter.to_be_bytes());
            self.buffer
                .extend_from_slice(&lengsuo_vless::reality::hash::sha::sha256(&input));
            self.counter = self.counter.wrapping_add(1);
        }
        let take = dest.len();
        dest.copy_from_slice(&self.buffer[..take]);
        self.buffer.drain(..take);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), md5::digest::crypto_common::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

/// REALITY 服务端（固定假私钥 + 固定白名单）。
pub struct Server {
    private_key: [u8; 32],
    config: RealityServerConfig,
}

impl Server {
    /// 新建服务端：固定假私钥 + 固定白名单。
    #[must_use]
    pub fn new() -> Self {
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

    /// 客户端配置用的公钥文本（参考格式：base64 raw-url）。
    #[must_use]
    pub fn public_key(&self) -> String {
        base64_url(&x25519_base(&self.private_key))
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// 目标地址 ⇒ 回环 `SocketAddr`。
fn target_addr(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::V4(ip, port) => SocketAddr::from((*ip, *port)),
        TargetAddr::V6(ip, port) => SocketAddr::from((*ip, *port)),
        TargetAddr::Domain(host, port) => format!("{host}:{port}")
            .parse()
            .expect("夹具目标是可解析的回环地址"),
    }
}

/// 把记录层读写器接到一条 TCP 连接上：读任务解封记录摊平成字节、写任务把
/// 字节切片成应用数据记录。
fn bridge(
    mut reader: RecordReader,
    mut writer: RecordWriter,
    transport: TcpStream,
) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (mut transport_read, mut transport_write) = tokio::io::split(transport);
    let (app, inner) = tokio::io::duplex(16384);
    let (mut inner_read, mut inner_write) = tokio::io::split(inner);
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
                    // 传输侧 EOF（客户端半关闭）：必须把 EOF 传给应用侧
                    // （关闭 duplex 的写半），否则 `copy_bidirectional` 永远不会
                    // 半关闭目标端 ⇒ 目标收不到 FIN ⇒ 回程永远不会回来。
                    Ok(None) => {
                        let _ = inner_write.shutdown().await;
                        return;
                    }
                    Err(_) => return,
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

/// 起一个 REALITY 中继服务端：REALITY 握手 → VLESS 主链路 → 连真实目标 →
/// 双向转发。返回端口。
pub async fn reality_proxy_server(server: Arc<Server>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reality");
    let port = listener.local_addr().expect("reality 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let _ = serve_proxy(socket, &server).await;
            });
        }
    });
    port
}

/// 处理一条 REALITY 连接。
async fn serve_proxy(mut stream: TcpStream, server: &Server) -> Result<(), String> {
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
    accept_hello(&server.config, &raw, now_unix()).map_err(|e| format!("REALITY 认证被拒: {e}"))?;
    let hello = parse_client_hello(&raw[4..]).map_err(|e| format!("ClientHello 解析: {e}"))?;
    if hello.server_name.as_deref() != Some(SERVER_NAME) {
        return Err("SNI 不匹配".to_owned());
    }
    let peer = hello.x25519_key_share.ok_or("缺 X25519 key_share")?;
    let shared = x25519(&server.private_key, &peer).map_err(|e| e.to_string())?;
    let auth_key = lengsuo_vless::reality::auth::derive_auth_key(&shared, &hello.random)
        .map_err(|e| e.to_string())?;
    let mut rng = SeededRng::from_label("server");
    let mut state = ServerHandshake::new(auth_key, [0x31; 32], [0x32; 32], &mut rng)
        .map_err(|e| format!("服务端状态机: {e}"))?;
    state
        .process_client_hello(&raw, &peer)
        .map_err(|e| format!("处理 ClientHello: {e}"))?;
    let outcome = server_handshake(&mut state, &mut stream, &hello.random)
        .await
        .map_err(|e| format!("服务端握手: {e}"))?;
    let mut reader = RecordReader::new();
    reader.enable_cipher(outcome.reader);
    let mut writer = RecordWriter::new();
    writer.enable_cipher(outcome.writer);
    let (mut app, _bridge) = bridge(reader, writer, stream);

    // —— VLESS 主链路 ——
    let request = stream::receive_request(&mut app, &KEY, WAIT)
        .await
        .map_err(|e| format!("主链路读 VLESS 头: {e}"))?;
    if request.command != Command::Tcp {
        return Err("命令不是 TCP".to_owned());
    }
    // 目标建立成功后才回成功头（主链路契约，与参考一致）。
    let mut target = TcpStream::connect(target_addr(&request.target))
        .await
        .map_err(|e| format!("连目标失败: {e}"))?;
    stream::send_response(&mut app, WAIT)
        .await
        .map_err(|e| format!("主链路写响应头: {e}"))?;
    let _ = tokio::io::copy_bidirectional(&mut app, &mut target).await;
    Ok(())
}

/// REALITY 节点配置（公钥文本由服务端私钥派生）。
#[must_use]
pub fn reality_node(name: &str, port: u16, server: &Server) -> NodeConfig {
    let value = serde_json::json!([{
        "name": name,
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "auth": { "password": UUID },
        "reality": {
            "server_name": SERVER_NAME,
            "public_key": server.public_key(),
            "short_id": SHORT_ID_HEX,
            "fingerprint": "chrome"
        }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}
