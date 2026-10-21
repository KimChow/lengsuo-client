//! VLESS + REALITY 回环夹具：本仓 REALITY 服务端 + node 侧节点配置。
//!
//! 服务端编排照抄 `lengsuo-vless/tests/reality_main_link.rs`：
//! `accept_hello` → TLS 1.3（`session::server_handshake`）→ 主链路读 VLESS 头
//! → 回环 echo → 主链路写响应头 + 载荷。
//!
//! **本文件不声称与参考实现互通**：它只提供「本仓服务端 ↔ 本仓客户端」的
//! 端到端夹具；与参考的互通结论见各协议 crate 的文档。
//!
//! 全部只绑回环、只用临时端口（`127.0.0.1:0` 交给内核分配）、只用假凭据。
//! 每个网络操作都有截止时间；日志不输出任何密钥材料。

#![allow(dead_code)]

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
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};

/// 单步截止时间（建流 / 帧读写）。
pub const WAIT: Duration = Duration::from_secs(8);
/// 用例总截止时间。
pub const DEADLINE: Duration = Duration::from_secs(30);
/// SNI（服务端白名单）。
pub const SERVER_NAME: &str = "www.example.com";
/// 服务端白名单里的短 ID（配置里的十六进制文本 → `[0x31..0x38]`）。
pub const SHORT_ID_HEX: &str = "3132333435363738";
/// 短 ID 展开后的 8 字节。
pub const SHORT_ID: [u8; 8] = *b"12345678";
/// 测试用 UUID（假凭据）。
pub const UUID: &str = "11111111-1111-1111-1111-111111111111";
/// 回环载荷（含二进制字节）。
pub const PAYLOAD: &[u8] = b"node vless reality payload\0\xff\xfe binary";
/// 服务端读 VLESS 头时用的凭据（与 UUID 文本的 16 字节一致）。
pub const KEY: [u8; 16] = [0x11; 16];

/// base64 raw-url（RFC 4648 §5，无 padding）编码。
///
/// 与参考 `realitySettings.privateKey` 的编码一致；crate 内无 base64 依赖，
/// 夹具侧自带。
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

/// 确定性熵源：SHA-256 计数器模式展开种子。
///
/// 服务端握手状态机要一个 `RngCore + CryptoRng`；固定种子让用例可复现。
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

/// 服务端身份（假值）与准入白名单。
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

/// 当前 Unix 秒（REALITY 认证载荷的时间戳）。
#[must_use]
pub fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("时钟在 Unix 纪元之后")
        .as_secs() as u32
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

/// 本仓 REALITY 服务端：认证 → TLS 1.3 → 主链路读 VLESS 头 → 载荷交给 echo，
/// 把 echo 的结果按主链路写回响应头 + 载荷。
///
/// 返回服务端读到的载荷。
pub async fn serve_once(mut stream: TcpStream, server: &Server) -> Result<Vec<u8>, String> {
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
    // ClientHello 的走查用协议 crate 自带的解析器（不复制一份切片逻辑）。
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

    // —— 以下走的是 VLESS 主链路函数 ——
    let request = stream::receive_request(&mut app, &KEY, WAIT)
        .await
        .map_err(|e| format!("主链路读 VLESS 头: {e}"))?;
    if request.command != Command::Tcp {
        return Err("命令不是 TCP".to_owned());
    }
    // 「目标」建立成功后才写成功头（主链路契约）。参考服务端在目标连上后
    // **立刻**写 `[0, 0]`，不等业务载荷——node 的拨号顺序同样是
    // 「写请求头 → 等 `[0, 0]`」，故这里必须先回成功头再收载荷。
    stream::send_response(&mut app, WAIT)
        .await
        .map_err(|e| format!("主链路写响应头: {e}"))?;
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
    app.write_all(&received).await.map_err(|e| e.to_string())?;
    app.flush().await.map_err(|e| e.to_string())?;
    Ok(received)
}

/// 起一个只服务一次连接的本仓 REALITY 服务端。返回端口与后台任务。
pub async fn start_server(
    server: Arc<Server>,
) -> (u16, tokio::task::JoinHandle<Result<Vec<u8>, String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        serve_once(socket, &server).await
    });
    (port, task)
}

/// 只 accept、不服务：用来判定「连接到底有没有发生」。
///
/// 返回（端口，accept 计数句柄，观察任务）。观察任务在**没有连接**时一直
/// 挂着（直到调用方的截止时间到），有连接则记一次数并立刻返回。
pub async fn accept_only_watcher() -> (
    u16,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let watcher = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(socket);
        }
    });
    (port, accepted, watcher)
}

/// node 配置：vless + REALITY 段。
#[must_use]
pub fn reality_node(port: u16, server: &Server) -> NodeConfig {
    let value = json!([{
        "name": "vless-reality-loopback",
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
