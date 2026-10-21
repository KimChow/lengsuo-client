//! REALITY 传输层的测试夹具：**本仓** REALITY 服务端 + 客户端。
//!
//! 与 `tests/reality_main_link.rs` 同一条思路（服务端是**测试夹具**，不是
//! 产品代码），但这里额外提供两件那个文件没有的东西：
//!
//! 1. `connect_with_deadline` —— 可自定义截止时间的 `RealityStream::connect`，
//!    用来测「握手对端沉默 ⇒ 有限时间内超时失败」。
//! 2. `RealityServer` —— 服务端的应用侧字节流 + 后台泵任务句柄，用来在
//!    清理格里断言「读任务已结束、读到的是**干净 EOF**」。
//!
//! ## 管道方向（与 `src/reality_link.rs` 的 `RealityStream` 完全一致）
//!
//! ```text
//! TCP  ──读泵──▶ inner.write ──▶ one ──▶ app.read   （服务端 → 调用方）
//! TCP  ◀──写泵── inner.read  ◀── two ◀── app.write   （调用方 → 服务端）
//! ```
//!
//! 读泵在 TCP 结束时**通知**写泵收尾：写泵随后关掉本端写方向（发 FIN），
//! 两个泵都结束后 `inner` 被 drop，调用方侧的应用流读到**干净 EOF**
//! （`Ok(0)`），而不是错误。
//!
//! 全部身份材料是运行时生成的**假值**；日志与断言不输出任何密钥。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lengsuo_vless::reality::{
    auth::derive_auth_key,
    server::{accept_hello, RealityServerConfig},
    session::server_handshake,
    tls13::{
        io::{HandshakeCollector, Inbound, Outbound, RecordReader, RecordWriter},
        messages::parse_client_hello,
        server::ServerHandshake,
    },
    x25519::{x25519, x25519_base},
};
use lengsuo_vless::reality_config::{RealityConfig, RealitySettings};
use lengsuo_vless::reality_link::{Error as LinkError, RealityStream};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

use super::support::{base64_url, SeededRng};

/// 假 SNI（回环场景下只是个字符串，不做真实 DNS 解析）。
pub const SERVER_NAME: &str = "www.example.com";
/// 短 ID（8 字节假值）。
const SHORT_ID: [u8; 8] = *b"12345678";
/// 短 ID 的十六进制文本（客户端配置用）。
const SHORT_ID_HEX: &str = "3132333435363738";
/// 服务端 REALITY 私钥（假值）。
const PRIVATE_KEY: [u8; 32] = [0x5a; 32];
/// 握手截止时间。
pub const HANDSHAKE: Duration = Duration::from_secs(10);
/// 应用侧管道容量。
const PIPE: usize = 16384;

/// 客户端配置（公钥按参考格式的 base64 raw-url 文本给出）。
pub fn client_config() -> RealityConfig {
    RealityConfig::from_settings(RealitySettings {
        server_name: SERVER_NAME.to_owned(),
        password: String::new(),
        public_key: base64_url(&x25519_base(&PRIVATE_KEY)),
        short_id: SHORT_ID_HEX.to_owned(),
        fingerprint: "chrome".to_owned(),
    })
    .expect("合法配置")
}

/// 服务端配置。
fn server_config() -> RealityServerConfig {
    RealityServerConfig {
        private_key: PRIVATE_KEY,
        short_ids: vec![SHORT_ID],
        server_names: vec![SERVER_NAME.to_owned()],
        max_time_diff: Duration::from_secs(60),
    }
}

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or_default()
}

/// 已完成 REALITY + TLS 1.3 握手的**服务端**。
pub struct RealityServer {
    /// 监听端口（客户端连这个端口）。
    pub port: u16,
    /// 服务端的应用侧字节流（VLESS 主链路就跑在它上面）。
    pub app: DuplexStream,
    /// 后台泵任务（读泵 + 写泵）。任务结束即「读任务已结束」。
    pub pumps: JoinHandle<()>,
}

/// 在观察上限内等后台泵任务结束；返回 `Err` 表示任务**挂住**了。
pub async fn join_pumps(pumps: JoinHandle<()>, limit: Duration) -> Result<(), String> {
    match timeout(limit, pumps).await {
        Ok(joined) => joined.map_err(|e| format!("泵任务异常: {e}")),
        Err(_) => Err("泵任务未在观察上限内结束（存在悬挂读任务）".to_owned()),
    }
}

/// 起一个**本仓** REALITY 服务端（只服务一条连接）。
///
/// 服务端流程：REALITY 认证 → TLS 1.3 握手 → 把应用数据摊平成字节流交给
/// 调用方（调用方拿到的是服务端的应用侧字节流）。
pub async fn start_server() -> RealityServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定回环端口");
    let port = listener.local_addr().expect("读取端口").port();
    let (app, inner) = tokio::io::duplex(PIPE);
    let (inner_read, inner_write) = split(inner);
    let pumps = tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        if let Err(reason) = serve_once(socket, inner_read, inner_write).await {
            // 服务端失败不 panic：断言由调用方在读端做出。
            eprintln!("REALITY 夹具服务端失败：{reason}");
        }
    });
    RealityServer { port, app, pumps }
}

/// 服务端主体：REALITY 认证 + TLS 1.3 握手 + 记录层 ↔ 管道泵。
async fn serve_once(
    socket: TcpStream,
    mut inner_read: ReadHalf<DuplexStream>,
    mut inner_write: WriteHalf<DuplexStream>,
) -> Result<(), String> {
    let mut socket = socket;
    let mut reader = RecordReader::new();
    let mut collector = HandshakeCollector::new();
    let raw = loop {
        match reader
            .next_record(&mut socket)
            .await
            .map_err(|e| format!("服务端读记录失败: {e}"))?
        {
            Some(Inbound::PlainHandshake(payload)) => {
                collector.push(&payload);
                if let Some(message) = collector.take().map_err(|e| e.to_string())? {
                    break message;
                }
            }
            Some(_) => continue,
            None => return Err("服务端在 ClientHello 前遇到 EOF".to_owned()),
        }
    };
    // REALITY 认证（失败即拒，不回落）。
    accept_hello(&server_config(), &raw, now_unix())
        .map_err(|e| format!("REALITY 认证被拒: {e}"))?;
    let info = parse_client_hello(&raw[4..]).map_err(|e| format!("解析 ClientHello 失败: {e}"))?;
    let peer = info
        .x25519_key_share
        .ok_or_else(|| "ClientHello 缺 X25519 key_share".to_owned())?;
    let shared = x25519(&PRIVATE_KEY, &peer).map_err(|e| format!("X25519 失败: {e}"))?;
    let auth_key =
        derive_auth_key(&shared, &info.random).map_err(|e| format!("派生 auth_key 失败: {e}"))?;
    let mut rng = SeededRng::from_label("server");
    let mut state = ServerHandshake::new(auth_key, [0x31; 32], [0x32; 32], &mut rng)
        .map_err(|e| format!("服务端状态机: {e}"))?;
    state
        .process_client_hello(&raw, &peer)
        .map_err(|e| format!("处理 ClientHello: {e}"))?;
    let outcome = server_handshake(&mut state, &mut socket, &info.random)
        .await
        .map_err(|e| format!("服务端握手: {e}"))?;

    let (transport_read, mut transport_write) = split(socket);
    let mut transport_read = transport_read;
    let mut reader = RecordReader::new();
    reader.enable_cipher(outcome.reader);
    let mut writer = RecordWriter::new();
    writer.enable_cipher(outcome.writer);

    // 读泵结束（对端关闭）时通知写泵收尾。
    let (closed_tx, mut closed_rx) = oneshot::channel::<()>();

    // 读泵：TCP → 管道（解封记录、摊平成字节流）。
    let pump_reads = async {
        loop {
            match reader.next_record(&mut transport_read).await {
                Ok(Some(Inbound::Encrypted(framed))) if framed.first() == Some(&23) => {
                    if inner_write.write_all(&framed[1..]).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => break,
            }
        }
        let _ = closed_tx.send(());
    };
    // 写泵：管道 → TCP（把字节切片成应用数据记录）。
    let pump_writes = async {
        let mut buffer = [0u8; PIPE];
        loop {
            tokio::select! {
                // 对端已关闭 ⇒ 收尾并关掉本端写方向。
                _ = &mut closed_rx => break,
                read = inner_read.read(&mut buffer) => {
                    let Ok(read) = read else { break };
                    if read == 0 {
                        break;
                    }
                    if writer
                        .write(
                            &mut transport_write,
                            &Outbound::EncryptedApplication(buffer[..read].to_vec()),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        // 关掉本端写方向，让对端读到**干净 EOF** 而不是挂住。
        let _ = transport_write.shutdown().await;
    };
    tokio::join!(pump_reads, pump_writes);
    Ok(())
}

/// 建一条 REALITY 连接（截止时间可自定义）。
pub async fn connect_with_deadline(
    address: &str,
    config: &RealityConfig,
    deadline: Duration,
) -> Result<RealityStream, LinkError> {
    RealityStream::connect(address, config, deadline).await
}

/// 建一条 REALITY 连接（默认握手截止时间）。
pub async fn connect(address: &str, config: &RealityConfig) -> Result<RealityStream, LinkError> {
    RealityStream::connect(address, config, HANDSHAKE).await
}
