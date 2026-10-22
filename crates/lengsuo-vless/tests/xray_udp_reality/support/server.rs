//! 服务端侧夹具：本仓 REALITY 服务端 + XUDP 转发器。
//!
//! 服务端一侧复刻本仓 REALITY 服务端（`reality::server::accept_hello` +
//! `reality::session::server_handshake`），再把 VLESS 主链路与 XUDP 包封接上：
//!
//! ```text
//! accept_hello → TLS 1.3 → stream::receive_request → stream::send_response
//!             → UdpSession::receive（解 XUDP 包封）→ 按目标拨号 → 回程按同一包封回送
//! ```

use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lengsuo_vless::{
    header::Command,
    reality::{
        auth::derive_auth_key_server,
        server::{accept_hello, RealityServerConfig},
        session::server_handshake,
        tls13::io::{HandshakeCollector, Inbound, Outbound, RecordReader, RecordWriter},
        tls13::server::ServerHandshake,
        udp::{Error as UdpError, UdpSession},
        x25519::x25519_base,
    },
    reality_config::{RealityConfig, RealitySettings},
    stream,
};
use ss_core::target::TargetAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};

use super::shared::{base64_url, SeededRng, KEY};
use super::{SERVER_NAME, SHORT_ID, SHORT_ID_HEX};

/// 本仓 REALITY 服务端身份（假值）。
pub struct Server {
    /// X25519 私钥（假值）。
    private_key: [u8; 32],
    /// REALITY 准入配置。
    config: RealityServerConfig,
}

impl Server {
    /// 新建一份服务端身份。
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

    /// 客户端配置：公钥按参考格式（base64 raw-url 文本）给出。
    pub fn client_settings(&self) -> RealitySettings {
        RealitySettings {
            server_name: SERVER_NAME.to_owned(),
            password: String::new(),
            public_key: base64_url(&x25519_base(&self.private_key)),
            short_id: SHORT_ID_HEX.to_owned(),
            fingerprint: "chrome".to_owned(),
        }
    }

    /// 解析后的客户端配置。
    pub fn client_config(&self) -> RealityConfig {
        RealityConfig::from_settings(self.client_settings()).expect("合法配置")
    }
}

/// 一次 UDP 拨号记录（目标 + 实际拨的地址）。
#[derive(Debug, Clone)]
pub struct Dial {
    /// XUDP 包封里给出的目标。
    pub target: TargetAddr,
    /// 实际拨出的地址（域名已按 hosts 表解析）。
    pub addr: SocketAddr,
}

/// 拨号记录（跨连接共享；负例要断言它**为空**）。
pub type DialLog = Arc<Mutex<Vec<Dial>>>;

/// 会话结束原因。
#[derive(Debug)]
pub enum Stop {
    /// 对端在包封边界关闭（会话正常结束）。
    Closed,
    /// 失败（包封非法 / 超时 / I/O 错误）：一律 fail-closed。
    Failed(String),
}

/// 服务端一次会话的结果。
#[derive(Debug)]
pub struct Served {
    /// 收到的包封（目标地址 + 载荷）。
    pub packets: Vec<(TargetAddr, Vec<u8>)>,
    /// 会话结束原因。
    pub stop: Stop,
}

/// hosts 静态映射：假域名 → 回环；IPv4/IPv6 直接用地址。**不依赖公网 DNS**。
fn resolve(target: &TargetAddr) -> Result<SocketAddr, String> {
    match target {
        TargetAddr::V4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        TargetAddr::V6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        TargetAddr::Domain(host, port) => {
            let ip = match host.as_str() {
                super::FAKE_DOMAIN => [127, 0, 0, 1],
                _ => return Err(format!("假域名不在 hosts 表中：{host}")),
            };
            Ok(SocketAddr::from((ip, *port)))
        }
    }
}

/// 源地址与目标同族、端口取 0（避免回程来源地址歧义）。
fn bind_addr(addr: &SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), 0)),
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(*v6.ip(), 0, 0, 0)),
    }
}

/// 把记录层读写器接到一条字节流：读任务解封记录摊平成字节、写任务把字节切成
/// 应用数据记录。服务端侧用它与主链路函数对接。
///
/// **读泵独占内层写端**：读泵结束（承载 EOF）时 `inner_write` 随之被丢弃，
/// 对端（`app`）随即读到 EOF。否则服务端的读侧会一直挂到截止时间，而不是在
/// 包封边界上干净结束。
fn bridge(
    mut reader: RecordReader,
    mut writer: RecordWriter,
    transport: TcpStream,
) -> (DuplexStream, JoinHandle<()>) {
    let (transport_read, transport_write) = tokio::io::split(transport);
    let (app, inner) = tokio::io::duplex(16384);
    let (mut inner_read, mut inner_write) = tokio::io::split(inner);
    let mut transport_read = transport_read;
    let mut transport_write = transport_write;
    let task = tokio::spawn(async move {
        let reader_task = tokio::spawn(async move {
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
        });
        let writer_task = tokio::spawn(async move {
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
        });
        // 读泵结束 → 内层写端被丢弃 → `app` 读到 EOF → 写泵也结束。
        let _ = reader_task.await;
        writer_task.abort();
    });
    (app, task)
}

/// 从 ClientHello 取 `random` 与 X25519 `key_share`（扩展类型 `0x0033`）。
///
/// 本仓的 `ClientHello` 解析器是模块私有的，服务端侧只能自己走一遍最小切片：
/// `type(1)+len(3)+version(2)+random(32)+session_id(1+n)+suites(2+n)+
/// compression(1+n)+extensions(2+n)`。
fn hello_parts(raw: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let random: [u8; 32] = raw.get(6..38)?.try_into().ok()?;
    let mut at = 6 + 32;
    at += 1 + usize::from(*raw.get(at)?);
    let suites: [u8; 2] = raw.get(at..at + 2)?.try_into().ok()?;
    at += 2 + usize::from(u16::from_be_bytes(suites));
    at += 1 + usize::from(*raw.get(at)?);
    let end = raw.len();
    if at + 2 > end {
        return None;
    }
    at += 2;
    while at + 4 <= end {
        let kind = u16::from_be_bytes(raw.get(at..at + 2)?.try_into().ok()?);
        let length = usize::from(u16::from_be_bytes(
            raw.get(at + 2..at + 4)?.try_into().ok()?,
        ));
        let data = raw.get(at + 4..(at + 4 + length).min(end))?;
        if kind == 0x0033 && data.len() >= 6 + 32 {
            let mut share = [0u8; 32];
            share.copy_from_slice(&data[6..6 + 32]);
            return Some((random, share));
        }
        at += 4 + length;
    }
    None
}

/// 本仓 REALITY 服务端：ClientHello → REALITY 认证 → TLS 1.3 → 已认证字节流。
async fn handshake(socket: TcpStream, server: &Server) -> Result<DuplexStream, String> {
    let mut socket = socket;
    let mut reader = RecordReader::new();
    let mut collector = HandshakeCollector::new();
    let raw = loop {
        match reader
            .next_record(&mut socket)
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
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟")
        .as_secs() as u32;
    accept_hello(&server.config, &raw, now_unix).map_err(|e| format!("REALITY 认证被拒：{e}"))?;
    let (random, peer) = hello_parts(&raw).ok_or("ClientHello 缺 random/key_share")?;
    let auth_key =
        derive_auth_key_server(&server.private_key, &peer, &random).map_err(|e| e.to_string())?;
    let mut rng = SeededRng::from_label("server");
    let mut state = ServerHandshake::new(auth_key, [0x31; 32], [0x32; 32], &mut rng)
        .map_err(|e| format!("服务端状态机：{e}"))?;
    state
        .process_client_hello(&raw, &peer)
        .map_err(|e| format!("处理 ClientHello：{e}"))?;
    let outcome = server_handshake(&mut state, &mut socket, &random)
        .await
        .map_err(|e| format!("服务端握手：{e}"))?;
    let mut reader = RecordReader::new();
    reader.enable_cipher(outcome.reader);
    let mut writer = RecordWriter::new();
    writer.enable_cipher(outcome.writer);
    Ok(bridge(reader, writer, socket).0)
}

/// 把一个 UDP 数据报转发到目标，并把回程按同一包封回送。
async fn forward(
    app: &mut DuplexStream,
    session: &mut UdpSession,
    target: &TargetAddr,
    payload: &[u8],
    dials: &DialLog,
    step: Duration,
) -> Result<(), String> {
    let addr = resolve(target)?;
    // 先记「拨号意图」：连不上的目标也算尝试过，负例要断言这里为空。
    dials.lock().expect("拨号记录锁").push(Dial {
        target: target.clone(),
        addr,
    });
    let socket = UdpSocket::bind(bind_addr(&addr))
        .await
        .map_err(|e| format!("绑定回环 UDP：{e}"))?;
    socket
        .send_to(payload, addr)
        .await
        .map_err(|e| format!("发 UDP：{e}"))?;
    let mut buffer = vec![0u8; 65536];
    let (length, _) = timeout(step, socket.recv_from(&mut buffer))
        .await
        .map_err(|_| "回程超时".to_owned())?
        .map_err(|e| format!("收 UDP：{e}"))?;
    session
        .send(app, &buffer[..length], step)
        .await
        .map_err(|e| format!("回程包封：{e}"))?;
    Ok(())
}

/// 服务端一次会话：读 VLESS 头 → 回成功头 → 循环解 XUDP 包封、按目标拨号转发、
/// 回程按同一包封回送。
pub async fn serve_udp(
    socket: TcpStream,
    server: &Server,
    dials: &DialLog,
    step: Duration,
) -> Served {
    let mut packets = Vec::new();
    let mut app = match handshake(socket, server).await {
        Ok(app) => app,
        Err(error) => {
            return Served {
                packets,
                stop: Stop::Failed(error),
            }
        }
    };
    let request = match stream::receive_request(&mut app, &KEY, step).await {
        Ok(request) => request,
        Err(error) => {
            return Served {
                packets,
                stop: Stop::Failed(format!("读 VLESS 头：{error}")),
            }
        }
    };
    if request.command != Command::Mux {
        return Served {
            packets,
            stop: Stop::Failed(format!("命令不是 Mux：{:?}", request.command)),
        };
    }
    if let Err(error) = stream::send_response(&mut app, step).await {
        return Served {
            packets,
            stop: Stop::Failed(format!("写 VLESS 响应头：{error}")),
        };
    }
    let mut session = UdpSession::server();
    loop {
        let received = session.receive(&mut app, super::PAYLOAD_LIMIT, step).await;
        let (target, payload) = match received {
            Ok(value) => value,
            Err(error) => {
                let stop = match &error {
                    // 对端在包封边界关闭：会话正常结束。
                    UdpError::Stream(stream::Error::Io(_)) => Stop::Closed,
                    other => Stop::Failed(format!("XUDP 包封：{other}")),
                };
                return Served { packets, stop };
            }
        };
        packets.push((target.clone(), payload.clone()));
        if let Err(error) = forward(&mut app, &mut session, &target, &payload, dials, step).await {
            return Served {
                packets,
                stop: Stop::Failed(error),
            };
        }
    }
}

/// 起一个 REALITY + UDP 服务端，接受 `count` 条连接（每条连接一个 XUDP 会话）。
pub async fn start_servers(
    server: Arc<Server>,
    port: u16,
    dials: DialLog,
    count: usize,
    step: Duration,
) -> Vec<JoinHandle<Served>> {
    let listener = Arc::new(
        TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("绑定 REALITY 服务端"),
    );
    let mut handles = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = listener.clone();
        let server = server.clone();
        let dials = dials.clone();
        handles.push(tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("接受连接");
            serve_udp(socket, &server, &dials, step).await
        }));
    }
    handles
}
