//! `tests/udp_pool.rs` 的共享夹具：回显后端、池配置与 Xray 互通夹具。
//!
//! 夹具写法对齐既有参考测试（`tests/xray_trojan_client.rs` / `tests/xray_trojan_udp.rs`）：
//! rcgen 现场自签证书 + 显式信任、临时端口、假口令、真实回环 UDP 回显后端。

#![allow(dead_code)]
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient};
use lengsuo_trojan::server::{Inbound, Server, Timeouts, Validator};
use lengsuo_trojan::udp_pool::{PoolConfig, UdpPool};
use lengsuo_trojan::TargetAddr;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

pub const WAIT: Duration = Duration::from_secs(8);
pub const TOTAL: Duration = Duration::from_secs(60);
/// 单包载荷上限：取参考服务端策略值（`protocol.go` 的 `maxLength = 8192`）。
pub const LIMIT: usize = lengsuo_trojan::stream::REFERENCE_MAX_DATAGRAM_PAYLOAD;

/// 参考侧 UDP 回显的**实测**稳定上限：8180 字节。
///
/// Xray 的 `PacketReader` 把整帧读入 `buf.Size = 8192` 的缓冲，帧头
/// （地址 7 + 长度 2 + CRLF 2 = 11）占用后余量有限，边界附近（8182 起）回程
/// 开始不稳定失败——这是**参考侧**上限，不是本仓限制；本仓 `udp::MAX_PAYLOAD_LEN`
/// 仍按协议线上的 65535。载荷分档按该口径取，**不用 65535 去卡参考侧**。
pub const REF_MAX: usize = 8180;

/// 回显后端：原样回写收到的数据报，并按**源地址**统计收包数。
///
/// 按源地址计数是关键：同一 socket 发出的多个包共享同一个源端口，
/// 计数即“同一出站 socket”的独立观测面（而不是“没报错”）。
pub struct Echo {
    pub port: u16,
    /// 源地址 → 收包数。
    seen: Arc<Mutex<HashMap<SocketAddr, usize>>>,
    /// 独立观测面：总收包数。
    pub total: Arc<AtomicUsize>,
    /// 独立观测面：见过的**不同源地址数**（= 出站 socket 数）。
    pub peers: Arc<AtomicUsize>,
}

impl Echo {
    /// 起一个回环 UDP 回显服务。
    pub async fn spawn() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(HashMap::new()));
        let total = Arc::new(AtomicUsize::new(0));
        let peers = Arc::new(AtomicUsize::new(0));
        let task_seen = Arc::clone(&seen);
        let task_total = Arc::clone(&total);
        let task_peers = Arc::clone(&peers);
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                task_total.fetch_add(1, Ordering::SeqCst);
                {
                    let mut map = task_seen.lock().unwrap();
                    let counter = map.entry(peer).or_insert(0);
                    *counter += 1;
                    if *counter == 1 {
                        task_peers.fetch_add(1, Ordering::SeqCst);
                    }
                }
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        });
        Self {
            port,
            seen,
            total,
            peers,
        }
    }

    /// 全部源地址的收包数（按源地址聚合）。
    pub fn counts(&self) -> Vec<usize> {
        let mut values: Vec<usize> = self.seen.lock().unwrap().values().copied().collect();
        values.sort_unstable();
        values
    }
}

/// 池配置：统一的测试默认值。
pub fn config() -> PoolConfig {
    PoolConfig {
        idle_timeout: WAIT,
        max_entries: 8,
        cone: false,
        payload_limit: LIMIT,
    }
}

/// 构造一个回环 IPv4 目标。
pub fn v4(port: u16) -> TargetAddr {
    TargetAddr::V4([127, 0, 0, 1], port)
}

/// 收取一个回程数据报（带总超时）。
pub async fn recv_reply(pool: &UdpPool) -> (TargetAddr, Vec<u8>) {
    let inbound = timeout(WAIT, pool.recv())
        .await
        .expect("回程超时")
        .expect("回程通道已关闭");
    (inbound.address, inbound.payload)
}

/// 现场自签证书身份（rcgen），供本仓 TLS 服务端与 Xray 客户端共用。
pub struct Identity {
    cert: rcgen::CertifiedKey,
}

impl Identity {
    pub fn new() -> Self {
        Self {
            cert: rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap(),
        }
    }

    /// 本仓 TLS 入站。
    pub fn inbound(&self) -> Inbound {
        Inbound::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }

    /// 本仓 TLS 客户端（供本仓侧直连时用）。
    pub fn client(&self) -> TlsClient {
        TlsClient::new("localhost", [self.cert.cert.der().clone()], WAIT).unwrap()
    }

    /// Xray 客户端的 TLS 出站设置：显式信任本仓自签证书（不跳过校验）。
    pub fn client_settings(&self) -> Value {
        json!({"security":"tls","tlsSettings":{"serverName":"localhost",
            "disableSystemRoot":true,"certificates":[{"usage":"verify",
            "certificate":self.cert.cert.pem().lines().collect::<Vec<_>>()}]}})
    }
}

/// 起本仓 trojan 服务端（TCP + UDP 关联都在同一 TLS 端口上），返回端口。
pub async fn spawn_rust_tls_server(
    identity: &Identity,
    password: &str,
) -> (u16, tokio::task::JoinHandle<()>) {
    let mut validator = Validator::new();
    validator.add("interop@example.com", password).unwrap();
    let server = Server::with_tls(
        validator,
        Timeouts::new(WAIT, WAIT).unwrap(),
        identity.inbound(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let _ = server.accept_loop(listener).await;
    });
    (port, task)
}

/// Xray 配置：本地 socks5 入站（**启用 UDP**）+ 指向本仓服务端的 trojan 出站。
pub fn xray_config(socks_port: u16, rust_port: u16, password: &str, identity: &Identity) -> Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks",
            "settings":{"auth":"noauth","udp":true}}],
        "outbounds":[{"protocol":"trojan","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"password":password}]},
            "streamSettings":identity.client_settings()}]})
}

/// SOCKS5 UDP 关联：完成 TCP 握手与 UDP ASSOCIATE，返回（回程中继地址，TCP 控制连接）。
///
/// **TCP 控制连接必须由调用方持有到用例结束**：参考 `proxy/socks/server.go` 的
/// `handleUDP` 会 `io.Copy` 直到客户端关闭该连接，连接一断，关联即结束。
///
/// 中继地址取自服务端应答（参考 `proxy/socks/protocol.go` 的
/// `writeSocks5Response`：地址取连接本地 IP，端口取入站端口）。
pub async fn socks5_udp_associate(proxy_port: u16) -> std::io::Result<(SocketAddr, TcpStream)> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::other("socks 协商失败"));
    }
    // UDP ASSOCIATE：命令 0x03，地址 0.0.0.0:0（按 RFC 1928 表示“由服务端决定”）。
    let mut request = vec![0x05, 0x03, 0x00, 0x01];
    request.extend_from_slice(&[0, 0, 0, 0]);
    request.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "socks UDP ASSOCIATE 失败",
        ));
    }
    let extra = match head[3] {
        1 => 4 + 2,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0]) + 2
        }
        4 => 16 + 2,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "非法 bind ATYP",
            ))
        }
    };
    let mut tail = vec![0u8; extra];
    stream.read_exact(&mut tail).await?;
    // 应答的 bind 地址取连接本地 IP、端口取入站端口（socks 入站的 TCP 与 UDP 同端口）。
    let port = u16::from_be_bytes([tail[extra - 2], tail[extra - 1]]);
    Ok((
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
        stream,
    ))
}

/// 发送一个 SOCKS5 UDP 数据报：RSV(2) + FRAG(1) + 地址 + 载荷。
pub async fn socks5_udp_send(
    socket: &UdpSocket,
    relay: SocketAddr,
    target: &TargetAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut datagram = vec![0u8, 0u8, 0u8];
    target.encode_into(&mut datagram);
    datagram.extend_from_slice(payload);
    socket.send_to(&datagram, relay).await?;
    Ok(())
}

/// 收取一个 SOCKS5 UDP 回程数据报，返回（来源地址，载荷）。
pub async fn socks5_udp_recv(socket: &UdpSocket) -> std::io::Result<(TargetAddr, Vec<u8>)> {
    let mut buf = vec![0u8; 65535];
    let (size, _) = socket.recv_from(&mut buf).await?;
    let datagram = &buf[..size];
    if datagram.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP 回程过短",
        ));
    }
    if datagram[2] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP 回程分片标记非零",
        ));
    }
    let (address, used) = TargetAddr::decode(&datagram[3..])
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    Ok((address, datagram[3 + used..].to_vec()))
}
