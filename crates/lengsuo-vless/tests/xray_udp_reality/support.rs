//! 本仓 REALITY 服务端与 UDP 目标的测试夹具。
//!
//! 全部回环地址、临时端口、测试专用假凭据；日志不输出任何密钥材料。
//!
//! 服务端一侧在 [`server`] 里复刻本仓 REALITY 服务端（`reality::server::accept_hello`
//! + `reality::session::server_handshake`），再把 VLESS 主链路与 XUDP 包封接上：
//!
//! ```text
//! 客户端：RealityStream::connect → reality::udp::client_handshake（VLESS 头 + 响应头）
//!        → UdpSession::send / receive（XUDP 包封）
//! 服务端：accept_hello → TLS 1.3 → stream::receive_request → stream::send_response
//!        → UdpSession::receive（解 XUDP 包封）→ 按目标拨号 → 回程按同一包封回送
//! ```

// 复用仓库里既有的共享夹具（凭据、端口、base64、确定性熵源）。
#[path = "../support/mod.rs"]
mod shared;

// 服务端侧夹具（本仓 REALITY 服务端 + XUDP 转发器）。
mod server;

pub use server::*;

use std::{net::SocketAddr, time::Duration};

use lengsuo_vless::{
    reality::udp::UdpSession, reality_config::RealityConfig, reality_link::RealityStream,
};
use ss_core::target::TargetAddr;
use tokio::{io::AsyncReadExt, task::JoinHandle};

use shared::KEY;

/// 用例总截止时间。
pub const DEADLINE: Duration = Duration::from_secs(30);
/// 单次操作截止时间。
pub const STEP: Duration = Duration::from_secs(8);
/// 建流截止时间。
pub const HANDSHAKE: Duration = Duration::from_secs(10);
/// 负例里服务端等残缺包封的截止时间（短，避免用例拖长）。
pub const NEGATIVE_STEP: Duration = Duration::from_secs(2);
/// 服务端 SNI 白名单里的名字。
pub const SERVER_NAME: &str = "www.example.com";
/// 短 ID（配置里的十六进制文本 → `[0x31..0x38]`）。
pub const SHORT_ID_HEX: &str = "3132333435363738";
/// 短 ID 的原始字节。
pub const SHORT_ID: [u8; 8] = *b"12345678";
/// 假域名：hosts 静态映射到回环，**不依赖公网 DNS**。
pub const FAKE_DOMAIN: &str = "udp-reality.test";
/// XUDP 载荷上限。
pub const PAYLOAD_LIMIT: u16 = 2048;

/// 起一个 UDP 回显目标（收到什么原样回什么）。
pub async fn start_echo(bind: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .expect("绑定 UDP 回显");
    let addr = socket.local_addr().expect("读回显端口");
    let handle = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65536];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            if socket.send_to(&buffer[..length], peer).await.is_err() {
                return;
            }
        }
    });
    (addr, handle)
}

/// 客户端：REALITY 建流 → XUDP 会话前置握手（VLESS 请求头 + 响应头）。
pub async fn connect_client(config: &RealityConfig, port: u16) -> Result<RealityStream, String> {
    let mut stream = RealityStream::connect(&format!("127.0.0.1:{port}"), config, HANDSHAKE)
        .await
        .map_err(|e| format!("REALITY 建流：{e}"))?;
    lengsuo_vless::reality::udp::client_handshake(&mut stream, &KEY, STEP)
        .await
        .map_err(|e| format!("VLESS 前置握手：{e}"))?;
    Ok(stream)
}

/// 预留一个 TCP 端口（REALITY 服务端用）。
pub fn reserve_port() -> u16 {
    shared::free_ports(1)[0]
}

/// 回环 IPv4 任意端口。
pub fn any_v4() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// 回环 IPv6（`::1`）任意端口。
pub fn any_v6() -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0)
}

/// 读出库里编码器产出的**合法** XUDP 包封字节（不手写编解码）。
pub async fn valid_envelope(target: &TargetAddr) -> Vec<u8> {
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let mut session = UdpSession::client(target.clone());
    session
        .send(&mut writer, b"envelope", STEP)
        .await
        .expect("编码 XUDP 包封");
    drop(writer);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .await
        .expect("读出 XUDP 包封");
    bytes
}
