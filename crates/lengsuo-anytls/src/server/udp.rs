//! 服务端 **UDP-over-TCP（v2）** 承载：把一条 anytls 流上的 UoT 字节流接到本地
//! UDP 套接字，并把回程报文按同一条 UoT 会话投递回客户端。
//!
//! 对齐参考 anytls-go fd6167a：
//! - `cmd/server/inbound_tcp.go`：流首目的地址含 `udp-over-tcp.arpa` ⇒ 转 UoT 分支，
//!   否则转 `proxyOutboundTCP`（**绝不可回落**）。
//! - `cmd/server/outbound_tcp.go::proxyOutboundUoT`：
//!   `uot.ReadRequest(conn)` → `net.ListenPacket("udp", "")` → `ReportHandshakeSuccess`
//!   → `bufio.CopyPacketConn(ctx, uot.NewConn(conn, *request), bufio.NewPacketConn(c))`。
//! - sing v0.5.1 `common/uot`：`Request{IsConnect, Destination}` 与
//!   `Conn.ReadFrom` / `Conn.WriteTo` 的线格式。
//!
//! ## 服务端线格式（一条 anytls 流承载一条 UoT 会话）
//!
//! ```text
//! [SOCKS5 目的地址 = 魔法域]   <- anytls 帧流的首地址（inbound_tcp.go 判定用）
//! [isConnect(1B)]              <- uot.ReadRequest
//! [SOCKS5 目的地址]            <- uot.ReadRequest（真正的 UDP 目标）
//! [报文]*                      <- [地址?] | 长度(2B BE) | 载荷
//! ```
//!
//! ⚠️ **两处地址编码不同，混用即整体错位**：
//! - **首地址**与**请求头目的地址**走 SOCKS5 ATYP（`0x01` IPv4 / `0x04` IPv6 /
//!   `0x03` 域名）——参考 `uot.ReadRequest` 用的是 `M.SocksaddrSerializer`；
//! - **报文内地址**走 UoT 家族字节（`0x00` IPv4 / `0x01` IPv6 / `0x02` 域名）——
//!   参考 `uot.AddrParser`，**不是** SOCKS5 ATYP。
//!
//! 编解码原语一律复用 [`crate::stream`]（`UotRequest` / `Association` /
//! `Datagram` / `Address`），本模块不另写编解码器。
//!
//! ## fail-closed
//!
//! 识别到魔法域后，本流**只走 UoT 分支**：请求头解析失败、报文截断、地址族非法、
//! 域名超长等一律让会话以错误结束，**不得**回落成 TCP 拨号或静默直连。
use crate::frame::Command;
use crate::stream::{
    socks::SocksAddr, Address, Association, Datagram, StreamError, UdpAssociations, UdpVersion,
    UotRequest,
};
use crate::Error;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::sink::Sink;
use super::streams::StreamFlags;

mod magic;
pub use magic::{classify, version_matches, Magic};

/// 回程读取缓冲：UDP 报文最大 65535 字节。
const RECV_BUF: usize = 65535;

/// 会话内的 UDP-over-TCP 承载表：协议关联（[`UdpAssociations`]）+ 运行态。
#[derive(Default)]
pub struct UotTable {
    /// 协议关联：流编号 → 关联（版本 + 请求头）。登记即代表「这条流归 UoT 管」。
    associations: UdpAssociations,
    /// 运行态：流编号 → 已建立的会话。
    live: HashMap<u32, UdpStream>,
    /// 已识别为 UoT 但请求头尚未到齐：流编号 → 待解析字节 + 观测位 + 代次。
    opening: HashMap<u32, Opening>,
}

/// 请求头尚未到齐时的暂存。
struct Opening {
    bytes: Vec<u8>,
    flags: Arc<StreamFlags>,
    magic: UdpVersion,
    /// 协商出的 AnyTLS 版本：SYNACK 只在 v2 下汇报（参考 `HandshakeSuccess`）。
    version: u8,
}

/// 一条已建立的 UDP-over-TCP 会话（运行态）。
struct UdpStream {
    association: Association,
    /// 报文可能被拆在多帧里：未凑齐的字节留在这里。
    pending: Vec<u8>,
    /// 报文 → 本地 UDP 套接字。
    tx: mpsc::UnboundedSender<Datagram>,
    /// 中继任务句柄。
    ///
    /// 只为在会话结构里留住这个任务（丢弃 `JoinHandle` 只是**分离**任务，任务本身
    /// 仍会跑完：客户端 FIN ⇒ `tx` 关闭 ⇒ 中继任务收尾并按需补 FIN）。不 `abort`：
    /// `abort` 会吞掉中继任务补发的那条 FIN。
    _relay: JoinHandle<()>,
}

impl UotTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 该流编号是否归 UoT 管（已建立，或请求头未到齐）。
    pub fn owns(&self, id: u32) -> bool {
        self.live.contains_key(&id) || self.opening.contains_key(&id)
    }

    /// 登记一条已识别为 UoT 的流（请求头尚未到齐）。
    pub fn open(&mut self, id: u32, magic: UdpVersion, version: u8, flags: Arc<StreamFlags>) {
        self.opening.entry(id).or_insert(Opening {
            bytes: Vec::new(),
            flags,
            magic,
            version,
        });
    }

    /// 喂入一条 UoT 流的字节：请求头未到齐则暂存，到齐则建立会话并继续喂报文。
    pub async fn feed(&mut self, id: u32, data: &[u8], sink: &Sink) -> Result<(), Error> {
        if let Some(live) = self.live.get_mut(&id) {
            live.feed(data)?;
            return Ok(());
        }
        let Some(opening) = self.opening.get_mut(&id) else {
            return Err(Error::Invalid);
        };
        opening.bytes.extend_from_slice(data);
        let decoded = match UotRequest::decode(&opening.bytes) {
            Ok(pair) => pair,
            // 字节不够：等下一帧。
            Err(StreamError::Incomplete) => return Ok(()),
            // 非法请求头（isConnect 非 0/1、地址族非法）⇒ fail-closed。
            Err(_) => return Err(Error::Invalid),
        };
        let (request, used) = decoded;
        let mut opening = self.opening.remove(&id).ok_or(Error::Invalid)?;
        let rest = opening.bytes.split_off(used);
        self.start(id, opening, request, rest, sink).await
    }

    /// 建立会话：本地 UDP 套接字 + SYNACK + 中继任务。
    async fn start(
        &mut self,
        id: u32,
        opening: Opening,
        request: UotRequest,
        rest: Vec<u8>,
        sink: &Sink,
    ) -> Result<(), Error> {
        let Opening {
            flags,
            magic,
            version,
            ..
        } = opening;
        let association = Association::new(magic, request);
        // 参考 `proxyOutboundUoT`：`net.ListenPacket("udp", "")` 每次会话一个新端口。
        let local = match Local::bind().await {
            Ok(local) => local,
            Err(err) => {
                // 参考 `N.ReportHandshakeFailure`：握手失败带错误文本，且只在 v2 下汇报。
                if version >= 2 {
                    sink.control_data(Command::SynAck, id, err.to_string().as_bytes())
                        .await?;
                }
                return Err(Error::Invalid);
            }
        };
        self.associations
            .insert(id, association.clone())
            .map_err(|_| Error::Invalid)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let relay = tokio::spawn(relay_loop(
            id,
            local,
            association.clone(),
            flags,
            sink.clone(),
            rx,
        ));
        let mut live = UdpStream {
            association,
            pending: Vec::new(),
            tx,
            _relay: relay,
        };
        // 请求头之后紧跟的字节就是报文。
        live.feed(&rest)?;
        self.live.insert(id, live);
        // 参考 `Stream.HandshakeSuccess`：`once && peerVersion >= 2` 才写 SYNACK。
        if version >= 2 {
            sink.control(Command::SynAck, id).await?;
        }
        Ok(())
    }

    /// 关闭一条 UoT 流（客户端 FIN / 会话收尾）。
    pub fn remove(&mut self, id: u32) {
        self.opening.remove(&id);
        self.live.remove(&id);
        let _ = self.associations.remove(id);
    }

    /// 关闭全部 UoT 流。
    pub fn clear(&mut self) {
        self.opening.clear();
        self.live.clear();
        self.associations.clear();
    }

    /// 已建立的 UoT 会话数（诊断用）。
    pub fn live_len(&self) -> usize {
        self.live.len()
    }
}

impl UdpStream {
    /// 喂入客户端字节：解析报文并交给本地 UDP 套接字。
    ///
    /// 字节可能被拆在多帧里：先攒着，凑齐一个报文就送走（参考
    /// `uot.Conn.ReadFrom` 是从字节流里读一个完整报文）。
    ///
    /// ⛔ 解析失败（地址族非法 / 载荷超长）一律报错，**不得**把残余字节当普通
    /// TCP 载荷转发。
    fn feed(&mut self, data: &[u8]) -> Result<(), Error> {
        self.pending.extend_from_slice(data);
        loop {
            match self.association.decode_datagram(&self.pending) {
                Ok((datagram, used)) => {
                    self.pending.drain(..used);
                    // 发送失败 = 会话已断：参考 `CopyPacketConn` 的写失败即终止。
                    if self.tx.send(datagram).is_err() {
                        return Err(Error::Invalid);
                    }
                }
                // 字节不够：等下一帧。
                Err(StreamError::Incomplete) => return Ok(()),
                // 其它错误：非法地址族 / 超长载荷 ⇒ fail-closed。
                Err(_) => return Err(Error::Invalid),
            }
        }
    }
}

/// 中继任务：客户端报文 ↔ 本地 UDP 套接字 ↔ 客户端。
///
/// 参考 `bufio.CopyPacketConn(ctx, uot.NewConn(conn, *request), bufio.NewPacketConn(c))`：
/// 双向各一个方向（`CopyPacketConn` 内部就是 upload + download 两组任务）。
async fn relay_loop(
    id: u32,
    local: Local,
    association: Association,
    flags: Arc<StreamFlags>,
    sink: Sink,
    mut rx: mpsc::UnboundedReceiver<Datagram>,
) {
    let mut buffer = vec![0u8; RECV_BUF];
    loop {
        tokio::select! {
            biased;
            // 客户端 → UDP：目标地址 = 报文地址（connect 模式下固定为请求目的地址）。
            datagram = rx.recv() => {
                let Some(datagram) = datagram else { break };
                let Some(target) = target_of(&association, &datagram) else { break };
                let Ok(target) = resolve(target).await else { break };
                if local.send_to(&datagram.payload, target).await.is_err() { break; }
            }
            // UDP → 客户端：回程报文按同一 UoT 会话编码（connect 模式不带地址）。
            received = local.recv_from(&mut buffer) => {
                let Ok((count, source)) = received else { break };
                let datagram = Datagram {
                    address: if association.carries_address() {
                        Some(address_of(source))
                    } else {
                        None
                    },
                    payload: buffer[..count].to_vec(),
                };
                let Ok(bytes) = association.encode_datagram(&datagram) else { break };
                if sink.data(id, &bytes).await.is_err() { break; }
            }
        }
    }
    // 参考 TCP 路径的 `collect_target`：客户端未先 FIN 时补一条 FIN。
    if !flags.client_fin() {
        let _ = sink.control(Command::Fin, id).await;
    }
}

/// 会话内的本地 UDP 套接字。
///
/// 参考 `net.ListenPacket("udp", "")`：Go 侧绑定到**未指定地址**（`[::]:0`，双栈），
/// 因此同一个套接字既能发 IPv4 也能发 IPv6。本仓用 `[::]:0` 复刻这一点；
/// 环境不支持 IPv6 时退回 `0.0.0.0:0`（仅 IPv4，此时 IPv6 目标不可达）。
struct Local {
    socket: UdpSocket,
    /// 是否双栈（`[::]:0`）：IPv4 目标需写成 v4 映射地址才能发出去。
    dual: bool,
}

impl Local {
    /// 绑定本地套接字。
    async fn bind() -> Result<Self, std::io::Error> {
        match UdpSocket::bind("[::]:0").await {
            Ok(socket) => Ok(Self { socket, dual: true }),
            // 环境无 IPv6 ⇒ 退回 IPv4-only。
            Err(_) => Ok(Self {
                socket: UdpSocket::bind("0.0.0.0:0").await?,
                dual: false,
            }),
        }
    }

    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.socket
            .send_to(payload, map_target(target, self.dual))
            .await
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer).await
    }
}

/// 双栈套接字上，IPv4 目标要写成 v4 映射地址（`::ffff:a.b.c.d`），
/// 否则 `send_to` 会因地址族不符而失败。
fn map_target(target: SocketAddr, dual: bool) -> SocketAddr {
    if !dual {
        return target;
    }
    match target {
        SocketAddr::V4(v4) => SocketAddr::V6(std::net::SocketAddrV6::new(
            v4.ip().to_ipv6_mapped(),
            v4.port(),
            0,
            0,
        )),
        v6 => v6,
    }
}

/// 客户端报文的目标地址：connect 模式取请求目的地址，否则取报文自带地址。
fn target_of(association: &Association, datagram: &Datagram) -> Option<Address> {
    if association.carries_address() {
        datagram.address.clone()
    } else {
        Some(uot_address(&association.request.destination))
    }
}

/// 域名 → IP：参考侧 `M.Socksaddr.UDPAddr()` 对域名返回 nil（写 UDP 必然失败），
/// 本仓补上解析，让域名目标可用（见分文档「偏离清单」）。
///
/// 多个候选时优先 IPv4：回环测试要确定性，且 UDP 中继的常见目标是 IPv4。
async fn resolve(address: Address) -> Result<SocketAddr, Error> {
    match address {
        Address::Ipv4(raw, port) => Ok(SocketAddr::from((std::net::Ipv4Addr::from(raw), port))),
        Address::Ipv6(raw, port) => Ok(SocketAddr::from((std::net::Ipv6Addr::from(raw), port))),
        Address::Fqdn(name, port) => {
            let candidates: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), port))
                .await
                .map_err(|_| Error::Invalid)?
                .collect();
            candidates
                .iter()
                .find(|addr| addr.is_ipv4())
                .or_else(|| candidates.first())
                .copied()
                .ok_or(Error::Invalid)
        }
    }
}

/// `SocketAddr` → UoT 地址（家族字节 `0x00`/`0x01`）。
fn address_of(addr: SocketAddr) -> Address {
    match addr {
        SocketAddr::V4(v4) => Address::Ipv4(v4.ip().octets(), v4.port()),
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            // 双栈套接字上收到的 IPv4 源是 v4 映射地址 ⇒ 还原成 IPv4
            // （参考 Go 的 `sockaddrToUDPAddr` 同样把 v4 映射地址归一为 4 字节 IP）。
            Some(v4) => Address::Ipv4(v4.octets(), v6.port()),
            None => Address::Ipv6(v6.ip().octets(), v6.port()),
        },
    }
}

/// SOCKS5 地址（请求头里的）→ UoT 地址（报文里的）。
fn uot_address(addr: &SocksAddr) -> Address {
    match addr {
        SocksAddr::Ipv4(raw, port) => Address::Ipv4(*raw, *port),
        SocksAddr::Ipv6(raw, port) => Address::Ipv6(*raw, *port),
        SocksAddr::Fqdn(name, port) => Address::Fqdn(name.clone(), *port),
    }
}
