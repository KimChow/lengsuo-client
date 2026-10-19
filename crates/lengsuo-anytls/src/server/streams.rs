//! 单流的中继：把客户端 PUSH 的字节写进目标，把目标的字节读回并转成 PUSH 帧。
//!
//! 对齐参考 `cmd/server/outbound_tcp.go::proxyOutboundTCP`（DialContext → 汇报握手 →
//! `bufio.CopyConn` 双向中继）与 `session/stream.go` 的流生命周期：
//! - 出站连接成功 → 空载荷 SYNACK；失败 → 带错误文本的 SYNACK（v2）。
//! - 客户端 FIN → 本地关流，不再回 FIN；目标先 EOF → 服务端主动补一条 FIN。
//! - SYNACK 只汇报一次（参考 `reportOnce`）。
//!
//! 出站目标由外部按 SOCKS5 地址解析后用 `SocketAddr` 传入，不支持 UDP。
use super::sink::Sink;
use crate::frame::Command;
use crate::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time::timeout;

/// 回程一次读取的目标字节数。
const CHUNK: usize = 2048;
/// 出站拨号超时。
const DIAL: Duration = Duration::from_secs(10);

/// 单流跨任务共享的观测位。
#[derive(Default)]
pub struct StreamFlags {
    /// 客户端已 FIN：回程任务不再补发 FIN。
    client_fin: AtomicBool,
    /// 已汇报过 SYNACK（参考 `reportOnce`）。
    reported: AtomicBool,
    /// 转发给目标的字节数。
    pub to_target: AtomicUsize,
    /// 回程给客户端的载荷字节数。
    pub to_client: AtomicUsize,
}

impl StreamFlags {
    pub fn client_fin(&self) -> bool {
        self.client_fin.load(Ordering::Relaxed)
    }
    fn mark_reported(&self) -> bool {
        !self.reported.swap(true, Ordering::Relaxed)
    }
}

/// 一条流在服务端会话内的句柄。
pub struct Stream {
    /// PUSH 载荷的去向；`None` 表示出站未建连或已关闭。
    sender: Option<UnboundedSender<Vec<u8>>>,
    /// 未解析出完整目标地址时缓存的字节（参考：首帧 PUSH 的前缀是 SOCKS 地址）。
    pending: Vec<u8>,
    /// 已解析出的目标地址，防止重复拨号。
    endpoint: Option<std::net::SocketAddr>,
    pub flags: Arc<StreamFlags>,
    /// 出站连接失败的流：后续载荷一律丢弃（参考断连后写失败）。
    pub failed: bool,
}

impl Stream {
    /// 未建连的占位（SYN 之后、首帧数据解析出目标之前）。
    pub fn pending() -> Self {
        Self {
            sender: None,
            pending: Vec::new(),
            endpoint: None,
            flags: Arc::new(StreamFlags::default()),
            failed: false,
        }
    }

    /// 出站连接是否已建立（后续 PUSH 直接转发）。
    pub fn sender_ready(&self) -> bool {
        self.sender.is_some()
    }

    /// 拨号并建立中继；返回是否成功。
    ///
    /// 无论成功失败都在 v2 下写一条 SYNACK（失败时携带错误文本），
    /// 且只写一次——与参考 `HandshakeSuccess` / `HandshakeFailure` 的 `reportOnce` 一致。
    pub async fn connect(
        &mut self,
        sid: u32,
        endpoint: std::net::SocketAddr,
        version: u8,
        sink: &Sink,
    ) -> Result<bool, Error> {
        let target = match timeout(DIAL, TcpStream::connect(endpoint)).await {
            Ok(Ok(socket)) => socket,
            Ok(Err(err)) => {
                self.failed = true;
                if version >= 2 && self.flags.mark_reported() {
                    // 参考 writeControlFrame：写失败即关闭会话。
                    sink.control_data(Command::SynAck, sid, err.to_string().as_bytes())
                        .await?;
                }
                return Ok(false);
            }
            Err(_) => {
                self.failed = true;
                return Err(Error::Timeout);
            }
        };
        let (read, write) = target.into_split();
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.sender = Some(tx);
        let flags = Arc::clone(&self.flags);
        tokio::spawn(feed_target(write, rx));
        tokio::spawn(collect_target(sid, read, Arc::clone(&flags), sink.clone()));
        if version >= 2 && self.flags.mark_reported() {
            sink.control(Command::SynAck, sid).await?;
        }
        Ok(true)
    }

    /// 缓存一段尚未解析目标地址的 PUSH 载荷。
    pub fn push_pending(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);
    }

    /// 若缓存里已够一段完整 SOCKS5 地址就解析并消耗；不足则返回 `None` 等下一帧。
    ///
    /// 参考 `M.SocksaddrSerializer.ReadAddrPort(stream)`：它直接从流里读，
    /// 而帧模式下地址可能跨帧，因此这里显式缓存未消费的字节。
    pub fn take_endpoint(&mut self) -> Result<Option<std::net::SocketAddr>, Error> {
        if let Some(endpoint) = self.endpoint {
            return Ok(Some(endpoint));
        }
        let (addr, used) = match ss_core::target::TargetAddr::decode(&self.pending) {
            Ok(pair) => pair,
            Err(ss_core::Error::TooShort { .. }) => return Ok(None),
            Err(_) => return Err(Error::Invalid),
        };
        self.pending.drain(..used);
        let endpoint = to_socket_addr(&addr).ok_or(Error::Invalid)?;
        self.endpoint = Some(endpoint);
        Ok(Some(endpoint))
    }

    /// 已解析目标地址后，把剩余缓存一次交给出站通道（并计入转发统计）。
    pub fn flush_pending(&mut self) {
        let payload = std::mem::take(&mut self.pending);
        if !payload.is_empty() {
            self.write_to_target(&payload);
        }
    }

    /// 客户端 PUSH 载荷 → 目标。返回计入统计的字节数。
    pub fn write_to_target(&mut self, data: &[u8]) -> usize {
        if self.failed || data.is_empty() {
            return 0;
        }
        match self.sender.as_ref() {
            Some(sender) if sender.send(data.to_vec()).is_ok() => {
                self.flags
                    .to_target
                    .fetch_add(data.len(), Ordering::Relaxed);
                data.len()
            }
            _ => 0,
        }
    }

    /// 客户端 FIN：关闭出站通道并标记；目标侧半关闭由 `feed_target` 完成。
    pub fn close_local(&mut self) {
        self.sender = None;
        self.flags.client_fin.store(true, Ordering::Relaxed);
    }
}

/// SOCKS5 目标地址 → 可直接拨号的 `SocketAddr`；域名在此不做解析（本卡不涉及 DNS）。
fn to_socket_addr(addr: &ss_core::target::TargetAddr) -> Option<std::net::SocketAddr> {
    match addr {
        ss_core::target::TargetAddr::V4(octets, port) => Some(std::net::SocketAddr::from((
            std::net::Ipv4Addr::from(*octets),
            *port,
        ))),
        ss_core::target::TargetAddr::V6(octets, port) => Some(std::net::SocketAddr::from((
            std::net::Ipv6Addr::from(*octets),
            *port,
        ))),
        ss_core::target::TargetAddr::Domain(_, _) => None,
    }
}

/// 出站方向：把客户端数据按序写进目标，通道关闭后半关闭写出。
async fn feed_target(
    mut write: tokio::net::tcp::OwnedWriteHalf,
    mut inbound: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(bytes) = inbound.recv().await {
        if write.write_all(&bytes).await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

/// 回程方向：读目标直到 EOF，按块发 PUSH；本端未先收到 FIN 时补发一条 FIN。
async fn collect_target(
    sid: u32,
    mut read: tokio::net::tcp::OwnedReadHalf,
    flags: Arc<StreamFlags>,
    sink: Sink,
) {
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let count = match read.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        if sink.data(sid, &buffer[..count]).await.is_err() {
            return;
        }
        flags.to_client.fetch_add(count, Ordering::Relaxed);
    }
    if !flags.client_fin() {
        let _ = sink.control(Command::Fin, sid).await;
    }
}
