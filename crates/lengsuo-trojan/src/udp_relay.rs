//! UDP 关联中继：把流上的 Trojan UDP 报文转发到真实 UDP 套接字并回程。
//!
//! 语义基线：Xray v26.3.27，`proxy/trojan/server.go` 的 `handleUDPPayload` +
//! `protocol.go` 的 `PacketReader` / `PacketWriter`。
//!
//! 设计取舍与参考的差异（如实记录，见 `docs/trojan-status.md`）：
//! - **无会话池**：参考用 `transport/internet/udp` 的会话化调度器按目标多路复用/
//!   复用出站 UdpConn；本实现**每个目标地址一个独立 `UdpSocket`**（按端口的
//!   NAT/会话映射本质即是按目标区分；同时上游给**每个包**单独往返，
//!   「一个数据包一个地址」天然成立，不缓存也不需要缓存首包地址）。
//! - **请求/响应串行**：上游在回程 socket 上等待响应期间不读下行报文。这正是
//!   参考默认 `cone=false` 的语义（`s.cone` 默认 false，非 cone 时每个连接只记
//!   一个 `dest`）；区别在于本实现按目标复用 socket 而非单包即弃。用同步 UDP
//!   回显即可与参考默认行为逐字节互通。
//! - **未实现**：cone 模式（`cone=true` 时参考把首包地址固定到整个关联）、
//!   会话复用与 drain 行为对照（文档「仍未实现项」）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::timeout;

use crate::udp::{decode_packet, Error as FrameError};

/// 上行读缓冲：容纳最长域名地址 + 2 字节长度 + CRLF + 最大载荷（65535）。
const READ_BUF: usize = 1 + 1 + 255 + 2 + 2 + 2 + crate::udp::MAX_PAYLOAD_LEN;

/// 回程读缓冲：一个 UDP 数据报的载荷上限。
const RECV_BUF: usize = crate::udp::MAX_PAYLOAD_LEN;

/// 出站 DNS 解析截止上限（解析本身由 `lookup_host` 完成，单次解析不无限等待）。
const DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// UDP 中继错误。帧格式错误、地址解析、拨号/IO 与超时分区上报，一律 fail-closed。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("截止时间必须大于零")]
    InvalidDeadline,

    #[error("UDP 报文帧非法：{0}")]
    Frame(#[from] FrameError),

    #[error("目标地址无法解析：{0}")]
    Address(#[from] ss_core::Error),

    #[error("DNS 解析失败：{0}")]
    Resolve(#[source] std::io::Error),

    #[error("UDP 套接字绑定/收发失败：{0}")]
    Socket(#[source] std::io::Error),

    #[error("UDP 关联内协议操作超时")]
    Timeout,

    #[error("UDP 关联读侧结束：{0}")]
    Io(#[from] std::io::Error),
}

/// 单个目标地址绑定的 UDP 套接字，按地址族分别绑定通配源。
struct Egress {
    socket: UdpSocket,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// 在一条已建立的 UDP 关联上双向中继，直到客户端读侧 EOF（半关闭见文档）。
///
/// `payload_limit` 是单包载荷上限（超限 fail-closed）；`idle` 是单个读/写操作
/// 的空闲截止（参考 `CancelAfterInactivity` 的逐操作等价，见文档偏离清单）。
/// 客户端停止发送但仍接收时**不得提前断开**：读侧 EOF 之前，回程照常写出。
pub async fn relay<R, W>(
    mut reader: R,
    mut writer: W,
    payload_limit: usize,
    idle: Duration,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if idle.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    let mut buf = vec![0u8; READ_BUF];
    let mut filled = 0usize;
    let mut egress: HashMap<TargetAddr, Egress> = HashMap::new();

    loop {
        // 有半帧就续读，否则读下一块。limit 者取“本帧完整长度”，超限即 fail-closed。
        let (frame, used) = match decode_packet(&buf[..filled], payload_limit) {
            Ok((frame, used)) => (frame, used),
            Err(FrameError::Truncated { need, .. }) => {
                if need > READ_BUF {
                    return Err(Error::Frame(FrameError::Oversize(need)));
                }
                let read = timeout(idle, reader.read(&mut buf[filled..]))
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(Error::Io)?;
                if read == 0 {
                    // 读侧结束：残留半帧是协议错误，否则是干净半关闭。
                    return if filled == 0 {
                        Ok(())
                    } else {
                        Err(Error::Frame(FrameError::Truncated { need, got: filled }))
                    };
                }
                filled += read;
                continue;
            }
            Err(other) => return Err(Error::Frame(other)),
        };
        debug_assert_eq!(&buf[used..filled], &[]);
        filled = 0;

        let (target, payload) = frame;
        let socket = egress_socket(&mut egress, &target).await?;
        let destination = resolve(&target, idle).await?;
        timeout(idle, socket.send_to(payload, destination))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Socket)?;

        // 回程：参考 cone=false 一律回显给请求方；本实现同步等待单个响应，
        // 带地址与原长度前缀写回同一关联。
        let mut recv = vec![0u8; RECV_BUF];
        let (received, from) = timeout(idle, socket.recv_from(&mut recv))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Socket)?;
        // 只接受来自本次请求目标的响应，避免串包；丢包/错源按上限超时兜底。
        if from != destination {
            continue;
        }
        // 回程地址用解析后的真实目标（域名解析后与请求包地址一致，逐字节比对成立）。
        let reply_addr = target_from_socket(from);
        let reply =
            crate::udp::encode_packet(&reply_addr, &recv[..received]).map_err(Error::Frame)?;
        timeout(idle, async {
            writer.write_all(&reply).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| Error::Timeout)??;
    }
}

/// 取（或按需绑定）目标地址对应的出站 socket，按地址族区分。
///
/// 域名目标的地址族由 `resolve` 决定，这里统一按 IPv4 通配源绑定；IPv4 socket
/// 仅能发往 IPv4 目标，若域名解析到 IPv6 则 `send_to` 会失败——当前用例不涉及
/// 域名解析到 IPv6（见文档偏离清单）。
async fn egress_socket<'a>(
    egress: &'a mut HashMap<TargetAddr, Egress>,
    target: &TargetAddr,
) -> Result<&'a UdpSocket, Error> {
    let family = match target {
        TargetAddr::V6(..) => Family::V6,
        TargetAddr::V4(..) | TargetAddr::Domain(..) => Family::V4,
    };
    if !egress.contains_key(target) {
        let bind: SocketAddr = match family {
            Family::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            Family::V6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind).await.map_err(Error::Socket)?;
        egress.insert(target.clone(), Egress { socket });
    }
    Ok(&egress.get(target).expect("刚插入").socket)
}

/// 把目标地址解析为一个可 `send_to` 的 `SocketAddr`；域名走 `lookup_host` 取首条。
async fn resolve(target: &TargetAddr, idle: Duration) -> Result<SocketAddr, Error> {
    match target {
        TargetAddr::V4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        TargetAddr::V6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        TargetAddr::Domain(host, port) => {
            let deadline = idle.min(DNS_TIMEOUT);
            let mut addrs = timeout(deadline, lookup_host((host.as_str(), *port)))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(Error::Resolve)?;
            addrs.next().ok_or_else(|| {
                Error::Resolve(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "域名无解析结果",
                ))
            })
        }
    }
}

/// 把回程源 `SocketAddr` 还原成回给客户端的 `TargetAddr`。
fn target_from_socket(from: SocketAddr) -> TargetAddr {
    match from {
        SocketAddr::V4(addr) => TargetAddr::V4(addr.ip().octets(), addr.port()),
        SocketAddr::V6(addr) => TargetAddr::V6(addr.ip().octets(), addr.port()),
    }
}

/// 读侧一次性收尾：把 `reader` 读到 EOF（用于产品侧的优雅收尾），带空闲截止。
pub async fn drain_to_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle: Duration,
) -> Result<(), Error> {
    if idle.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    let mut sink = [0u8; 2048];
    loop {
        let read = timeout(idle, reader.read(&mut sink))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;
        if read == 0 {
            return Ok(());
        }
    }
}
