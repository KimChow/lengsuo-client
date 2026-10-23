//! SOCKS5 UDP ASSOCIATE 的本地中继面（**仅回环**）。
//!
//! 只负责客户端 ↔ 本进程之间的数据报封装/解封装；不做「UDP 过隧道」。
//!
//! 数据报格式（RFC 1928 §7）：
//! `RSV(2) | FRAG(1) | ATYP | DST.ADDR | DST.PORT | DATA`
//!
//! 非法数据报（RSV 非零 / FRAG 非零 / 地址解析失败 / 非回环来源）一律**丢弃**，
//! 只记 debug 日志，不断开关联。

use std::net::SocketAddr;
use std::sync::Mutex;

use tokio::net::{TcpStream, UdpSocket};

use ss_core::target::TargetAddr;

use super::{
    handshake_greeting, read_request_header, read_target, send_reply, send_reply_bnd, Auth,
    Buffered, InboundError,
};

const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// `RSV(2) + FRAG(1)`。
const DATAGRAM_HEADER_LEN: usize = 3;
/// UDP 数据报理论上限；超过的会由内核截断。
const MAX_DATAGRAM: usize = 65535;

/// 一次 UDP 关联：持有 TCP 控制连接（关闭即结束）与回环中继 socket。
pub struct UdpAssociation {
    control: TcpStream,
    relay: UdpSocket,
    local: SocketAddr,
    /// 客户端 UDP 源地址，从收到的第一个合法数据报学得（回程目的地）。
    client: Mutex<Option<SocketAddr>>,
}

impl UdpAssociation {
    /// 返回给客户端的 BND 地址（回环 UDP socket 的实际地址）。
    #[must_use]
    pub fn relay_addr(&self) -> SocketAddr {
        self.local
    }

    /// 收一个客户端数据报，解出 `(target, payload)`。
    ///
    /// 非法或应丢弃的数据报返回 `Ok(None)`；调用方需自行继续收。
    pub async fn recv_from_client(&self) -> Result<Option<(TargetAddr, Vec<u8>)>, InboundError> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (n, src) = self.relay.recv_from(&mut buf).await?;
        if !src.ip().is_loopback() {
            tracing::debug!(%src, "drop UDP datagram from non-loopback source");
            return Ok(None);
        }
        let Some((target, payload)) = decode_datagram(&buf[..n]) else {
            return Ok(None);
        };
        if let Ok(mut slot) = self.client.lock() {
            *slot = Some(src);
        }
        Ok(Some((target, payload)))
    }

    /// 把回程数据报封给客户端；`from` 作为报文的源地址。
    pub async fn send_to_client(
        &self,
        from: &TargetAddr,
        payload: &[u8],
    ) -> Result<(), InboundError> {
        let Some(client) = self.client.lock().ok().and_then(|slot| *slot) else {
            return Err(InboundError::Protocol("no client datagram received yet"));
        };
        let mut buf = Vec::with_capacity(DATAGRAM_HEADER_LEN + from.encoded_len() + payload.len());
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
        from.encode_checked(&mut buf)
            .map_err(|_| InboundError::Protocol("invalid source address"))?;
        buf.extend_from_slice(payload);
        self.relay.send_to(&buf, client).await?;
        Ok(())
    }

    /// 控制连接是否已关闭（关闭即关联结束）。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        let mut probe = [0u8; 1];
        match self.control.try_read(&mut probe) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
        }
    }
}

/// 完成 UDP ASSOCIATE 握手并绑定回环 UDP socket。
pub(super) async fn handshake_udp(
    stream: TcpStream,
    auth: Option<&Auth>,
) -> Result<UdpAssociation, InboundError> {
    let mut conn = Buffered::new(stream);
    handshake_greeting(&mut conn, auth).await?;

    let (cmd, atyp) = read_request_header(&mut conn).await?;
    if cmd != CMD_UDP_ASSOCIATE {
        send_reply(&mut conn.stream, 0x07).await?;
        return Err(InboundError::UnsupportedCommand(cmd));
    }
    // 客户端声明的目标（通常 0.0.0.0:0）本卡不使用，但必须把地址读完。
    let _client_declared = read_target(&mut conn, atyp).await?;

    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let local = relay.local_addr()?;
    send_reply_bnd(&mut conn.stream, local).await?;

    // 控制连接上不应再有数据；残留字节按 RFC 无意义，直接丢弃。
    let Buffered { stream, .. } = conn;
    Ok(UdpAssociation {
        control: stream,
        relay,
        local,
        client: Mutex::new(None),
    })
}

/// 解析一个客户端数据报；任何不合法之处都返回 `None`（丢弃）。
fn decode_datagram(buf: &[u8]) -> Option<(TargetAddr, Vec<u8>)> {
    if buf.len() < DATAGRAM_HEADER_LEN {
        tracing::debug!("drop undersized UDP datagram");
        return None;
    }
    if buf[0] != 0 || buf[1] != 0 {
        tracing::debug!("drop UDP datagram with nonzero RSV");
        return None;
    }
    if buf[2] != 0 {
        tracing::debug!(frag = buf[2], "drop fragmented UDP datagram");
        return None;
    }
    let (target, used) = match TargetAddr::decode(&buf[DATAGRAM_HEADER_LEN..]) {
        Ok(decoded) => decoded,
        Err(_) => {
            tracing::debug!("drop UDP datagram with malformed address");
            return None;
        }
    };
    Some((target, buf[DATAGRAM_HEADER_LEN + used..].to_vec()))
}
