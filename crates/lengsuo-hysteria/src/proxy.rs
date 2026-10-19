//! TCP/UDP 业务的承载层（对齐 `proxy/hysteria/client.go` `Process` 的
//! TCP/UDP 分支、`conn.go` `interConn`/`InterUdpConn` 与 `frag.go`）。
//!
//! TCP：一条 QUIC 双向流 = 一个代理连接。首写内容为
//! `varint(0x401) + TCPRequest`（`TcpRequest::encode` 已含帧类型，与
//! `interConn.Write` 的 client 分支 + `WriteTCPRequest` 逐字节一致），
//! 随后读 `TCPResponse`（status/message/padding），status=0 才开始双向转
//! 发。响应帧后的字节属于目标数据，保留在 `leftover` 中不吞掉。
//!
//! UDP：每条 QUIC datagram = 一条 UDPMessage，前 4 字节为会话 ID
//! （`udp.rs` 编码时 SessionID 写 0，发送层覆盖为真实值，与参考
//! `Serialize` 注释掉 SessionID + `InterUdpConn.Write` 覆写的组合一致）。
//! 超限报文按参考 `UDPWriter` 路径分片（随机 packet id + `frag_udp_message`）；
//! 入站经 `OwnedDefragger` 重组（`fragment.rs` 的 Defragger 借用入参字节，
//! 无法跨多次 channel 接收存活，这里按 frag.go 同一规则实现 owned 版）。

use crate::fragment::frag_udp_message;
use crate::h3_auth;
use crate::padding::Range;
use crate::quic::{ConnectError, HysteriaClient, UdpSendError, UdpSession};
use crate::tcp::{Status, TcpRequest, TcpResponse};
use crate::udp::UdpMessage;

/// TCPResponse 增量读取的缓冲上限：1 + 9 + 2048 + 9 + 4096 的上界。
const MAX_RESPONSE_BUFFER: usize = 8192;

/// 承载层错误。错误文本不包含认证密码与目标地址内容。
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("QUIC 流打开失败: {0}")]
    Connect(#[from] ConnectError),
    #[error("帧编码/解码失败: {0}")]
    Frame(#[from] crate::Error),
    #[error("流写入失败: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("流读取失败: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("流已关闭: {0}")]
    Closed(#[from] quinn::ClosedStream),
    #[error("对端在响应帧完成前关闭了流")]
    PrematureEof,
    #[error("响应帧超过缓冲上限")]
    ResponseTooLarge,
    #[error("目标连接被服务端拒绝: {0}")]
    Rejected(String),
    #[error("UDP 发送失败: {0}")]
    UdpSend(#[from] UdpSendError),
}

/// TCP 代理流：TCPResponse 之后的 QUIC 流封装。
pub struct TcpProxyStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    leftover: Vec<u8>,
}

/// 打开到 `address`（`host:port`）的代理连接（对齐 client.go TCP 分支：
/// 写请求帧 → 读响应帧 → 成功后开始转发）。
pub async fn tcp_connect(
    client: &HysteriaClient,
    address: &str,
) -> Result<TcpProxyStream, ProxyError> {
    let (mut send, mut recv) = client.open_tcp().await?;

    // 首写：0x401 前缀 + 请求帧（padding 长度按 tcpRequestPadding [64,512)）
    let padding = h3_auth::random_padding(Range::TCP_REQUEST).into_bytes();
    let request = TcpRequest {
        address: address.to_string(),
        padding,
    }
    .encode()?;
    send.write_all(&request).await?;

    // 增量读 TCPResponse；帧后的字节留给应用读
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let response = loop {
        match TcpResponse::decode(&buf) {
            Ok((resp, consumed)) => {
                buf.drain(..consumed);
                break resp;
            }
            Err(crate::Error::Truncated { .. }) => {
                if buf.len() >= MAX_RESPONSE_BUFFER {
                    return Err(ProxyError::ResponseTooLarge);
                }
                match recv.read(&mut chunk).await? {
                    Some(n) => buf.extend_from_slice(&chunk[..n]),
                    None => return Err(ProxyError::PrematureEof),
                }
            }
            Err(e) => return Err(ProxyError::Frame(e)),
        }
    };
    if response.status != Status::Ok {
        return Err(ProxyError::Rejected(response.message));
    }
    Ok(TcpProxyStream {
        send,
        recv,
        leftover: buf,
    })
}

impl TcpProxyStream {
    /// 发送应用数据。首帧前缀逻辑已在 `tcp_connect` 完成，这里透写。
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), ProxyError> {
        self.send.write_all(buf).await?;
        Ok(())
    }

    /// 读应用数据：先消费 `leftover`（与响应帧同包到达的目标数据），
    /// 再读 QUIC 流。返回 0 表示流结束。
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyError> {
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Ok(n);
        }
        match self.recv.read(buf).await? {
            Some(n) => Ok(n),
            None => Ok(0),
        }
    }

    /// 半关闭（对齐 `interConn.Close`：发送侧 FIN）。
    pub fn finish(&mut self) -> Result<(), ProxyError> {
        self.send.finish()?;
        Ok(())
    }

    /// 停止接收（对齐 `interConn.Close` 的 `CancelRead(0)`）。
    pub fn stop_read(&mut self) {
        let _ = self.recv.stop(quinn::VarInt::from_u32(0));
    }
}

/// 组一条出站 datagram：SessionID 字段编码为 0，随后用真实会话 ID 覆盖
/// 前 4 字节（对齐 `Serialize` 跳过 SessionID + `InterUdpConn.Write` 覆写）。
pub fn udp_out_datagram(
    session_id: u32,
    address: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    let msg = UdpMessage {
        session_id: 0,
        packet_id: 0,
        fragment_id: 0,
        fragment_count: 1,
        address,
        data,
    };
    let mut bytes = msg.encode()?;
    bytes[..4].copy_from_slice(&session_id.to_be_bytes());
    Ok(bytes)
}

/// 组出站 datagram，超限时按参考 `UDPWriter.WriteMultiBuffer` 的分片路径：
/// 随机 packet id（`rand.Intn(0xFFFF)+1` ∈ [1, 65535]）+ `FragUDPMessage`
/// 切片。每片返回前同样写入真实会话 ID 前缀。
pub fn udp_out_datagrams(
    session_id: u32,
    address: &[u8],
    data: &[u8],
    max_size: usize,
) -> Result<Vec<Vec<u8>>, ProxyError> {
    let whole = udp_out_datagram(session_id, address, data)?;
    if whole.len() <= max_size {
        return Ok(vec![whole]);
    }
    let packet_id = (h3_auth::random_u64() % 0xFFFF + 1) as u16;
    let msg = UdpMessage {
        session_id: 0,
        packet_id,
        fragment_id: 0,
        fragment_count: 1,
        address,
        data,
    };
    let frags = frag_udp_message(&msg, max_size).map_err(|_| {
        ProxyError::Frame(crate::Error::TooLong {
            field: "udp fragment",
            len: data.len() as u64,
            max: max_size as u64,
        })
    })?;
    let mut out = Vec::with_capacity(frags.len());
    for frag in &frags {
        let mut bytes = frag.encode()?;
        bytes[..4].copy_from_slice(&session_id.to_be_bytes());
        out.push(bytes);
    }
    Ok(out)
}

/// 重组完成的一条 UDP 报文（地址与会话/报文 ID 取自最后到达的一片，
/// 对齐 frag.go 收齐时改写并返回入参的语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInbound {
    pub address: Vec<u8>,
    pub data: Vec<u8>,
}

/// `fragment.rs::Defragger` 的 owned 版：规则逐条对齐 frag.go `Feed`
/// （fragID/fragCount<=1 直通、非法 fragID 丢弃、换 packet/数量不符重开、
/// 重复片忽略、收齐按序拼接、**交付后清空状态**——对端随后复用同一
/// packet id 的新报文仍能正常重组）。存在原因是 channel 接收的
/// datagram 缓冲无法跨 `feed` 调用保持借用。
#[derive(Default)]
pub struct OwnedDefragger {
    slots: Vec<Option<Vec<u8>>>,
    received: usize,
    packet_id: u16,
    frag_count: u8,
    address: Vec<u8>,
    session_id: u32,
}

impl OwnedDefragger {
    /// 喂入一条已解析的报文分片；收齐时返回完整报文。
    pub fn feed(&mut self, m: &UdpMessage<'_>) -> Option<UdpInbound> {
        if m.fragment_count <= 1 {
            return Some(UdpInbound {
                address: m.address.to_vec(),
                data: m.data.to_vec(),
            });
        }
        if m.fragment_id >= m.fragment_count {
            return None;
        }
        let count = usize::from(m.fragment_count);
        if self.slots.len() != count || self.packet_id != m.packet_id {
            self.slots = vec![None; count];
            self.received = 0;
            self.packet_id = m.packet_id;
            self.frag_count = m.fragment_count;
        }
        let slot = &mut self.slots[usize::from(m.fragment_id)];
        if slot.is_some() {
            // 重复片：忽略（含交付完成后再到达的片，对齐规则 4/7）
            return None;
        }
        *slot = Some(m.data.to_vec());
        self.received += 1;
        self.session_id = m.session_id;
        self.address = m.address.to_vec();
        if self.received == count {
            // 只有真正补齐最后一片的这次 feed 触发交付；交付后清空状态
            //（对齐 frag.go 返回后置 current=nil），迟到的重复片只会落进
            // 新一轮未完成重组，不会二次交付。
            let data: Vec<u8> = self.slots.iter().flatten().flatten().copied().collect();
            debug_assert_eq!(self.frag_count, m.fragment_count);
            self.slots.clear();
            self.received = 0;
            return Some(UdpInbound {
                address: self.address.clone(),
                data,
            });
        }
        None
    }
}

/// UDP 入站循环（对齐 client.go `UDPReader.ReadMultiBuffer`：解析失败
/// continue、未收齐 continue、收齐交付）。
pub async fn udp_recv(
    session: &mut UdpSession,
    defrag: &mut OwnedDefragger,
) -> Option<Result<UdpInbound, crate::Error>> {
    loop {
        let raw = session.recv_raw().await?;
        let msg = match UdpMessage::decode(&raw) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if let Some(complete) = defrag.feed(&msg) {
            return Some(Ok(complete));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_datagram_overwrites_session_prefix() {
        let dgram = udp_out_datagram(7, b"127.0.0.1:53", b"ping").expect("encode");
        assert_eq!(&dgram[..4], &7u32.to_be_bytes());
        let msg = UdpMessage::decode(&dgram).expect("decode");
        assert_eq!(msg.session_id, 7);
        assert_eq!(msg.packet_id, 0);
        assert_eq!(msg.fragment_count, 1);
        assert_eq!(msg.address, b"127.0.0.1:53");
        assert_eq!(msg.data, b"ping");
    }

    #[test]
    fn out_datagrams_fragments_oversize() {
        let data = vec![0xABu8; 2000];
        let dgrams = udp_out_datagrams(3, b"10.0.0.1:53", &data, 1200).expect("frag");
        assert!(dgrams.len() > 1);
        let mut defrag = OwnedDefragger::default();
        let mut assembled: Vec<u8> = Vec::new();
        for d in &dgrams {
            let msg = UdpMessage::decode(d).expect("decode");
            assert_eq!(msg.session_id, 3);
            assert!(msg.packet_id >= 1);
            if let Some(done) = defrag.feed(&msg) {
                assembled = done.data;
            }
        }
        assert_eq!(assembled, data);
    }

    #[test]
    fn owned_defrag_mirrors_frag_rules() {
        let mut d = OwnedDefragger::default();
        let mk = |fid: u8, count: u8, pkt: u16, data: &'static [u8]| UdpMessage {
            session_id: 1,
            packet_id: pkt,
            fragment_id: fid,
            fragment_count: count,
            address: b"a:1",
            data,
        };
        // 直通
        assert_eq!(
            d.feed(&mk(0, 1, 0, b"x")).map(|m| m.data),
            Some(b"x".to_vec())
        );
        // 非法 fragID 丢弃
        assert!(d.feed(&mk(5, 2, 1, b"y")).is_none());
        // 乱序收齐：meta 取最后到达一片
        assert!(d.feed(&mk(1, 2, 7, b"cd")).is_none());
        let done = d.feed(&mk(0, 2, 7, b"ab")).expect("assembled");
        assert_eq!(done.data, b"abcd".to_vec());
        // 交付后状态已清空：迟到单片落入新一轮未完成重组，不交付
        assert!(d.feed(&mk(0, 2, 7, b"ab")).is_none());
        // 新 packet id 的报文正常重组交付
        assert!(d.feed(&mk(1, 2, 9, b"CD")).is_none());
        assert_eq!(
            d.feed(&mk(0, 2, 9, b"AB")).map(|m| m.data),
            Some(b"ABCD".to_vec())
        );
    }
}
