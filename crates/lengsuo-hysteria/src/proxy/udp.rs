//! UDP 承载：出向组包（含分片）与入向重组（owned 版 Defragger）。
//!
//! 每条 QUIC datagram = 一条 UDPMessage，前 4 字节为会话 ID
//! （`udp.rs` 编码时 SessionID 写 0，发送层覆盖为真实值，与参考
//! `Serialize` 注释掉 SessionID + `InterUdpConn.Write` 覆写的组合一致）。
//! 超限报文按参考 `UDPWriter` 路径分片（随机 packet id + `frag_udp_message`）；
//! 入站经 `OwnedDefragger` 重组（`fragment.rs` 的 Defragger 借用入参字节，
//! 无法跨多次 channel 接收存活，这里按 frag.go 同一规则实现 owned 版）。

use crate::fragment::frag_udp_message;
use crate::h3_auth;
use crate::quic::UdpSession;
use crate::udp::UdpMessage;

use super::error::ProxyError;

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
