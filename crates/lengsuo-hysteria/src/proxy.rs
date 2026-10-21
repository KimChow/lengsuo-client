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
//!
//! ## 子模块
//!
//! | 子模块 | 职责 |
//! |---|---|
//! | [`error`] | [`ProxyError`]（错误文本不含密码与目标地址内容） |
//! | [`tcp_client`] | 客户端侧 TCP 代理（[`TcpProxyStream`] / [`tcp_connect`]） |
//! | [`udp`] | UDP 出向组包（含分片）与入向重组（[`OwnedDefragger`]） |
//! | [`server`] | 服务端侧承载（TCP 中继 + UDP 会话中继） |

mod error;
mod server;
mod tcp_client;
mod udp;

pub use error::ProxyError;
pub use server::{serve_tcp_stream, serve_tcp_stream_paced, serve_udp_session};
pub use tcp_client::{tcp_connect, TcpProxyStream};
pub use udp::{udp_out_datagram, udp_out_datagrams, udp_recv, OwnedDefragger, UdpInbound};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::UdpMessage;

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
