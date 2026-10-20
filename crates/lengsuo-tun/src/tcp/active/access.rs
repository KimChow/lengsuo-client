//! 主动连接的只读访问器：状态、序号、窗口与计数。
//!
//! 单独成文件是为了让状态机实现文件保持在行数目标内；这些访问器都是纯读取，
//! 不改变连接状态。

use std::net::IpAddr;

use super::connect::ActiveConnection;
use super::types::ActiveState;

impl ActiveConnection {
    /// 当前状态。
    pub fn state(&self) -> ActiveState {
        self.state
    }

    /// 走过的状态序列（含初始态 `SynSent`）。
    pub fn history(&self) -> &[ActiveState] {
        &self.history
    }

    /// 是否已握手完成。
    pub fn is_established(&self) -> bool {
        matches!(self.state, ActiveState::Established)
    }

    /// 本端地址。
    pub fn local(&self) -> IpAddr {
        self.config.local
    }

    /// 本端端口。
    pub fn local_port(&self) -> u16 {
        self.config.local_port
    }

    /// 远端地址。
    pub fn remote(&self) -> IpAddr {
        self.config.remote
    }

    /// 远端端口。
    pub fn remote_port(&self) -> u16 {
        self.config.remote_port
    }

    /// 出接口索引。
    pub fn interface_index(&self) -> u32 {
        self.config.interface_index
    }

    /// 出接口 MTU：MSS clamp 的输入，也是出站报文长度上限。
    pub fn interface_mtu(&self) -> u16 {
        self.config.interface_mtu
    }

    /// IP 头部的 TTL / hop limit。
    pub fn ttl(&self) -> u8 {
        self.config.ttl
    }

    /// 本端通告的 MSS（已按接口 MTU 夹紧）。
    pub fn local_mss(&self) -> u16 {
        self.local_mss
    }

    /// 实际可用于发送的最大段长（取本端与对端 MSS 的较小值）。
    pub fn effective_mss(&self) -> u16 {
        self.effective_mss
    }

    /// 对端通告的 MSS；未收到对端 MSS 选项时为 `None`。
    pub fn peer_mss(&self) -> Option<u16> {
        self.peer_mss
    }

    /// 已重传的 SYN 次数。
    pub fn retries(&self) -> u32 {
        self.retries
    }

    /// 下一个发送序号。
    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt
    }

    /// 最早未确认的发送序号。
    pub fn snd_una(&self) -> u32 {
        self.snd_una
    }

    /// 对端初始序号（收到对端 SYN 后已知）。
    pub fn peer_isn(&self) -> u32 {
        self.peer_isn
    }

    /// 期望收到的下一个序号。
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt
    }

    /// 已交付的载荷字节总数。
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered
    }

    /// 被丢弃的段数。
    pub fn discarded_segments(&self) -> u64 {
        self.discarded
    }

    /// 记录对端通告的 MSS，并据此收紧本端的发送段长。
    pub fn set_peer_mss(&mut self, peer_mss: u16) {
        if peer_mss == 0 {
            return;
        }
        self.peer_mss = Some(peer_mss);
        self.effective_mss = self.local_mss.min(peer_mss);
    }
}
