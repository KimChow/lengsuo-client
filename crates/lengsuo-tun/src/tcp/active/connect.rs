//! 单条主动 TCP 连接的状态机骨架：构造、序号记账与三条入口。
//!
//! 本文件持有 [`ActiveConnection`] 的字段与三条入口（`connect()` / `on_segment()`
//! / `on_timeout()`），入口风格与被动内核 [`crate::tcp::state::Connection::advance`]
//! 一致；各状态的入向处理分支在 [`super::handshake`]，只读访问器在
//! [`super::access`]。类型形状在 [`super::types`]，MSS 选项原语在 [`super::option`]。
//!
//! 全部拒绝路径都返回 [`ActiveOutcome::Failed`] 或 [`ActiveOutcome::Discarded`]，
//! 绝不 panic、绝不静默降级。

use crate::mtu::{IpVersion, MssClamp};
use crate::session::Clock;

use crate::tcp::segment::{Flags, Segment};
use crate::tcp::state::DiscardReason;

use super::option::mss_option;
use super::types::{ActiveConfig, ActiveError, ActiveOutcome, ActiveState, OutboundSegment};

/// 单条主动 TCP 连接的状态机。
///
/// 字段可见性为 `pub(super)`：同属 `active` 模块的子模块（`handshake` / `access`）
/// 需要读写内部记账，但这些字段对本 crate 之外不可见。
#[derive(Debug, Clone)]
pub struct ActiveConnection {
    pub(super) config: ActiveConfig,
    pub(super) state: ActiveState,
    /// 本端初始序号（发送 SYN 时占用一个序号）。
    pub(super) iss: u32,
    /// 最早未确认的发送序号。
    pub(super) snd_una: u32,
    /// 下一个发送序号。
    pub(super) snd_nxt: u32,
    /// 期望收到的下一个序号。
    pub(super) rcv_nxt: u32,
    /// 对端初始序号。
    pub(super) peer_isn: u32,
    /// 对端通告的窗口。
    pub(super) peer_window: u16,
    /// 对端通告的 MSS（收到后才已知）。
    pub(super) peer_mss: Option<u16>,
    /// 本端通告的 MSS（已按接口 MTU 夹紧）。
    pub(super) local_mss: u16,
    /// 实际可用于发送的最大段长：取本端与对端 MSS 的较小者。
    pub(super) effective_mss: u16,
    /// 已重传的 SYN 次数。
    pub(super) retries: u32,
    /// 当前重传超时（毫秒），每次重传翻倍。
    pub(super) rto: Clock,
    /// 重传截止时刻；`None` 表示当前不计时。
    pub(super) deadline: Option<Clock>,
    /// 已交付的载荷字节总数。
    pub(super) delivered: u64,
    /// 被丢弃的段数。
    pub(super) discarded: u64,
    /// 走过的状态序列（含初始态），供用例断言状态迁移路径。
    pub(super) history: Vec<ActiveState>,
    /// 是否已经发起过主动打开（防止重复 `connect()`）。
    pub(super) started: bool,
}

impl ActiveConnection {
    /// 建立处于 `SynSent` 的连接状态机。
    ///
    /// 地址族不一致直接拒绝；本端 MSS 会按 [`crate::mtu::MssClamp`] 依接口 MTU 夹紧
    /// （`config.mss` 为 0 时直接取夹紧后的上限）。
    pub fn new(config: ActiveConfig) -> Result<Self, ActiveError> {
        if config.local.is_ipv4() != config.remote.is_ipv4() {
            return Err(ActiveError::FamilyMismatch);
        }
        let family = if config.local.is_ipv4() {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        let limit = MssClamp::new(config.interface_mtu)?.mss_for(family)?;
        let local_mss = if config.mss == 0 {
            limit
        } else {
            config.mss.min(limit)
        };
        let iss = config.iss_seed;
        Ok(Self {
            snd_una: iss,
            snd_nxt: iss,
            rcv_nxt: 0,
            peer_isn: 0,
            peer_window: 0,
            peer_mss: None,
            effective_mss: local_mss,
            retries: 0,
            rto: config.rto_ms,
            deadline: None,
            delivered: 0,
            discarded: 0,
            state: ActiveState::SynSent,
            history: vec![ActiveState::SynSent],
            started: false,
            config,
            iss,
            local_mss,
        })
    }

    /// 迁移到新状态并记入状态历史。
    pub(super) fn transition(&mut self, next: ActiveState) {
        self.state = next;
        self.history.push(next);
    }

    /// 发起主动打开：发出 SYN 并武装重传定时器。
    ///
    /// 只能在 `SynSent` 状态调用一次；重复调用返回 [`ActiveError::Closed`]。
    pub fn connect(&mut self, now: Clock) -> Result<OutboundSegment, ActiveError> {
        if self.started || !matches!(self.state, ActiveState::SynSent) {
            return Err(ActiveError::Closed);
        }
        self.started = true;
        self.snd_una = self.iss;
        self.snd_nxt = self.iss.wrapping_add(1);
        self.rto = self.config.rto_ms;
        self.deadline = Some(now.saturating_add(self.rto));
        Ok(self.syn_segment())
    }

    /// 处理一个已解析、已校验的入向段。
    ///
    /// `now` 是调用方提供的单调时钟刻度（与被动内核同口径）：本状态机在
    /// `Established` 之后的处理不依赖时钟，故此处只做接口对齐，不用它记账。
    pub fn on_segment(&mut self, seg: &Segment<'_>, _now: Clock) -> ActiveOutcome {
        match self.state {
            ActiveState::SynSent => self.on_syn_sent(seg),
            ActiveState::SynReceived => self.on_syn_received(seg),
            ActiveState::Established => self.on_established(seg),
            ActiveState::Closed => {
                self.discarded += 1;
                ActiveOutcome::Discarded(DiscardReason::Closed)
            }
        }
    }

    /// 推进重传定时器：到点则重传 SYN；重传次数用尽则 fail-closed 报错并释放。
    pub fn on_timeout(&mut self, now: Clock) -> Result<Option<OutboundSegment>, ActiveError> {
        if !matches!(self.state, ActiveState::SynSent) {
            return Ok(None);
        }
        let Some(deadline) = self.deadline else {
            return Ok(None);
        };
        if now < deadline {
            return Ok(None);
        }
        if self.retries >= self.config.max_retries {
            self.transition(ActiveState::Closed);
            self.deadline = None;
            return Err(ActiveError::ConnectTimeout {
                retries: self.retries,
            });
        }
        self.retries += 1;
        self.rto = self
            .rto
            .saturating_mul(2)
            .min(self.config.max_rto_ms.max(self.config.rto_ms));
        self.deadline = Some(now.saturating_add(self.rto));
        Ok(Some(self.syn_segment()))
    }

    /// 发送应用载荷：按生效 MSS 切段，逐段产出 PSH|ACK。
    ///
    /// 只在 `Established` 状态可用；本层不做拥塞控制与发送缓冲管理。
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<OutboundSegment>, ActiveError> {
        if !matches!(self.state, ActiveState::Established) {
            return Err(ActiveError::NotEstablished);
        }
        let mss = usize::from(self.effective_mss.max(1));
        let mut out = Vec::new();
        let mut rest = payload;
        while !rest.is_empty() {
            let take = rest.len().min(mss);
            let chunk = &rest[..take];
            out.push(OutboundSegment {
                seq: self.snd_nxt,
                ack: self.rcv_nxt,
                flags: Flags::ACK | Flags::PSH,
                window: self.config.receive_window,
                options: Vec::new(),
                payload: chunk.to_vec(),
            });
            self.snd_nxt = self.snd_nxt.wrapping_add(chunk.len() as u32);
            rest = &rest[take..];
        }
        Ok(out)
    }

    /// 关闭本端写端：发 FIN。不实现 TIME-WAIT（见「偏离清单」）。
    pub fn close(&mut self) -> Option<OutboundSegment> {
        if !matches!(self.state, ActiveState::Established) {
            return None;
        }
        let seq = self.snd_nxt;
        self.snd_nxt = seq.wrapping_add(1);
        Some(OutboundSegment {
            seq,
            ack: self.rcv_nxt,
            flags: Flags::FIN | Flags::ACK,
            window: self.config.receive_window,
            options: Vec::new(),
            payload: Vec::new(),
        })
    }

    /// SYN 段：seq 为 ISN，带 MSS 选项。
    pub(super) fn syn_segment(&self) -> OutboundSegment {
        OutboundSegment {
            seq: self.iss,
            ack: 0,
            flags: Flags::SYN,
            window: self.config.receive_window,
            options: mss_option(self.local_mss),
            payload: Vec::new(),
        }
    }

    /// SYN+ACK 段：seq 仍是本端 ISN，ack 为对端序号 + 1。
    pub(super) fn syn_ack_segment(&self) -> OutboundSegment {
        OutboundSegment {
            seq: self.iss,
            ack: self.rcv_nxt,
            flags: Flags::SYN | Flags::ACK,
            window: self.config.receive_window,
            options: mss_option(self.local_mss),
            payload: Vec::new(),
        }
    }

    /// 纯 ACK 段。
    pub(super) fn ack_segment(&self) -> OutboundSegment {
        OutboundSegment {
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: Flags::ACK,
            window: self.config.receive_window,
            options: Vec::new(),
            payload: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ActiveConfig {
        ActiveConfig {
            local: "10.0.0.1".parse().unwrap(),
            local_port: 40000,
            remote: "10.0.0.2".parse().unwrap(),
            remote_port: 80,
            iss_seed: 0x1000_0000,
            receive_window: 4096,
            mss: 0,
            interface_mtu: 1500,
            interface_index: 3,
            ttl: 64,
            rto_ms: 1000,
            max_rto_ms: 8000,
            max_retries: 3,
        }
    }

    #[test]
    fn mss_is_clamped_by_interface_mtu() {
        // 接口 MTU 576 ⇒ MSS 536；配置里写更大的 MSS 也必须被夹紧。
        let mut cfg = config();
        cfg.interface_mtu = 576;
        cfg.mss = 1460;
        let conn = ActiveConnection::new(cfg).unwrap();
        assert_eq!(conn.local_mss(), 536);
        // MTU 1500 ⇒ MSS 1460。
        let conn = ActiveConnection::new(config()).unwrap();
        assert_eq!(conn.local_mss(), 1460);
        // 低于协议族下限时 fail-closed。
        let mut cfg = config();
        cfg.interface_mtu = 100;
        assert!(matches!(
            ActiveConnection::new(cfg),
            Err(ActiveError::Mss(_))
        ));
    }

    #[test]
    fn state_machine_rejects_mismatched_family() {
        let mut cfg = config();
        cfg.remote = "::1".parse().unwrap();
        assert!(matches!(
            ActiveConnection::new(cfg),
            Err(ActiveError::FamilyMismatch)
        ));
    }
}
