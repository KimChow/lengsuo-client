//! 主动打开方向的**类型定义**：配置、状态、错误、待发段与状态机动作。
//!
//! 本文件只放数据形状与语义说明，不含任何行为实现；状态机本体在
//! [`super`](super::ActiveConnection)，MSS 选项原语在 [`super::option`]。
//!
//! 全部错误都是拒绝语义，不存在「降级继续」的路径：解析失败、状态不一致、
//! 路由缺失一律 fail-closed。

use std::net::IpAddr;

use crate::mtu::MtuError;
use crate::session::Clock;

use crate::tcp::segment::Flags;
use crate::tcp::state::DiscardReason;

/// 主动方的静态配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveConfig {
    /// 本端地址。
    pub local: IpAddr,
    /// 本端端口。
    pub local_port: u16,
    /// 远端地址。
    pub remote: IpAddr,
    /// 远端端口。
    pub remote_port: u16,
    /// 本端初始序号种子（**非密码学随机**，见模块头说明）。
    pub iss_seed: u32,
    /// 本端通告的接收窗口上限（字节）。
    pub receive_window: u16,
    /// 本端期望的最大段长；0 表示「按接口 MTU 取」。实际生效值还会被
    /// [`crate::mtu::MssClamp`] 按接口 MTU 夹紧。
    pub mss: u16,
    /// 出接口 MTU：MSS clamp 的输入，也是出站报文长度上限的来源。
    pub interface_mtu: u16,
    /// 出接口索引：供上层在多网卡场景下选路。
    pub interface_index: u32,
    /// IP 头部的 TTL / hop limit。
    pub ttl: u8,
    /// 初始重传超时（毫秒）。
    pub rto_ms: Clock,
    /// 重传退避上限（毫秒）：`rto` 每次翻倍但不超过该值。
    pub max_rto_ms: Clock,
    /// 允许的 SYN 重传次数上限；用尽后 fail-closed 报错并释放连接。
    pub max_retries: u32,
}

impl Default for ActiveConfig {
    fn default() -> Self {
        Self {
            local: IpAddr::from([0, 0, 0, 0]),
            local_port: 0,
            remote: IpAddr::from([0, 0, 0, 0]),
            remote_port: 0,
            iss_seed: 0,
            receive_window: 65_535,
            mss: 0,
            interface_mtu: 1500,
            interface_index: 0,
            ttl: 64,
            rto_ms: 1_000,
            max_rto_ms: 60_000,
            max_retries: 5,
        }
    }
}

/// 主动连接的状态。`SynSent` 与 `SynReceived` 是握手中间态。
///
/// 两条路径都会依次走过 `SynSent → SynReceived → Established`：
/// - **常规主动打开**（RFC 9293 §3.10.7.3）：`SynSent` 收到 SYN-ACK ⇒ 进
///   `SynReceived`（已握手到「只差最终 ACK」这一步）⇒ 发出最终 ACK ⇒ `Established`。
/// - **同时打开**（RFC 9293 §3.10.7.4）：`SynSent` 收到裸 SYN ⇒ 进 `SynReceived`
///   并回 SYN-ACK ⇒ 收到对端 ACK/SYN-ACK ⇒ `Established`。
///
/// 状态进入历史由 [`ActiveConnection::history`] 记录，便于用例断言确实走过中间态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveState {
    /// 已发出 SYN，等待 SYN-ACK（或对端的裸 SYN = 同时打开）。
    SynSent,
    /// 握手的最后一步：已收到对端 SYN/SYN-ACK，最终 ACK 待发或待确认。
    SynReceived,
    /// 握手完成，可双向传数据。
    Established,
    /// 连接已终结或失败，资源已释放。
    Closed,
}

/// 主动方向的全部失败原因。全部是拒绝语义，不存在「降级继续」的路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActiveError {
    /// 本端与远端地址族不一致：无法构造同一协议族的报文。
    #[error("本地与远端地址族不一致")]
    FamilyMismatch,
    /// MTU / MSS 越界（fail-closed，不按下限夹紧）。
    #[error("MTU 或 MSS 越界：{0}")]
    Mss(#[from] MtuError),
    /// 连接不在 `Established`：不能发送应用数据。
    #[error("连接尚未建立")]
    NotEstablished,
    /// 连接已终结或已发起过握手。
    #[error("连接已终结")]
    Closed,
    /// 主动打开超时：SYN 重传次数用尽仍未收到 SYN-ACK。
    #[error("主动打开超时：已重传 {retries} 次仍未收到 SYN-ACK")]
    ConnectTimeout { retries: u32 },
    /// 对端回 RST：连接被拒绝。
    #[error("对端拒绝连接（收到 RST）")]
    ConnectionRefused,
    /// SYN-ACK 的确认号不等于 ISN+1：fail-closed 回 RST 并失败。
    #[error("SYN-ACK 确认号非法：期望 {expected}，实得 {got}")]
    AckMismatch { expected: u32, got: u32 },
    /// 报文不是 TCP。
    #[error("入站报文不是 TCP")]
    NotTcp,
    /// 入站报文校验失败（校验和或头部结构非法）。
    #[error("入站报文校验失败：{0}")]
    Checksum(#[from] crate::checksum::Error),
    /// 目的地址没有匹配的出接口路由。
    #[error("目的地址 {0} 没有匹配的出接口")]
    NoRoute(IpAddr),
    /// 报文长度非法（无法构造 IP 头或 TCP 段）。
    #[error("报文长度非法：{0}")]
    Length(usize),
}

/// 要发出的 TCP 段。IP 头与最终校验和由接入层（[`super::connector`]）补齐。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSegment {
    /// 发送端序号。
    pub seq: u32,
    /// 确认号。
    pub ack: u32,
    /// 标志位。
    pub flags: Flags,
    /// 本端通告的接收窗口。
    pub window: u16,
    /// TCP 选项区（已按 4 字节对齐；MSS 选项由本模块构造）。
    pub options: Vec<u8>,
    /// 应用载荷。
    pub payload: Vec<u8>,
}

/// 主动方对单个入向段给出的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveOutcome {
    /// 需要发出一个段（ACK / SYN-ACK / 重传的 SYN / RST）。
    Send(OutboundSegment),
    /// 按序到达的应用载荷，交上层消费。
    Deliver(Vec<u8>),
    /// 连接失败并已释放；`reset` 非空时上层须先把这个 RST 发出去。
    Failed {
        reason: ActiveError,
        reset: Option<OutboundSegment>,
    },
    /// 段被丢弃，附原因，连接保持。
    Discarded(DiscardReason),
    /// 段被吸收，无动作（纯 ACK 记账等）。
    None,
}
