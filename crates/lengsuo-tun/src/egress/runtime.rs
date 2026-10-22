//! 出口运行时：协议出口的身份、可用性与会话生命周期。

use std::net::SocketAddr;

use super::authority::DeviceId;

/// 出口协议：与 `lengsuo-node` 的八协议出口一一对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutboundProtocol {
    Trojan,
    AnyTls,
    Vless,
    Vmess,
    Shadowsocks,
    Ss2022,
    Hysteria,
    Wireguard,
}

impl OutboundProtocol {
    /// 稳定的短标签，供日志与指标输出（不含任何凭据）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Shadowsocks => "shadowsocks",
            Self::Ss2022 => "ss2022",
            Self::Hysteria => "hysteria",
            Self::Wireguard => "wireguard",
        }
    }
}

/// 出口运行时的拒绝原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    #[error("该设备未配置出口协议")]
    NoProtocol,
    #[error("协议出口当前不可用")]
    Unavailable,
    #[error("出口建连失败")]
    Dial,
    #[error("出口转发失败")]
    Forward,
    #[error("出口会话句柄无效")]
    UnknownSession,
}

/// 出口运行时：决定某台设备承担哪个协议出口、该出口是否可用，并建立/释放会话。
///
/// 真实实现对应 `lengsuo-node` 的八协议拨号；本 trait 不含任何凭据字段。
pub trait OutboundRuntime {
    /// 该设备配置的出口协议；未配置 ⇒ `None`（拒绝，不回落直连）。
    fn protocol_of(&self, device: DeviceId) -> Option<OutboundProtocol>;

    /// 该协议出口此刻是否可用（配置齐备、凭据有效、节点可达等）。
    fn is_available(&self, device: DeviceId, protocol: OutboundProtocol) -> bool;

    /// 建立一条到 `target` 的出口会话。
    fn open(
        &mut self,
        device: DeviceId,
        protocol: OutboundProtocol,
        target: SocketAddr,
    ) -> Result<OutboundSession, RuntimeError>;

    /// 把应用报文交给已建立的出口会话。
    fn forward(&mut self, session: OutboundSession, packet: &[u8]) -> Result<(), RuntimeError>;

    /// 释放一条出口会话（会话结束或建连失败回滚时调用）。
    fn release(&mut self, session: OutboundSession);
}

/// 运行时分配的出口会话句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundSession(pub u64);

/// 出口运行时的**回程**取回能力。
///
/// [`OutboundRuntime`] 只覆盖去程（建连、转发载荷）；回程字节（对端发来的应用
/// 数据）由本 trait 单独承载。真实实现接 node 的读端；测试用内存替身。
///
/// 与 [`OutboundRuntime`] 分成两个 trait 的原因：去程是**必须**的（没有它就无法把
/// 报文送出），回程是**可选**的（只有出站方向的最小实现可以不实现回程）。
pub trait OutboundExchange {
    /// 取回某个会话已就绪的回程字节；没有就绪数据时返回 `None`。
    fn take_response(&mut self, session: OutboundSession) -> Option<Vec<u8>>;
}
