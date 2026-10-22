//! UDP-over-TCP 魔法域的识别与代次一致性判定。
//!
//! 参考 anytls-go fd6167a：
//! - `uot.MagicAddress` = `sp.v2.udp-over-tcp.arpa`（v2）、
//!   `uot.LegacyMagicAddress` = `sp.udp-over-tcp.arpa`（v1）；
//! - `cmd/client/inbound.go:61` 用 `uot.RequestDestination(2)` ⇒ 官方客户端恒用 v2 魔法域；
//! - `cmd/server/inbound_tcp.go:76` 只做 `strings.Contains(destination, "udp-over-tcp.arpa")`。
//!
//! 本模块比参考**更严**：参考的 `Contains` 会把 `evil.udp-over-tcp.arpa` 之类也认成
//! UoT 流，且不校验魔法域代次与协商版本是否一致。本卡要求「魔数与版本不符 ⇒ 拒绝」，
//! 故只认两个**精确**魔法域，其余一律拒绝（fail-closed），绝不回落成 TCP 拨号。
use crate::stream::{
    is_udp_over_tcp_request, version_from_magic, UdpVersion, MAGIC_ADDRESS_V1, MAGIC_ADDRESS_V2,
};

/// 流首地址的判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    /// 不是 UoT 流（普通 TCP 目标）——走普通 TCP 拨号路径。
    NotUot,
    /// 像是 UoT 流，但魔法域无法识别（既不是 v1 也不是 v2 的精确域名）⇒ 必须拒绝。
    Invalid,
    /// 是 UoT 流，魔法域有效，携带其代次。
    Uot(UdpVersion),
}

/// 判定流首地址归属。
///
/// 规则：
/// 1. 不含 `udp-over-tcp.arpa` ⇒ [`Magic::NotUot`]（走普通 TCP 路径）；
/// 2. 含该后缀但不是两个精确魔法域之一 ⇒ [`Magic::Invalid`]（调用方必须拒绝）；
/// 3. 精确匹配 ⇒ [`Magic::Uot`] 并给出代次。
pub fn classify(host: &str) -> Magic {
    if !is_udp_over_tcp_request(host) {
        return Magic::NotUot;
    }
    if host != MAGIC_ADDRESS_V2 && host != MAGIC_ADDRESS_V1 {
        return Magic::Invalid;
    }
    // 代次由魔法域决定（复用既有原语 `version_from_magic`）。
    Magic::Uot(version_from_magic(host))
}

/// 魔法域代次与协商出的 AnyTLS 版本是否一致。
///
/// 参考侧两者是硬编码耦合的（客户端恒用 `RequestDestination(2)`、服务端恒发 `v=2`），
/// 本仓把它显式化：协商版本 ≥ 2 必须用 v2 魔法域，版本 1 必须用 v1 魔法域。
pub fn version_matches(peer_version: u8, magic: UdpVersion) -> bool {
    (peer_version >= 2) == (magic == UdpVersion::V2)
}
