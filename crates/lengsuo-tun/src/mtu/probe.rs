//! MTU 探测的纯逻辑层：MSS clamp 与 PMTUD 状态下调。
//!
//! 不打开设备、不调用系统时钟、不发送报文、不需要 root；输入是内存中的接口 MTU
//! 与 ICMP/ICMPv6 报文，输出是 MSS 和新的路径 MTU。真实网卡上的 DF 试探与
//! PLPMTUD（RFC 8899）**不在本模块范围内**，见 `docs/tun-status.md` 的偏离清单。
//!
//! 依据：
//! - RFC 1191 §7 的典型 MTU 平台表 [`RFC1191_PLATEAUS`]：IPv4 路由未在 ICMP
//!   Next-Hop MTU 字段给出数值（字段为 0）时按该表递降，不自行猜测。
//! - RFC 8201（IPv6 PMTUD，取代 RFC 1981）：IPv6 最小路径 MTU 为 1280。
//! - Linux `net.ipv4.ip_no_pmtu_disc` / `tcp_mtu_probing` 的可观察语义：本模块
//!   对应「收到 ICMP 过大报文才下调、不主动试探」这一基线。
//!
//! 本层**不验证 ICMP 校验和、不核对 ICMP 报文的来源**：那是 `checksum` 与设备
//! 接入层的职责；这里只做结构解析与状态迁移。所有拒绝错误只描述字段值，不携带
//! 报文原始字节。

use std::net::IpAddr;

use super::{IpVersion, MAX_MTU_V4_FIELD, MIN_PATH_MTU_V4, MIN_PATH_MTU_V6};

/// IPv4 固定头部字节数（IHL=5，不含选项）。
pub const IPV4_HEADER_BYTES: u16 = 20;
/// IPv6 固定头部字节数。
pub const IPV6_HEADER_BYTES: u16 = 40;
/// TCP 固定头部字节数（数据偏移=5，不含选项）。
pub const TCP_HEADER_BYTES: u16 = 20;
/// 接口 MTU 下限：IPv4 取 RFC 1191 的 576；IPv6 由 `mss_for` 另行拒绝。
pub const MIN_MTU: u16 = MIN_PATH_MTU_V4;
/// 接口 MTU 上限：IPv4 总长度与 IPv6 载荷长度字段都能表达的最大值。
/// IPv6 jumbogram（RFC 2675）不使用该字段，本层不支持。
pub const MAX_MTU: u16 = u16::MAX;
/// IPv4 的最小 MSS：576 − 20（IP）− 20（TCP）。
pub const MIN_MSS_V4: u16 = MIN_PATH_MTU_V4 - IPV4_HEADER_BYTES - TCP_HEADER_BYTES;
/// IPv6 的最小 MSS：1280 − 40（IP）− 20（TCP）。
pub const MIN_MSS_V6: u16 = MIN_PATH_MTU_V6 - IPV6_HEADER_BYTES - TCP_HEADER_BYTES;
/// IPv4 的最大 MSS：65535 − 40。
pub const MAX_MSS_V4: u16 = MAX_MTU - IPV4_HEADER_BYTES - TCP_HEADER_BYTES;
/// IPv6 的最大 MSS：65535 − 60。
pub const MAX_MSS_V6: u16 = MAX_MTU - IPV6_HEADER_BYTES - TCP_HEADER_BYTES;
/// RFC 1191 §7 的典型 MTU 平台表，按从大到小排列。仅在 ICMP 未通告数值时使用。
pub const RFC1191_PLATEAUS: [u16; 11] = [
    65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
];

/// ICMP 固定头部长度：类型、代码、校验和、4 字节字段区。
const ICMP_HEADER: usize = 8;
/// ICMPv4 Destination Unreachable。
const ICMPV4_DEST_UNREACHABLE: u8 = 3;
/// ICMPv4 code 4：fragmentation needed and DF set（RFC 1191）。
const ICMPV4_FRAG_NEEDED: u8 = 4;
/// ICMPv6 Packet Too Big（RFC 4443）。
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
/// ICMPv6 Packet Too Big 的 code 恒为 0（RFC 4443 §3.2）。
const ICMPV6_CODE: u8 = 0;

/// MTU 探测层的错误。全部为拒绝语义，调用方不得据错误内容接受越界值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MtuError {
    /// 接口 MTU 不在许可区间内（构造 `MssClamp` 或按协议族取 MSS 时）。
    #[error("MTU {value} 越界：许可区间 {min}..={max}")]
    MtuOutOfRange { value: u16, min: u16, max: u16 },
    /// ICMP 通告的 MTU 越界：低于协议族下限、为 0，或超出本层可表示的上限。
    #[error("通告 MTU {value} 越界：{family:?} 许可区间 {min}..={max}")]
    AdvertisedOutOfRange {
        family: IpVersion,
        value: u32,
        min: u16,
        max: u32,
    },
    /// 通告值不小于当前值。本层不实现主动探测，因此不允许上调。
    #[error("通告 MTU {advertised} 不小于当前 {current}：本层只允许下调")]
    NotSmaller { current: u16, advertised: u16 },
    /// 当前已在下限，RFC 1191 平台表无法继续递降。
    #[error("{family:?} 路径 MTU 已在下限 {floor}，无法继续下调")]
    AtFloor { family: IpVersion, floor: u16 },
    /// ICMP 报文短于解析所需长度。
    #[error("ICMP 报文截断：需要 {needed} 字节，实际 {got}")]
    Truncated { needed: usize, got: usize },
    /// 报文类型/代码不是 PMTUD 过大通告。
    #[error("不是 PMTUD 报文：{family:?} type={kind} code={code}")]
    NotPmtud {
        family: IpVersion,
        kind: u8,
        code: u8,
    },
    /// 显式处理函数与状态维护的协议族不一致。
    #[error("PMTUD 协议族不匹配：状态为 {state:?}，报文为 {message:?}")]
    FamilyMismatch {
        state: IpVersion,
        message: IpVersion,
    },
}

/// MSS clamp：把接口 MTU 换算成本端可发送的 TCP 最大段长。
///
/// 构造时只校验协议族无关的下限 [`MIN_MTU`] 与上限 [`MAX_MTU`]；IPv6 的 1280
/// 下限在调用 [`MssClamp::mss_for_v6`] / [`MssClamp::mss_for`] 时再拒绝，因此
/// 576..=1279 的 clamp 对 IPv4 合法、对 IPv6 fail-closed。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MssClamp {
    mtu: u16,
}

impl MssClamp {
    /// 构造 clamp；越界返回 [`MtuError::MtuOutOfRange`]，不做夹紧。
    pub fn new(mtu: u16) -> Result<Self, MtuError> {
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err(MtuError::MtuOutOfRange {
                value: mtu,
                min: MIN_MTU,
                max: MAX_MTU,
            });
        }
        Ok(Self { mtu })
    }

    /// 构造时使用的接口 MTU。
    pub fn mtu(self) -> u16 {
        self.mtu
    }

    /// IPv4 MSS：接口 MTU 减去 20 字节 IP 头与 20 字节 TCP 头。
    pub fn mss_for_v4(self) -> Result<u16, MtuError> {
        self.mss_for(IpVersion::V4)
    }

    /// IPv6 MSS：接口 MTU 减去 40 字节 IP 头与 20 字节 TCP 头。
    /// MTU 低于 1280 时返回 [`MtuError::MtuOutOfRange`]。
    pub fn mss_for_v6(self) -> Result<u16, MtuError> {
        self.mss_for(IpVersion::V6)
    }

    /// 按协议族取 MSS。两族都保证结果落在各自的最小/最大 MSS 常量之间。
    pub fn mss_for(self, family: IpVersion) -> Result<u16, MtuError> {
        let (floor, overhead) = match family {
            IpVersion::V4 => (MIN_PATH_MTU_V4, IPV4_HEADER_BYTES + TCP_HEADER_BYTES),
            IpVersion::V6 => (MIN_PATH_MTU_V6, IPV6_HEADER_BYTES + TCP_HEADER_BYTES),
        };
        if self.mtu < floor {
            return Err(MtuError::MtuOutOfRange {
                value: self.mtu,
                min: floor,
                max: MAX_MTU,
            });
        }
        Ok(self.mtu - overhead)
    }
}

/// 单个目标的路径 MTU 探测状态：只下调，不主动试探、不上调。
///
/// `current` 初始为调用方给出的接口 MTU，之后仅由 ICMP 过大通告或 RFC 1191
/// 平台表降低。是否采用新的 MSS、是否重传由上层决定；本类型不持有报文与定时器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmtudState {
    family: IpVersion,
    target: IpAddr,
    current: u16,
}

impl PmtudState {
    /// 以目标地址的协议族建立状态；`initial_mtu` 必须满足该族下限，
    /// 否则返回 [`MtuError::MtuOutOfRange`]（不按接口 MTU 夹紧）。
    pub fn new(target: IpAddr, initial_mtu: u16) -> Result<Self, MtuError> {
        let family = match target {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        };
        let clamp = MssClamp::new(initial_mtu)?;
        clamp.mss_for(family)?;
        Ok(Self {
            family,
            target,
            current: initial_mtu,
        })
    }

    /// 该状态对应的协议族。
    pub fn family(self) -> IpVersion {
        self.family
    }

    /// 该状态对应的目标地址。
    pub fn target(self) -> IpAddr {
        self.target
    }

    /// 当前估计的可用路径 MTU。
    pub fn current_mtu(self) -> u16 {
        self.current
    }

    /// 按当前路径 MTU 换算的 MSS。
    pub fn mss(self) -> Result<u16, MtuError> {
        MssClamp::new(self.current)?.mss_for(self.family)
    }

    /// 处理 ICMPv4 type 3 code 4。`next_hop_mtu` 为 `None` 或字段值 0 时按
    /// RFC 1191 平台表递降；给出数值时按该值下调。
    ///
    /// 非 IPv4 状态返回 [`MtuError::FamilyMismatch`]；数值越界返回
    /// [`MtuError::AdvertisedOutOfRange`]；不小于当前值返回
    /// [`MtuError::NotSmaller`]；已在下限返回 [`MtuError::AtFloor`]。
    pub fn on_frag_needed(&mut self, next_hop_mtu: Option<u16>) -> Result<u16, MtuError> {
        if self.family != IpVersion::V4 {
            return Err(MtuError::FamilyMismatch {
                state: self.family,
                message: IpVersion::V4,
            });
        }
        match next_hop_mtu {
            None | Some(0) => self.descend_plateau(),
            Some(value) if value > MAX_MTU_V4_FIELD => Err(MtuError::AdvertisedOutOfRange {
                family: IpVersion::V4,
                value: u32::from(value),
                min: MIN_PATH_MTU_V4,
                max: u32::from(MAX_MTU_V4_FIELD),
            }),
            Some(value) => self.lower_to(IpVersion::V4, u32::from(value)),
        }
    }

    /// 处理 ICMPv6 type 2 Packet Too Big。`mtu` 为报文 32 位 MTU 字段。
    ///
    /// 非 IPv6 状态返回 [`MtuError::FamilyMismatch`]；低于 1280、为 0 或超过
    /// 65535 返回 [`MtuError::AdvertisedOutOfRange`]（不把 0 当成 1280 接受）。
    pub fn on_packet_too_big(&mut self, mtu: u32) -> Result<u16, MtuError> {
        if self.family != IpVersion::V6 {
            return Err(MtuError::FamilyMismatch {
                state: self.family,
                message: IpVersion::V6,
            });
        }
        self.lower_to(IpVersion::V6, mtu)
    }

    /// 解析一条以 ICMP 类型字节开头的报文并迁移状态，返回新的 MSS。
    ///
    /// 长度短于 8 字节一律 [`MtuError::Truncated`]；类型/代码不匹配返回
    /// [`MtuError::NotPmtud`]，且状态不变。校验和与来源由上层负责。
    pub fn apply_icmp(&mut self, message: &[u8]) -> Result<u16, MtuError> {
        if message.len() < ICMP_HEADER {
            return Err(MtuError::Truncated {
                needed: ICMP_HEADER,
                got: message.len(),
            });
        }
        let kind = message[0];
        let code = message[1];
        match self.family {
            IpVersion::V4 => {
                if kind != ICMPV4_DEST_UNREACHABLE || code != ICMPV4_FRAG_NEEDED {
                    return Err(MtuError::NotPmtud {
                        family: IpVersion::V4,
                        kind,
                        code,
                    });
                }
                // 偏移 4..6 为 RFC 792 保留字节，6..8 为 Next-Hop MTU（RFC 1191）。
                let next_hop = u16::from_be_bytes([message[6], message[7]]);
                self.on_frag_needed(if next_hop == 0 { None } else { Some(next_hop) })
            }
            IpVersion::V6 => {
                if kind != ICMPV6_PACKET_TOO_BIG || code != ICMPV6_CODE {
                    return Err(MtuError::NotPmtud {
                        family: IpVersion::V6,
                        kind,
                        code,
                    });
                }
                // 偏移 4..8 为 32 位 MTU（RFC 4443 §3.2）。
                let mtu = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
                self.on_packet_too_big(mtu)
            }
        }
    }

    /// 按通告值下调。调用方已保证 `family` 与本状态一致。
    fn lower_to(&mut self, family: IpVersion, advertised: u32) -> Result<u16, MtuError> {
        let floor = family.floor();
        let max = u32::from(MAX_MTU);
        if advertised < u32::from(floor) || advertised > max {
            return Err(MtuError::AdvertisedOutOfRange {
                family,
                value: advertised,
                min: floor,
                max,
            });
        }
        // 上面的区间检查保证可落入 u16。
        let advertised = advertised as u16;
        if advertised >= self.current {
            return Err(MtuError::NotSmaller {
                current: self.current,
                advertised,
            });
        }
        self.current = advertised;
        self.mss()
    }

    /// 无通告值时按 RFC 1191 平台表取「小于当前且不低于该族下限」的最大值；
    /// 表中没有合格值（例如 1006 之后只剩 508）时落到下限。
    fn descend_plateau(&mut self) -> Result<u16, MtuError> {
        let floor = self.family.floor();
        if self.current <= floor {
            return Err(MtuError::AtFloor {
                family: self.family,
                floor,
            });
        }
        let next = RFC1191_PLATEAUS
            .iter()
            .copied()
            .find(|&plateau| plateau < self.current && plateau >= floor)
            .unwrap_or(floor);
        self.current = next;
        self.mss()
    }
}
