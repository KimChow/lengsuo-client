//! PLPMTUD（RFC 8899）的纯逻辑层：主动探测状态机与 DF 探测报文构造。
//!
//! 不建 socket、不打开设备、不需要 root、不读真实接口 MTU；探测报文以字节数组返回，
//! 是否写出以及真实链路结果由设备接入层负责。本模块**不**声称完成真实链路探测。
//!
//! 依据：
//! - RFC 8899 §5.1：`BASE_PLPMTU` 为 1200 字节，两族同值（IPv6 的 1280 最小链路
//!   MTU 是另一回事，主动探测从更保守的 1200 起步）。
//! - RFC 8899 §5.1.1：`MAX_PROBES = 3`（同一尺寸连续失败上限）、
//!   `PMTU_RAISE_TIMER = 600s`（搜索结束后重启探测的间隔）。
//! - RFC 8899 §5.2：在已确认值与搜索上限之间二分取候选尺寸。
//! - RFC 1191 / RFC 8201：IPv4 探测必须置 DF；IPv6 路由器本就不可分片，没有 DF 位。
//!
//! 探测报文是**骨架**：IP 头部字段自洽（总长、DF、首部校验和），载荷是按 seed 确定性
//! 填充的字节，不含合法传输层段。参数越界一律返回 `Err`，不夹紧、不静默降级。
//!
//! 错误变体沿用 [`MtuError`]（本模块不新增变体）：尺寸小于头部按 `Truncated`，
//! 超过 [`MAX_MTU`] 按 `AdvertisedOutOfRange`（该变体是唯一能携带 `u32`/超长值的种类），
//! 状态机里的尺寸不符按 `MtuOutOfRange { value, min: expected, max: expected }`。

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::probe::{MtuError, IPV4_HEADER_BYTES, IPV6_HEADER_BYTES, MAX_MTU};
use super::IpVersion;

/// RFC 8899 §5.1 的保守下界，两族同值。
pub const BASE_PLPMTU: u16 = 1200;
/// RFC 8899 §5.1.1：同一尺寸连续失败达到该次数即判其不可用。
pub const MAX_PROBES: u8 = 3;
/// RFC 8899 §5.1.1：搜索完成后等待多久再重启探测。
pub const PMTU_RAISE_TIMER: Duration = Duration::from_secs(600);

/// IPv4/IPv6 探测骨架统一的 TTL / Hop Limit。
const PROBE_HOP_LIMIT: u8 = 64;
/// 探测骨架的 IP 协议号/下一头（UDP）。载荷只是填充，不是合法 UDP 段。
const PROBE_PROTOCOL: u8 = 17;
/// IPv4 头部内标识字段偏移。
const IPV4_IDENTIFICATION: usize = 4;
/// IPv4 头部内标志与片偏移字段偏移。
const IPV4_FLAGS_OFFSET: usize = 6;
/// IPv4 DF 置位、片偏移为零的 16 位字段值（RFC 1191 §3）。
const IPV4_DF: u16 = 0x4000;
/// IPv4 首部校验和字段偏移。
const IPV4_CHECKSUM: usize = 10;

/// 单个目标的 PLPMTUD 状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlpmtudState {
    /// 路径不支持主动探测：一个探测包都不产生，路径 MTU 固定为 base。
    Disabled,
    /// 尚未探测，只有一个已确认值 = [`BASE_PLPMTU`]。
    Base,
    /// 有探测在飞。
    Searching,
    /// 已找到（或探测失败后停在上一个确认值），等 raise timer。
    SearchComplete,
}

/// 按目标地址维护的 PLPMTUD 搜索状态。
///
/// 不变量：`confirmed` 单调不减（除 `disable` 回 base）；探测尺寸恒在
/// `(confirmed, ceiling]`；任一尺寸必须累计 [`MAX_PROBES`] 次失败才被判不可用；
/// 任何 `Err` 分支都不改变状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlpmtudSearch {
    target: IpAddr,
    ceiling: u16,
    confirmed: u16,
    state: PlpmtudState,
    in_flight: Option<u16>,
    last_size: Option<u16>,
    losses: u8,
    next_raise_at: Option<Instant>,
}

impl PlpmtudSearch {
    /// 以目标地址与搜索上限建立状态。`base_ceiling < BASE_PLPMTU` 或
    /// `> MAX_MTU` 返回 [`MtuError::MtuOutOfRange`]，不夹紧。
    pub fn new(addr: IpAddr, base_ceiling: u16) -> Result<Self, MtuError> {
        if !(BASE_PLPMTU..=MAX_MTU).contains(&base_ceiling) {
            return Err(MtuError::MtuOutOfRange {
                value: base_ceiling,
                min: BASE_PLPMTU,
                max: MAX_MTU,
            });
        }
        Ok(Self {
            target: addr,
            ceiling: base_ceiling,
            confirmed: BASE_PLPMTU,
            state: PlpmtudState::Base,
            in_flight: None,
            last_size: None,
            losses: 0,
            next_raise_at: None,
        })
    }

    /// 该搜索对应的目标地址。
    pub fn target(&self) -> IpAddr {
        self.target
    }

    /// 当前状态。
    pub fn state(&self) -> PlpmtudState {
        self.state
    }

    /// 当前已确认可通的最大尺寸，初值 [`BASE_PLPMTU`]。
    pub fn confirmed_pmtu(&self) -> u16 {
        self.confirmed
    }

    /// 取下一个探测尺寸；无需探测时返回 `None`。
    ///
    /// `Disabled` 恒返回 `None`；`Base` / `Searching` 返回 `(confirmed, ceiling]` 的
    /// 二分中点（已有探测在飞时返回 `None`）；`SearchComplete` 仅在 raise timer 到点后
    /// 重新进入 `Searching` 并返回候选。
    pub fn next_probe(&mut self, now: Instant) -> Option<u16> {
        match self.state {
            PlpmtudState::Disabled => return None,
            PlpmtudState::SearchComplete => {
                if !self.next_raise_at.is_some_and(|at| now >= at) {
                    return None;
                }
                self.restart_search();
            }
            PlpmtudState::Base | PlpmtudState::Searching => {}
        }
        if self.in_flight.is_some() {
            return None;
        }
        if self.confirmed >= self.ceiling {
            self.complete(now);
            return None;
        }
        let candidate = self.midpoint();
        if self.last_size != Some(candidate) {
            self.losses = 0;
        }
        self.last_size = Some(candidate);
        self.in_flight = Some(candidate);
        self.state = PlpmtudState::Searching;
        Some(candidate)
    }

    /// 确认在飞探测 `size`：该尺寸成为 confirmed；已到 ceiling 则 `SearchComplete`，
    /// 否则继续 `Searching`。`size` 与在飞探测不符返回 `Err` 且状态不变。
    pub fn on_ack(&mut self, size: u16, now: Instant) -> Result<(), MtuError> {
        if self.in_flight != Some(size) {
            return Err(self.size_mismatch(size));
        }
        self.confirmed = size;
        self.in_flight = None;
        self.last_size = None;
        self.losses = 0;
        if self.confirmed >= self.ceiling {
            self.complete(now);
        } else {
            self.state = PlpmtudState::Searching;
        }
        Ok(())
    }

    /// 记录在飞探测 `size` 丢失。同尺寸累计失败达 [`MAX_PROBES`] 才放弃并回退到
    /// 上一个 confirmed（`SearchComplete` + raise timer）；未达上限保持 `Searching`
    /// 并允许同尺寸重试。`size` 与在飞探测不符返回 `Err` 且状态不变。
    pub fn on_loss(&mut self, size: u16, now: Instant) -> Result<(), MtuError> {
        if self.in_flight != Some(size) {
            return Err(self.size_mismatch(size));
        }
        self.in_flight = None;
        if self.last_size == Some(size) {
            self.losses = self.losses.saturating_add(1);
        } else {
            self.last_size = Some(size);
            self.losses = 1;
        }
        if self.losses >= MAX_PROBES {
            // 放弃该尺寸，confirmed 保持为上一个已确认值。
            self.complete(now);
        } else {
            self.state = PlpmtudState::Searching;
        }
        Ok(())
    }

    /// raise timer 到点后重启搜索（`SearchComplete` 之外或未到点时为 no-op）。
    pub fn on_raise_timer(&mut self, now: Instant) {
        if self.state != PlpmtudState::SearchComplete {
            return;
        }
        if self.next_raise_at.is_some_and(|at| now >= at) {
            self.restart_search();
        }
    }

    /// 转 `Disabled`：清在飞状态，confirmed 回到 base。
    pub fn disable(&mut self) {
        self.state = PlpmtudState::Disabled;
        self.confirmed = BASE_PLPMTU;
        self.in_flight = None;
        self.last_size = None;
        self.losses = 0;
        self.next_raise_at = None;
    }

    /// `(confirmed, ceiling]` 的二分中点（上取整，只接受严格大于 confirmed 的值）。
    fn midpoint(&self) -> u16 {
        let span = u32::from(self.ceiling - self.confirmed);
        self.confirmed + span.div_ceil(2) as u16
    }

    /// 进入 `SearchComplete`，并在 `now` 起算 raise timer。
    fn complete(&mut self, now: Instant) {
        self.state = PlpmtudState::SearchComplete;
        self.next_raise_at = Some(now + PMTU_RAISE_TIMER);
        self.in_flight = None;
        self.last_size = None;
        self.losses = 0;
    }

    /// 重新进入 `Searching`，下一个候选仍由 [`PlpmtudSearch::next_probe`] 给出。
    fn restart_search(&mut self) {
        self.state = PlpmtudState::Searching;
        self.next_raise_at = None;
        self.in_flight = None;
        self.last_size = None;
        self.losses = 0;
    }

    /// 尺寸不符的错误：该变体的 `min..=max` 描述唯一可接受的尺寸。
    fn size_mismatch(&self, size: u16) -> MtuError {
        let expected = self.in_flight.unwrap_or(self.confirmed);
        MtuError::MtuOutOfRange {
            value: size,
            min: expected,
            max: expected,
        }
    }
}

/// 构造 IPv4 DF 探测报文骨架：总长 `size`，DF 置位，首部校验和按 RFC 1071 计算。
///
/// `size < 20`（IPv4 头）返回 [`MtuError::Truncated`]；`size > MAX_MTU` 返回
/// [`MtuError::AdvertisedOutOfRange`]。载荷按 `payload_seed` 确定性填充。
pub fn probe_packet_v4(size: usize, payload_seed: u8) -> Result<Vec<u8>, MtuError> {
    let header = usize::from(IPV4_HEADER_BYTES);
    if size < header {
        return Err(MtuError::Truncated {
            needed: header,
            got: size,
        });
    }
    if size > usize::from(MAX_MTU) {
        return Err(oversize_error(IpVersion::V4, size, IPV4_HEADER_BYTES));
    }
    let total =
        u16::try_from(size).map_err(|_| oversize_error(IpVersion::V4, size, IPV4_HEADER_BYTES))?;
    let mut packet = vec![0u8; size];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[IPV4_IDENTIFICATION..IPV4_IDENTIFICATION + 2].copy_from_slice(&0u16.to_be_bytes());
    packet[IPV4_FLAGS_OFFSET..IPV4_FLAGS_OFFSET + 2].copy_from_slice(&IPV4_DF.to_be_bytes());
    packet[8] = PROBE_HOP_LIMIT;
    packet[9] = PROBE_PROTOCOL;
    fill_payload(&mut packet[header..], payload_seed);
    let checksum = crate::checksum::checksum_of(&[&packet[..header]]);
    packet[IPV4_CHECKSUM..IPV4_CHECKSUM + 2].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

/// 构造 IPv6 探测报文骨架：总长 `size`，载荷长度 = `size - 40`。
///
/// IPv6 没有 DF 位（RFC 8201），因此不写 flags/片偏移字段。`size < 40` 返回
/// [`MtuError::Truncated`]；`size > MAX_MTU` 返回 [`MtuError::AdvertisedOutOfRange`]。
pub fn probe_packet_v6(size: usize, payload_seed: u8) -> Result<Vec<u8>, MtuError> {
    let header = usize::from(IPV6_HEADER_BYTES);
    if size < header {
        return Err(MtuError::Truncated {
            needed: header,
            got: size,
        });
    }
    if size > usize::from(MAX_MTU) {
        return Err(oversize_error(IpVersion::V6, size, IPV6_HEADER_BYTES));
    }
    let payload_len = u16::try_from(size - header)
        .map_err(|_| oversize_error(IpVersion::V6, size, IPV6_HEADER_BYTES))?;
    let mut packet = vec![0u8; size];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[6] = PROBE_PROTOCOL;
    packet[7] = PROBE_HOP_LIMIT;
    fill_payload(&mut packet[header..], payload_seed);
    Ok(packet)
}

/// 超长探测请求的错误：`AdvertisedOutOfRange` 是唯一能携带超 `u16` 值的变体。
fn oversize_error(family: IpVersion, value: usize, min: u16) -> MtuError {
    MtuError::AdvertisedOutOfRange {
        family,
        value: u32::try_from(value).unwrap_or(u32::MAX),
        min,
        max: u32::from(MAX_MTU),
    }
}

/// 用 seed 按位置确定性填充载荷：同参数逐字节可复现，不依赖随机数或时钟。
fn fill_payload(payload: &mut [u8], seed: u8) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
}
