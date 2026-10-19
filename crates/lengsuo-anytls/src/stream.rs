//! AnyTLS v2 流层：UDP 关联的帧化封装（UDP-over-TCP v2）。
//! 基线 anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50
//! `cmd/server/inbound_tcp.go`（识别 `.arpa` 目的地址）、
//! `cmd/server/outbound_tcp.go`（`proxyOutboundUoT`）以及其依赖的
//! `github.com/sagernet/sing` v0.5.1 `common/uot` 与 `common/metadata`。
//!
//! ## UDP-over-TCP v2 的完整语义（逐字段对齐参考）
//!
//! 1. 客户端开一条**普通流**（cmdSYN），流首字节是 SOCKS 风格目的地址；
//!    请求 UDP 时目的地址主机名是魔法域 `sp.v2.udp-over-tcp.arpa`
//!    （v1 旧版是 `sp.udp-over-tcp.arpa`）。服务端对目的地址做
//!    `strings.Contains(destination, "udp-over-tcp.arpa")` 判定后转入 UoT 分支。
//! 2. `uot.ReadRequest`：`isConnect(1B, 0/1) | 地址 | 端口(2B BE)`。
//!    `isConnect=1` 表示后续**所有**报文的地址都固定为请求里的目的地址，
//!    报文中不再重复携带地址。
//! 3. 之后每个 UDP 报文是一段独立的 `地址? | 长度(2B BE) | 载荷`：
//!    - `isConnect=0` 时携带地址，`isConnect=1` 时省略；
//!    - 长度是**载荷**长度，不含地址与长度字段本身（注意：**没有** 2 字节
//!      `isize` 前缀，也没有帧内嵌套）。
//!
//! ## 两套地址编码必须区分（真实互通中最易错的一处）
//!
//! 参考在同一协议里用了**两种**地址编码，用错即整体错位：
//! * **请求头**走 `uot.EncodeRequest`/`ReadRequest` → `M.SocksaddrSerializer`，
//!   家族字节是 SOCKS5 的 `0x01`=IPv4、`0x04`=IPv6、`0x03`=域名（见 [`crate::socks`]）；
//! * **报文内地址**走 `uot.AddrParser` → `0x00`=IPv4、`0x01`=IPv6、`0x02`=域名。
//!
//! 已对 Go 侧 `uot.EncodeRequest` / `uot.AddrParser.WriteAddrPort` 的十六进制
//! 输出逐字节核对。这些报文不新占用命令字节：它们在既有 Push 流里当字节流传输。

pub use crate::socks;
pub use crate::udp_assoc::UdpAssociations;

/// 参考 `uot.MagicAddress`（版本 2）。
pub const MAGIC_ADDRESS_V2: &str = "sp.v2.udp-over-tcp.arpa";
/// 参考 `uot.LegacyMagicAddress`（版本 1）。
pub const MAGIC_ADDRESS_V1: &str = "sp.udp-over-tcp.arpa";
/// 服务端判定的子串（参考 `inbound_tcp.go` 的 `strings.Contains`）。
pub const MAGIC_SUFFIX: &str = "udp-over-tcp.arpa";

/// UDP-over-TCP 协议版本，对应请求目的地址里的魔法域名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpVersion {
    /// `sp.udp-over-tcp.arpa`；参考 `uot.LegacyVersion`。
    V1,
    /// `sp.v2.udp-over-tcp.arpa`；参考 `uot.Version`，AnyTLS v2 使用这一代。
    V2,
}

impl UdpVersion {
    pub fn to_byte(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            _ => None,
        }
    }

    /// 该版本对应的魔法目的地址；请求流用它与服务端协商。
    pub fn magic_address(self) -> &'static str {
        match self {
            Self::V1 => MAGIC_ADDRESS_V1,
            Self::V2 => MAGIC_ADDRESS_V2,
        }
    }
}

/// 参考 `inbound_tcp.go` 的分派判据：目的地址是否落在 `udp-over-tcp.arpa`。
pub fn is_udp_over_tcp_request(host: &str) -> bool {
    host.contains(MAGIC_SUFFIX)
}

/// 从魔法域反推版本；未知魔法域一律按 v1 处理（与 `uot.RequestDestination`
/// 的 `default: fallthrough LegacyVersion` 一致）。
pub fn version_from_magic(host: &str) -> UdpVersion {
    if host.eq_ignore_ascii_case(MAGIC_ADDRESS_V2) {
        UdpVersion::V2
    } else {
        UdpVersion::V1
    }
}

/// UoT 地址族字节（参考 `uot.AddrParser` 的 `AddressFamilyByte` 映射）。
/// 这是本协议最易踩的一处：它与 SOCKS5 的 ATYP 并不相同。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// 0x00 IPv4
    Ipv4,
    /// 0x01 IPv6
    Ipv6,
    /// 0x02 域名（1 字节长度前缀）
    Fqdn,
}

impl AddressFamily {
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Ipv4 => 0x00,
            Self::Ipv6 => 0x01,
            Self::Fqdn => 0x02,
        }
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x00 => Self::Ipv4,
            0x01 => Self::Ipv6,
            0x02 => Self::Fqdn,
            _ => return None,
        })
    }
}

/// 域名长度上限：UoT 用 1 字节长度前缀（参考 `WriteSocksString`）。
const MAX_DOMAIN_BYTES: usize = 255;

/// 地址 + 端口（参考 `M.Socksaddr`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4([u8; 4], u16),
    Ipv6([u8; 16], u16),
    Fqdn(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, port) | Self::Ipv6(_, port) | Self::Fqdn(_, port) => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ipv4(raw, _) => format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3]),
            Self::Ipv6(raw, _) => std::net::Ipv6Addr::from(*raw).to_string(),
            Self::Fqdn(name, _) => name.clone(),
        }
    }

    /// 编码为 UoT 地址：`家族字节 | 地址 | 端口(2B BE)`，无外前缀。
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let mut bytes = Vec::new();
        match self {
            Self::Ipv4(raw, port) => {
                bytes.push(AddressFamily::Ipv4.to_byte());
                bytes.extend_from_slice(raw);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv6(raw, port) => {
                bytes.push(AddressFamily::Ipv6.to_byte());
                bytes.extend_from_slice(raw);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
            Self::Fqdn(name, port) => {
                let raw = name.as_bytes();
                if raw.is_empty() || raw.len() > MAX_DOMAIN_BYTES {
                    return Err(StreamError::InvalidAddress);
                }
                bytes.push(AddressFamily::Fqdn.to_byte());
                bytes.push(raw.len() as u8);
                bytes.extend_from_slice(raw);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(bytes)
    }

    /// 解析 UoT 地址；返回 `(Address, 已消费字节数)`。
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), StreamError> {
        let family = AddressFamily::from_byte(*bytes.first().ok_or(StreamError::Incomplete)?)
            .ok_or(StreamError::InvalidAddress)?;
        match family {
            AddressFamily::Ipv4 => {
                let raw = bytes.get(1..5).ok_or(StreamError::Incomplete)?;
                let port = read_port(bytes, 5)?;
                Ok((Self::Ipv4(raw.try_into().expect("固定长度"), port), 7))
            }
            AddressFamily::Ipv6 => {
                let raw = bytes.get(1..17).ok_or(StreamError::Incomplete)?;
                let port = read_port(bytes, 17)?;
                Ok((Self::Ipv6(raw.try_into().expect("固定长度"), port), 19))
            }
            AddressFamily::Fqdn => {
                let length = *bytes.get(1).ok_or(StreamError::Incomplete)? as usize;
                if length == 0 {
                    return Err(StreamError::InvalidAddress);
                }
                let raw = bytes.get(2..2 + length).ok_or(StreamError::Incomplete)?;
                let name = std::str::from_utf8(raw).map_err(|_| StreamError::InvalidAddress)?;
                let port = read_port(bytes, 2 + length)?;
                Ok((Self::Fqdn(name.to_owned(), port), 4 + length))
            }
        }
    }
}

fn read_port(bytes: &[u8], offset: usize) -> Result<u16, StreamError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(StreamError::Incomplete)?;
    Ok(u16::from_be_bytes(raw.try_into().expect("固定长度")))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("流编号非法：{0}")]
    InvalidId(&'static str),
    #[error("地址非法")]
    InvalidAddress,
    #[error("数据未完整")]
    Incomplete,
    #[error("UoT 请求头非法：{0}")]
    InvalidRequest(&'static str),
    #[error("UoT 报文载荷超出 16 位长度")]
    Oversized,
    #[error("UDP 关联不存在：{0}")]
    UnknownAssociation(u32),
    #[error("UDP 关联已存在：{0}")]
    DuplicateAssociation(u32),
    #[error("该 UoT 会话处于 connect 模式，报文中不得携带地址")]
    UnexpectedAddress,
    #[error("该 UoT 会话非 connect 模式，报文缺少地址")]
    MissingAddress,
}

/// UoT 请求头（参考 `uot.Request`）：`isConnect(1B) | 地址 | 端口`。
///
/// 这里的地址**不是** UoT 报文的家族字节，而是 SOCKS5 的 ATYP：
/// 参考 `uot.EncodeRequest`/`ReadRequest` 用的是 `M.SocksaddrSerializer`
/// （`AddressFamilyByte(0x01, IPv4)`/`0x04, IPv6`/`0x03, Fqdn`），
/// 只有报文里的地址才用 `uot.AddrParser`（`0x00`/`0x01`/`0x02`）。
/// 两者混用在真实互通中会直接错位，已用 Go 侧 `uot.EncodeRequest` 实测锁定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UotRequest {
    /// 1 = 后续报文固定发往 `destination`，报文内不再带地址。
    pub is_connect: bool,
    /// 用 SOCKS5 地址编码（见本结构体的说明）。
    pub destination: socks::SocksAddr,
}

impl UotRequest {
    /// 编码请求头；`isConnect` 是单字节 0/1（参考 `binary.Write`）。
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let address = self.destination.encode()?;
        let mut bytes = Vec::with_capacity(1 + address.len());
        bytes.push(u8::from(self.is_connect));
        bytes.extend_from_slice(&address);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), StreamError> {
        let flag = *bytes.first().ok_or(StreamError::Incomplete)?;
        if flag > 1 {
            return Err(StreamError::InvalidRequest("isConnect 非 0/1"));
        }
        let (destination, consumed) = socks::SocksAddr::decode(&bytes[1..])?;
        Ok((
            Self {
                is_connect: flag == 1,
                destination,
            },
            1 + consumed,
        ))
    }

    /// 关联实际使用的主机名/地址文本，供调用方与魔法域判定共用。
    pub fn destination_host(&self) -> String {
        self.destination.host()
    }

    /// 该请求是否指向 UDP-over-TCP 魔法域（参考 `inbound_tcp.go` 的分派）。
    pub fn is_udp_over_tcp(&self) -> bool {
        is_udp_over_tcp_request(&self.destination.host())
    }
}

/// 一个 UDP 报文的头 + 载荷。载荷为空表示零长报文（UoT 允许，长度字段为 0）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// 非 connect 模式下才携带；connect 模式为 `None`。
    pub address: Option<Address>,
    pub payload: Vec<u8>,
}

impl Datagram {
    /// 编码为一个 UoT 报文：`[地址] | 长度(2B BE) | 载荷`。
    /// `is_connect` 必须与两端协商一致，否则报错（防止静默产生歧义字节）。
    pub fn encode(&self, is_connect: bool) -> Result<Vec<u8>, StreamError> {
        if self.payload.len() > u16::MAX as usize {
            return Err(StreamError::Oversized);
        }
        let mut bytes = Vec::with_capacity(2 + self.payload.len() + 19);
        match (is_connect, &self.address) {
            (true, None) => {}
            (false, Some(address)) => bytes.extend_from_slice(&address.encode()?),
            (true, Some(_)) => return Err(StreamError::UnexpectedAddress),
            (false, None) => return Err(StreamError::MissingAddress),
        }
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// 解析一个 UoT 报文；返回 `(Datagram, 已消费字节数)`。
    pub fn decode(bytes: &[u8], is_connect: bool) -> Result<(Self, usize), StreamError> {
        let address = if is_connect {
            None
        } else {
            let (address, consumed) = Address::decode(bytes)?;
            return Self::decode_with_offset(bytes, Some((address, consumed)));
        };
        Self::decode_with_offset(bytes, address)
    }

    fn decode_with_offset(
        bytes: &[u8],
        address: Option<(Address, usize)>,
    ) -> Result<(Self, usize), StreamError> {
        let (address, offset) = match address {
            Some((address, consumed)) => (Some(address), consumed),
            None => (None, 0),
        };
        let length = read_port(bytes, offset)? as usize;
        let payload = bytes
            .get(offset + 2..offset + 2 + length)
            .ok_or(StreamError::Incomplete)?
            .to_vec();
        Ok((Self { address, payload }, offset + 2 + length))
    }
}

/// 单个已建立的 UDP 关联（一条 UoT 流）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    pub version: UdpVersion,
    pub request: UotRequest,
}

impl Association {
    /// 由请求头建立关联。`is_connect=true` 时后续报文一律发往 `destination`。
    pub fn new(version: UdpVersion, request: UotRequest) -> Self {
        Self { version, request }
    }

    /// 该会话的报文中是否携带地址。
    pub fn carries_address(&self) -> bool {
        !self.request.is_connect
    }

    /// 校验地址与 connect 模式一致后编码一个报文。
    pub fn encode_datagram(&self, datagram: &Datagram) -> Result<Vec<u8>, StreamError> {
        datagram.encode(self.request.is_connect)
    }

    pub fn decode_datagram(&self, bytes: &[u8]) -> Result<(Datagram, usize), StreamError> {
        Datagram::decode(bytes, self.request.is_connect)
    }
}
