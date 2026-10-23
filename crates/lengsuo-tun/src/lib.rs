//! IPv4/IPv6 到 TCP/UDP 的只读报文元数据解析，加上纯内存的数据面决策原语。
//!
//! 这是安全策略与分流决策用的纯 Rust 解析器与状态表，不是 Windows/Linux TUN 驱动，
//! 不创建或删除网络接口，不发送报文，也不改写任何在途报文。
//! 解析结果只包含地址、端口与载荷偏移；不携带环境身份、进程或归属信息，
//! 这类上下文必须由上层显式传入，本模块不会伪造。
//!
//! 模块分工：
//! - `packet`：只读头部元数据解析，分片与扩展头一律显式拒绝。
//! - `dns`：DNS 报文结构解析（RFC 1035）与查询转发重写、响应回注匹配（`dns::rewrite`）。
//! - `checksum`：TCP/UDP 伪首部与传输段校验和验证。
//! - `session`：泛型五元组会话表，容量与 TTL 参数化，容量满时 fail-closed 拒绝。
//! - `mtu`：路径 MTU 判定与 PMTUD（ICMPv4 type 3/code 4、ICMPv6 Packet Too Big）
//!   错误报文生成。
//!
//! 已知范围限制：`packet` 的元数据解析本身不校验 TCP/UDP 传输层校验和，也不做 IP
//! 选项语义解析；`checksum` 模块单独提供伪首部与整个传输段的校验和验证。两者都不
//! 验证 TCP 状态，不得描述为完整的入站安全验证；调用方仍需按用途补足检查。
//! `session` 与 `mtu` 都不调用系统时钟、不读取真实接口参数：时钟刻度与接口 MTU 都
//! 由上层传入，因此这些原语不构成设备接入、用户态 TCP 栈或 DNS 的实现。

#![forbid(unsafe_code)]

pub mod checksum;
#[cfg(windows)]
pub mod device;
pub mod dns;
pub mod egress;
pub mod ingress;
pub mod lifecycle;
pub mod mtu;
pub mod packet;
pub mod route;
pub mod session;
pub mod tcp;

pub use mtu::{
    carried_prefix, decide, decide_from, error_packet, Decision, Direction, Error as MtuError,
    IpVersion, MAX_MTU_V4_FIELD, MIN_PATH_MTU_V4, MIN_PATH_MTU_V6,
};
pub use packet::{inspect, Error, PacketInfo, Transport};
pub use session::{Clock, OpenError, SessionKey, SessionTable};
