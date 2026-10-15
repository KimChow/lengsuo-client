//! IPv4/IPv6 到 TCP/UDP 的只读报文元数据解析。
//!
//! 这是安全策略与分流决策用的纯 Rust 解析器，不是 Windows/Linux TUN 驱动，
//! 不创建或删除网络接口，也不改写任何报文。
//! 解析结果只包含地址、端口与载荷偏移；不携带环境身份、进程或归属信息，
//! 这类上下文必须由上层显式传入，本模块不会伪造。
//!
//! 已知范围限制：暂不校验 TCP/UDP 传输层校验和，也不做 IP 选项语义解析，
//! 因此不得把它描述为完整的入站安全验证；调用方仍需按用途补足检查。

#![forbid(unsafe_code)]

pub mod packet;

pub use packet::{inspect, Error, PacketInfo, Transport};
