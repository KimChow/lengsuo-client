#![forbid(unsafe_code)]
//! lengsuo-hysteria — Hysteria2 帧原语：QUIC varint、TCP 请求/响应、
//! CONNECT-UDP 消息层、padding 长度策略与 UDP 分片重组。
//!
//! 已有：RFC 9000 变长整数（规范最短编码、允许非最短解码）、
//! TCPRequest（帧类型 0x401 + 地址 + padding）与 TCPResponse（状态 +
//! 消息 + padding）的安全编解码、CONNECT-UDP 请求（类型 0x402）与响应
//! 的消息层编解码（含 `decode_exact` 精确长度一致性检查）、padding.go
//! 的填充长度策略（半开区间 + `SegmentSize` 上下取整，纯函数、随机由调用方注入），
//! 以及 `frag.go` 的 UDP 分片重组状态机与切片判据（`fragment.rs`，
//! 只维持单个 packet 的半截状态，与参考同形）。
//! 解析返回精确消耗长度，帧之后的字节保留给应用载荷，不吞掉任何数据。
//!
//! 客户端与服务端方向均已实现 QUIC 传输、HTTP/3 认证与 TCP/UDP 承载
//! （`quic::{client,server}`、`h3_auth`、`h3_server`、`proxy`），并与参考 Xray
//! 真实互通（见 `tests/xray_hysteria.rs`、`tests/xray_hysteria_server.rs`）。
//! UDP 中继报文本身的消息层字节编解码见 `udp.rs`；分片重组与切片见
//! `fragment.rs`。
//!
//! 0-RTT：客户端已接入 quinn `into_0rtt`（`quic/early.rs`，默认关闭；
//! 有会话票据时尝试早数据，拒绝路径可观测并经显式入口回退 1-RTT）。
//! 与参考 Xray 服务端的 0-RTT **互通尚未打通**：Xray `hub.go` 的
//! `quic.Config` 未设 `Allow0RTT`，其下发票据的早数据上限为 0，rustls 因此
//! 无法产生早数据（详见 `docs/hysteria-status.md`）。
//!
//! 拥塞器：Brutal 内核已在 `lengsuo-congestion` 实现并经 quinn `ControllerFactory`
//! 注入（`congestion/wire.rs:149`）；BBR 未移植；未配置 up/down 时仍用 quinn 默认 CUBIC。
//! 尚未实现（不宣称）：服务端接受 0-RTT、连接迁移、masquerade 自定义（file/proxy/string）。
//! 状态、验收命令与偏离清单见 `docs/hysteria-status.md`。

pub mod congestion;
pub mod connect_udp;
pub mod fragment;
mod frame;
pub mod h3_auth;
pub mod h3_server;
pub mod obfs;
pub mod padding;
pub mod proxy;
pub mod qpack;
pub mod quic;
pub mod tcp;
pub mod transport;
pub mod udp;
pub mod varint;

/// 帧编解码错误。所有失败均 fail-closed：调用方必须丢弃该流，不得在
/// 未对齐的字节流上继续读取，也不得回退到明文。
///
/// `Truncated` 的 `need` 是已解析字段完整结束所需的最小字节数，
/// `got` 是当前缓冲区可用字节数。错误文本只携带长度与取值等元数据，
/// 不输出地址、消息或 padding 内容。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("输入不足：至少需要 {need} 字节，实际 {got}")]
    Truncated { need: usize, got: usize },

    #[error("数值超过 QUIC varint 上限 2^62-1：{value}")]
    VarIntOutOfRange { value: u64 },

    #[error("帧类型与帧定义不符（TCPRequest 期望 0x401，CONNECT-UDP 请求期望 0x402）：{value}")]
    InvalidFrameType { value: u64 },

    #[error("响应状态字节非法，协议只定义 0x00/0x01：{byte}")]
    InvalidStatus { byte: u8 },

    #[error("帧实际长度与外层声明长度不一致：声明 {declared} 字节，实际消耗 {consumed}")]
    LengthMismatch { declared: usize, consumed: usize },

    #[error("{field} 为空：地址至少需要 1 字节")]
    EmptyField { field: &'static str },

    #[error("{field} 长度 {len} 超过上限 {max}")]
    TooLong {
        field: &'static str,
        len: u64,
        max: u64,
    },

    #[error("{field} 含 NUL 字节")]
    ContainsNul { field: &'static str },

    #[error("{field} 不是合法 UTF-8")]
    InvalidUtf8 { field: &'static str },

    #[error("padding 长度区间或抽样值非法：区间 [{min}, {max})，宽度 {span}，抽样值 {sample}")]
    PaddingRangeInvalid {
        min: u64,
        max: u64,
        sample: u64,
        span: u64,
    },

    #[error("SegmentSize 非法，不能为 0：{segment}")]
    SegmentSizeInvalid { segment: usize },
}
