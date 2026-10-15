#![forbid(unsafe_code)]
//! lengsuo-hysteria — Hysteria2 TCP 请求/响应帧与 QUIC varint 原语。
//!
//! 已有：RFC 9000 变长整数（规范最短编码、允许非最短解码）、
//! TCPRequest（帧类型 0x401 + 地址 + padding）与 TCPResponse（状态 +
//! 消息 + padding）的安全编解码。解析返回精确消耗长度，帧之后的字节
//! 保留给应用载荷，不吞掉任何数据。
//!
//! 尚未实现：QUIC 连接与流、HTTP/3 伪装与 `POST /auth` 认证、UDP 中继
//! 报文与分片、Salamander 混淆、以及与 apernet/hysteria 的真实互通验收。
//! 本 crate 不能作为可用 Hysteria2 客户端或服务端发布。
//! 状态与验证记录见 `docs/hysteria-status.md`。

pub mod tcp;
pub mod varint;

/// 帧编解码错误。所有失败均 fail-closed：调用方必须丢弃该流，不得在
/// 未对齐的字节流上继续读取，也不得回退到明文。
///
/// `Truncated` 的 `need` 是已解析字段完整结束所需的最小字节数，
/// `got` 是当前缓冲区可用字节数。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("输入不足：至少需要 {need} 字节，实际 {got}")]
    Truncated { need: usize, got: usize },

    #[error("数值超过 QUIC varint 上限 2^62-1：{value}")]
    VarIntOutOfRange { value: u64 },

    #[error("TCP 请求帧类型不是 0x401：{value}")]
    InvalidFrameType { value: u64 },

    #[error("TCP 响应状态字节非法：{byte}")]
    InvalidStatus { byte: u8 },

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
}
