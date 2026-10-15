//! Hysteria2 CONNECT-UDP 扩展请求/响应消息层（不是完整协议服务）。
//!
//! CONNECT-UDP 用 HTTP/3 Extended CONNECT（`:protocol = connect-udp`）打开一条
//! 双向流，流首以本模块的消息给出目标地址；响应消息给出放行/拒绝。消息本身
//! 的字节布局与本 crate 的 TCP 帧同风格（capsule 只需自定界的消息体）：
//!
//! ```text
//! ConnectUdpRequest  : varint 0x402 | varint 地址长度 | 地址(host:port) | varint padding 长度 | padding
//! ConnectUdpResponse : status(1 字节, 0=OK, 1=Error) | varint 消息长度 | 消息 | varint padding 长度 | padding
//! ```
//!
//! 类型值 `0x402` 与 `TCPRequest` 的 `0x401` 同一命名空间（QUIC varint 帧类型），
//! 长度上限（地址 ≤2048、消息 ≤2048、padding ≤4096）与参考实现常量相同。
//!
//! 解码返回精确消耗长度，帧之后的字节保留给应用载荷（UDP 报文/后续 capsule），
//! 绝不吞掉；`decode_exact` 用于长度已由外层自定界的场合，消耗长度与输入长度
//! 不一致即拒绝。所有失败 fail-closed：截断、超长、类型不符、非法状态字节、
//! 非 UTF-8、NUL 一律报错，调用方必须丢弃该流。
//!
//! padding 由调用方传入（长度策略见 `padding.rs`），本模块不生成随机数。
//! 认证 token（QUIC TLS transcript 派生的 HMAC）、HTTP/3 帧与头、QUIC 连接与
//! datagram 中继、UDP 报文分片均不属于本模块：依赖 QUIC 栈，待后续实现。
//!
//! 注意：本仓固定的参考 commit（`ca8fbd874fd6ca82413948de6dc5924405e103e1`，
//! `core/internal/protocol/proxy.go` 只有 TCPRequest/TCPResponse/UDPMessage）不含
//! CONNECT-UDP 消息代码，因此本布局是按同风格封装的实现，**未与原生
//! apernet/hysteria 做字节级互通验证，不宣称兼容**。

use crate::frame::{check_len, read_varint, take_bytes, text, text_bytes};
use crate::tcp::{Status, MAX_ADDRESS_LENGTH, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH};
use crate::varint;
use crate::Error;

/// CONNECT-UDP 请求消息类型（QUIC varint 0x402）。
pub const REQUEST_TYPE_CONNECT_UDP: u64 = 0x402;

/// 不派生 Debug（改用手写脱敏实现，见下方）：目标地址是用户连接元数据，
/// 须受隐私策略约束。
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectUdpRequest {
    /// `host:port` 形式的目标地址，1..=2048 字节。
    pub address: String,
    /// 调用方提供的混淆填充，最多 4096 字节。
    pub padding: Vec<u8>,
}

/// 手动实现 `Debug`：只输出长度，不输出内容（与 `tcp::TcpRequest` 同策略）。
impl std::fmt::Debug for ConnectUdpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectUdpRequest")
            .field("address_len", &self.address.len())
            .field("padding_len", &self.padding.len())
            .finish()
    }
}

/// 不派生 Debug（改用手写脱敏实现，见下方）：错误消息可能包含内部信息。
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectUdpResponse {
    pub status: Status,
    /// 允许为空，最多 2048 字节。
    pub message: String,
    pub padding: Vec<u8>,
}

/// 手动实现 `Debug`：状态字节可以输出，消息与 padding 只输出长度。
impl std::fmt::Debug for ConnectUdpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectUdpResponse")
            .field("status", &self.status)
            .field("message_len", &self.message.len())
            .field("padding_len", &self.padding.len())
            .finish()
    }
}

impl ConnectUdpRequest {
    /// 校验字段并返回完整消息字节数；超限在写入任何字节前失败。
    pub fn encoded_len(&self) -> Result<usize, Error> {
        check_len("address", self.address.len() as u64, 1, MAX_ADDRESS_LENGTH)?;
        check_len("padding", self.padding.len() as u64, 0, MAX_PADDING_LENGTH)?;
        text_bytes("address", self.address.as_bytes())?;
        Ok(varint::size(REQUEST_TYPE_CONNECT_UDP)?
            + varint::size(self.address.len() as u64)?
            + self.address.len()
            + varint::size(self.padding.len() as u64)?
            + self.padding.len())
    }

    /// 编码完整 CONNECT-UDP 请求（含 0x402 类型）。
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.encoded_len()?);
        varint::append(REQUEST_TYPE_CONNECT_UDP, &mut bytes)?;
        varint::append(self.address.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(self.address.as_bytes());
        varint::append(self.padding.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(&self.padding);
        Ok(bytes)
    }

    /// 解析完整 CONNECT-UDP 请求，返回（请求，消耗字节数）。
    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        let (request_type, offset) = read_varint(input, 0)?;
        if request_type != REQUEST_TYPE_CONNECT_UDP {
            return Err(Error::InvalidFrameType {
                value: request_type,
            });
        }
        let (addr_len, offset) = read_varint(input, offset)?;
        check_len("address", addr_len, 1, MAX_ADDRESS_LENGTH)?;
        let (address, offset) = take_bytes(input, offset, addr_len)?;
        let address = text("address", address)?;
        let (padding_len, offset) = read_varint(input, offset)?;
        check_len("padding", padding_len, 0, MAX_PADDING_LENGTH)?;
        let (padding, offset) = take_bytes(input, offset, padding_len)?;
        Ok((
            ConnectUdpRequest {
                address,
                padding: padding.to_vec(),
            },
            offset,
        ))
    }

    /// 解析已由外层定界的 CONNECT-UDP 请求：消耗长度必须等于输入长度。
    ///
    /// 剩余字节意味着外层声明的长度与消息实际长度不一致（典型为长度字段
    /// 被篡改或 capsule 切分错误），一律拒绝而不是留下未消费的字节。
    pub fn decode_exact(input: &[u8]) -> Result<Self, Error> {
        let (message, used) = Self::decode(input)?;
        if used != input.len() {
            return Err(Error::LengthMismatch {
                declared: input.len(),
                consumed: used,
            });
        }
        Ok(message)
    }
}

impl ConnectUdpResponse {
    /// 校验字段并返回完整消息字节数。
    pub fn encoded_len(&self) -> Result<usize, Error> {
        check_len("message", self.message.len() as u64, 0, MAX_MESSAGE_LENGTH)?;
        check_len("padding", self.padding.len() as u64, 0, MAX_PADDING_LENGTH)?;
        text_bytes("message", self.message.as_bytes())?;
        Ok(1 + varint::size(self.message.len() as u64)?
            + self.message.len()
            + varint::size(self.padding.len() as u64)?
            + self.padding.len())
    }

    /// 编码完整 CONNECT-UDP 响应。
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.encoded_len()?);
        bytes.push(self.status.as_byte());
        varint::append(self.message.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(self.message.as_bytes());
        varint::append(self.padding.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(&self.padding);
        Ok(bytes)
    }

    /// 解析完整 CONNECT-UDP 响应，返回（响应，消耗字节数）。
    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        let byte = *input.first().ok_or(Error::Truncated { need: 1, got: 0 })?;
        let status = Status::from_byte(byte)?;
        let (msg_len, offset) = read_varint(input, 1)?;
        check_len("message", msg_len, 0, MAX_MESSAGE_LENGTH)?;
        let (message, offset) = take_bytes(input, offset, msg_len)?;
        let message = text("message", message)?;
        let (padding_len, offset) = read_varint(input, offset)?;
        check_len("padding", padding_len, 0, MAX_PADDING_LENGTH)?;
        let (padding, offset) = take_bytes(input, offset, padding_len)?;
        Ok((
            ConnectUdpResponse {
                status,
                message,
                padding: padding.to_vec(),
            },
            offset,
        ))
    }

    /// 解析已由外层定界的 CONNECT-UDP 响应：消耗长度必须等于输入长度，
    /// 不一致即拒绝（理由同 [`ConnectUdpRequest::decode_exact`]）。
    pub fn decode_exact(input: &[u8]) -> Result<Self, Error> {
        let (message, used) = Self::decode(input)?;
        if used != input.len() {
            return Err(Error::LengthMismatch {
                declared: input.len(),
                consumed: used,
            });
        }
        Ok(message)
    }
}
