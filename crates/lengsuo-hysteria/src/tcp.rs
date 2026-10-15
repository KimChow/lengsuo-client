//! Hysteria2 TCP 请求/响应帧（不是完整协议服务）。
//!
//! 线上格式与参考实现一致（apernet/hysteria 完整 commit
//! `ca8fbd874fd6ca82413948de6dc5924405e103e1`，`PROTOCOL.md` 与
//! `core/internal/protocol/proxy.go`）：
//!
//! ```text
//! TCPRequest  : varint 0x401 | varint 地址长度 | 地址(host:port) | varint padding 长度 | padding
//! TCPResponse : status(1 字节, 0=OK, 1=Error) | varint 消息长度 | 消息 | varint padding 长度 | padding
//! ```
//!
//! 参考实现的 `ReadTCPRequest` 假设调用方已读走帧类型，只从地址长度开始
//! 解析；本模块 `TcpRequest::decode` 是完整帧解码，自己先读 `0x401` 并校验。
//!
//! 解码返回精确消耗长度，帧之后的字节保留给应用载荷，绝不吞掉。
//! padding 由调用方传入，本模块不生成随机数，也不实现 padding 策略。
//! 长度字段接受 QUIC 允许的非最短 varint（与 `quicvarint.Read` 一致），
//! 编码侧永远输出最短形式。地址/消息按 Rust 侧更严格的规则校验：必须为
//! 合法 UTF-8 且不含 NUL（Go 字符串是字节切片，无此约束），长度上限与
//! 参考实现相同。QUIC 连接、HTTP/3 伪装认证、UDP 与分片不属于本模块。

use crate::varint;
use crate::Error;

/// TCPRequest 帧类型（QUIC varint 0x401）。
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// 防 DoS 上限，与参考实现常量相同。
pub const MAX_ADDRESS_LENGTH: u64 = 2048;
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
pub const MAX_PADDING_LENGTH: u64 = 4096;

/// 响应状态字节；协议只定义 0x00 与 0x01。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// 目标连接成功。
    Ok = 0,
    /// 失败，消息字段给出原因。
    Error = 1,
}

impl Status {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    fn from_byte(byte: u8) -> Result<Self, Error> {
        match byte {
            0 => Ok(Status::Ok),
            1 => Ok(Status::Error),
            other => Err(Error::InvalidStatus { byte: other }),
        }
    }
}

/// 不派生 Debug（改用手写脱敏实现，见下方）：目标地址是用户连接元数据，
/// 须受隐私策略约束。
#[derive(Clone, PartialEq, Eq)]
pub struct TcpRequest {
    /// `host:port` 形式的目标地址，1..=2048 字节。
    pub address: String,
    /// 调用方提供的混淆填充，最多 4096 字节。
    pub padding: Vec<u8>,
}

/// 手动实现 `Debug`：只输出长度，不输出内容。目标地址与错误消息属于
/// 连接元数据，可能进入 panic 文本或日志，因此受隐私策略约束。
impl std::fmt::Debug for TcpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpRequest")
            .field("address_len", &self.address.len())
            .field("padding_len", &self.padding.len())
            .finish()
    }
}

/// 不派生 Debug（改用手写脱敏实现，见下方）：错误消息可能包含内部信息。
#[derive(Clone, PartialEq, Eq)]
pub struct TcpResponse {
    pub status: Status,
    /// 允许为空，最多 2048 字节。
    pub message: String,
    pub padding: Vec<u8>,
}

/// 手动实现 `Debug`：状态字节可以输出，消息与 padding 只输出长度。
impl std::fmt::Debug for TcpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpResponse")
            .field("status", &self.status)
            .field("message_len", &self.message.len())
            .field("padding_len", &self.padding.len())
            .finish()
    }
}

impl TcpRequest {
    /// 校验字段并返回完整帧字节数；超限在写入任何字节前失败。
    pub fn encoded_len(&self) -> Result<usize, Error> {
        check_len("address", self.address.len() as u64, 1, MAX_ADDRESS_LENGTH)?;
        check_len("padding", self.padding.len() as u64, 0, MAX_PADDING_LENGTH)?;
        text_bytes("address", self.address.as_bytes())?;
        Ok(varint::size(FRAME_TYPE_TCP_REQUEST)?
            + varint::size(self.address.len() as u64)?
            + self.address.len()
            + varint::size(self.padding.len() as u64)?
            + self.padding.len())
    }

    /// 编码完整 TCPRequest（含 0x401 帧类型）。
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.encoded_len()?);
        varint::append(FRAME_TYPE_TCP_REQUEST, &mut bytes)?;
        varint::append(self.address.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(self.address.as_bytes());
        varint::append(self.padding.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(&self.padding);
        Ok(bytes)
    }

    /// 解析完整 TCPRequest，返回（请求，消耗字节数）。
    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        let (frame_type, offset) = read_varint(input, 0)?;
        if frame_type != FRAME_TYPE_TCP_REQUEST {
            return Err(Error::InvalidFrameType { value: frame_type });
        }
        let (addr_len, offset) = read_varint(input, offset)?;
        check_len("address", addr_len, 1, MAX_ADDRESS_LENGTH)?;
        let (address, offset) = take_bytes(input, offset, addr_len)?;
        let address = text("address", address)?;
        let (padding_len, offset) = read_varint(input, offset)?;
        check_len("padding", padding_len, 0, MAX_PADDING_LENGTH)?;
        let (padding, offset) = take_bytes(input, offset, padding_len)?;
        Ok((
            TcpRequest {
                address,
                padding: padding.to_vec(),
            },
            offset,
        ))
    }
}

impl TcpResponse {
    /// 校验字段并返回完整帧字节数。
    pub fn encoded_len(&self) -> Result<usize, Error> {
        check_len("message", self.message.len() as u64, 0, MAX_MESSAGE_LENGTH)?;
        check_len("padding", self.padding.len() as u64, 0, MAX_PADDING_LENGTH)?;
        text_bytes("message", self.message.as_bytes())?;
        Ok(1 + varint::size(self.message.len() as u64)?
            + self.message.len()
            + varint::size(self.padding.len() as u64)?
            + self.padding.len())
    }

    /// 编码完整 TCPResponse。
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.encoded_len()?);
        bytes.push(self.status.as_byte());
        varint::append(self.message.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(self.message.as_bytes());
        varint::append(self.padding.len() as u64, &mut bytes)?;
        bytes.extend_from_slice(&self.padding);
        Ok(bytes)
    }

    /// 解析完整 TCPResponse，返回（响应，消耗字节数）。
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
            TcpResponse {
                status,
                message,
                padding: padding.to_vec(),
            },
            offset,
        ))
    }
}

/// 在 `offset` 处读取 varint，返回（取值，其后绝对偏移）。
fn read_varint(input: &[u8], offset: usize) -> Result<(u64, usize), Error> {
    let rest = input.get(offset..).ok_or(Error::Truncated {
        need: offset.saturating_add(1),
        got: input.len(),
    })?;
    let (value, used) = varint::decode(rest).map_err(|error| match error {
        Error::Truncated { need, .. } => Error::Truncated {
            need: offset.saturating_add(need),
            got: input.len(),
        },
        other => other,
    })?;
    Ok((value, offset + used))
}

/// 取 `input[offset..offset+len]`，返回（切片，其后绝对偏移）。
///
/// 长度上限已在上游按协议常量校验，这里只处理输入不足。相加溢出归一为
/// `usize::MAX`，仍按截断失败，不因大长度字段 panic。
fn take_bytes(input: &[u8], offset: usize, len: u64) -> Result<(&[u8], usize), Error> {
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let end = offset.saturating_add(len);
    input
        .get(offset..end)
        .map(|slice| (slice, end))
        .ok_or(Error::Truncated {
            need: end,
            got: input.len(),
        })
}

/// 长度范围检查；`min` 为 1 时为空视为协议违规。
fn check_len(field: &'static str, len: u64, min: u64, max: u64) -> Result<(), Error> {
    if len < min {
        return Err(Error::EmptyField { field });
    }
    if len > max {
        return Err(Error::TooLong { field, len, max });
    }
    Ok(())
}

/// NUL 先于 UTF-8 报告：NUL 本身是合法 UTF-8，但地址与消息一律禁止。
fn text_bytes(field: &'static str, bytes: &[u8]) -> Result<(), Error> {
    if bytes.contains(&0) {
        return Err(Error::ContainsNul { field });
    }
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8 { field })?;
    Ok(())
}

fn text(field: &'static str, bytes: &[u8]) -> Result<String, Error> {
    text_bytes(field, bytes)?;
    Ok(String::from_utf8(bytes.to_vec()).expect("上文已确认字节是合法 UTF-8"))
}
