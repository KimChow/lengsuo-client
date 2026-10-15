//! Trojan 基础请求头编解码（不是完整协议服务）。
//!
//! 线上格式与参考实现一致（Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`proxy/trojan/protocol.go`）：
//!
//! ```text
//! 密码哈希(56 字节小写 hex) CRLF 命令(1 字节) SOCKS 地址+端口(2 字节) CRLF
//! ```
//!
//! 地址部分复用 `ss_core::target::TargetAddr` 的 `encode_checked` / `decode`，
//! 不复制地址实现。`decode` 只报告头部消耗长度，不吞掉同一缓冲区中的应用载荷。
//! TLS 由上层负责；本模块不提供服务端逻辑，也没有任何明文回退路径。

use ss_core::target::TargetAddr;
use subtle::ConstantTimeEq as _;

use crate::credential::{Credential, HASH_LEN};

/// 头部两处 CRLF 分隔符。
const CRLF: [u8; 2] = *b"\r\n";

/// 请求命令。Trojan 头部只定义 TCP=1 与 UDP=3。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Tcp = 1,
    Udp = 3,
}

impl Command {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Command::Tcp),
            3 => Some(Command::Udp),
            _ => None,
        }
    }
}

/// 编码/解码错误。认证失败与格式失败分开报告，调用方一律 fail-closed。
/// 地址错误透传 `ss_core::Error`，因此本类型不派生 PartialEq。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("输入不足：需要 {need} 字节，实际 {got}")]
    Truncated { need: usize, got: usize },

    #[error("密码哈希校验失败")]
    Authentication,

    #[error("偏移 {offset} 处缺少 CRLF")]
    InvalidCrlf { offset: usize },

    #[error("非法命令字节：{0:#04x}")]
    InvalidCommand(u8),

    #[error("目标地址非法：{0}")]
    Address(#[from] ss_core::Error),
}

/// 请求头部不含凭据；是否记录目标地址仍须服从隐私策略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub target: TargetAddr,
}

impl Request {
    /// 头部总长度：哈希 + CRLF + 命令 + 地址 + CRLF。
    #[must_use]
    pub fn header_len(&self) -> usize {
        HASH_LEN + 2 + 1 + self.target.encoded_len() + 2
    }
}

/// 编码请求头部；非法域名在写入任何字节前由 `encode_checked` 拒绝。
pub fn encode(request: &Request, credential: &Credential) -> Result<Vec<u8>, Error> {
    let mut header = Vec::with_capacity(request.header_len());
    header.extend_from_slice(credential.as_bytes());
    header.extend_from_slice(&CRLF);
    header.push(request.command as u8);
    request
        .target
        .encode_checked(&mut header)
        .map_err(Error::Address)?;
    header.extend_from_slice(&CRLF);
    Ok(header)
}

/// 解析并校验请求头部，返回（请求，头部消耗字节数）。
///
/// 哈希比较使用常量时间实现；认证通过后才解析命令与地址，
/// 因此认证失败不会先暴露地址解析结果。
pub fn decode(input: &[u8], credential: &Credential) -> Result<(Request, usize), Error> {
    let hash = peek(input, 0, HASH_LEN)?;
    if !bool::from(credential.as_bytes().ct_eq(hash)) {
        return Err(Error::Authentication);
    }

    let mut offset = HASH_LEN;
    offset = expect_crlf(input, offset)?;

    let command = match input.get(offset) {
        Some(&byte) => Command::from_byte(byte).ok_or(Error::InvalidCommand(byte))?,
        None => return Err(truncated(input, offset + 1)),
    };
    offset += 1;

    let (target, used) = decode_target(input, offset)?;
    offset += used;
    offset = expect_crlf(input, offset)?;
    Ok((Request { command, target }, offset))
}

/// 解析 SOCKS 地址，返回（地址，消耗字节数）；截断按头部总长度报告。
fn decode_target(input: &[u8], offset: usize) -> Result<(TargetAddr, usize), Error> {
    TargetAddr::decode(&input[offset..]).map_err(|error| match error {
        ss_core::Error::TooShort { need, .. } => truncated(input, offset + need),
        other => Error::Address(other),
    })
}

/// 断言 `offset` 处是 2 字节 CRLF，返回其后偏移。
fn expect_crlf(input: &[u8], offset: usize) -> Result<usize, Error> {
    if peek(input, offset, CRLF.len())? == CRLF {
        Ok(offset + CRLF.len())
    } else {
        Err(Error::InvalidCrlf { offset })
    }
}

/// 取 `input[offset..offset+len]`；不足时按所需总长度报截断。
fn peek(input: &[u8], offset: usize, len: usize) -> Result<&[u8], Error> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| truncated(input, usize::MAX))?;
    input.get(offset..end).ok_or_else(|| truncated(input, end))
}

/// 截断错误：need 为完整头部所需总字节数，got 为当前可用字节数。
fn truncated(input: &[u8], need: usize) -> Error {
    Error::Truncated {
        need,
        got: input.len(),
    }
}
