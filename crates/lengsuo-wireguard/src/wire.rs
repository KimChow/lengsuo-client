//! WireGuard 报文头解析：只做类型字段与长度的 fail-closed 检查。
//!
//! 线上格式依据 WireGuard 官方公开协议文档自主实现（未读取、未复制 GPL 内核
//! 源代码）：报文首 4 字节为 little endian 消息类型，高 3 字节必须为 0。
//!
//! ```text
//! 类型 1 握手初始化  精确 148 字节
//! 类型 2 握手响应    精确  92 字节
//! 类型 3 COOKIE      精确  64 字节
//! 类型 4 运输        至少  32 字节（头 16 + AEAD 标签 16 + 密文正文）
//! ```
//!
//! 运输报文在本层只有 **32 字节的结构下限**：明文是否按 16 字节对齐属于
//! 解密后才可判定的属性，本模块看不到内层 IP 报文，因此**不校验整包长度为
//! 16 的倍数**（33 字节的运输报文在这里结构可解析）。报文的真实有效性由
//! 后续 AEAD 认证解密与内层 IP 解析共同决定，不由本模块背书。
//!
//! **本模块不验证任何 MAC，也不解密任何载荷。** 握手变体只返回通过类型与长度
//! 检查后的原始借用字节；运输变体只返回头部字段与密文切片。真正的
//! Noise 握手状态机、X25519 密钥协商、blake2s/HKDF、AEAD 加解密与
//! COOKIE 生成校验均未实现，必须由上层完成后才可认定报文可信。

/// 类型字段长度（u32 little endian）。
const MESSAGE_TYPE_LEN: usize = 4;
/// 运输报文固定头部：类型(4) + 接收者(4) + 计数器(8)。
const TRANSPORT_HEADER_LEN: usize = 16;
/// AEAD 认证标签长度。
const AEAD_TAG_LEN: usize = 16;

/// 握手初始化报文总长。
pub const INIT_LEN: usize = 148;
/// 握手响应报文总长。
pub const RESPONSE_LEN: usize = 92;
/// COOKIE 报文总长。
pub const COOKIE_LEN: usize = 64;
/// 运输报文最小总长：头部 + 至少一个 AEAD 标签长度。
pub const TRANSPORT_MIN_LEN: usize = TRANSPORT_HEADER_LEN + AEAD_TAG_LEN;

const TYPE_INIT: u32 = 1;
const TYPE_RESPONSE: u32 = 2;
const TYPE_COOKIE: u32 = 3;
const TYPE_TRANSPORT: u32 = 4;

/// 解析失败原因。所有分支都是 fail-closed：不存在宽松回退路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 输入短于类型字段，无法判定报文种类。
    #[error("报文短于 4 字节类型字段")]
    Incomplete,
    /// 类型字段高 3 字节非零（保留位必须为 0）。
    #[error("类型字段高 3 字节保留位非零：{0:#010x}")]
    ReservedType(u32),
    /// 类型值不在 1..=4。
    #[error("未知消息类型 {0}")]
    UnknownType(u32),
    /// 握手报文长度与类型要求不一致。`kind` 为类型值，`expected` 为精确长度。
    #[error("类型 {kind} 报文长度为 {actual} 字节，要求精确 {expected} 字节")]
    HandshakeLength {
        kind: u32,
        actual: usize,
        expected: usize,
    },
    /// 运输报文短于 32 字节，装不下头部（16）与至少一个 AEAD 标签（16）。
    #[error("运输报文长度 {0} 小于最小值 32 字节")]
    TransportTooShort(usize),
}

/// 握手报文的种类。仅表示类型字段读数，不代表任何密码学校验。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    /// 类型 1：握手初始化。
    Init,
    /// 类型 2：握手响应。
    Response,
    /// 类型 3：COOKIE 重试令牌。
    Cookie,
}

impl HandshakeKind {
    /// 该类型要求的精确报文总长。
    pub const fn exact_len(self) -> usize {
        match self {
            HandshakeKind::Init => INIT_LEN,
            HandshakeKind::Response => RESPONSE_LEN,
            HandshakeKind::Cookie => COOKIE_LEN,
        }
    }

    /// 该类型对应的线上类型字段值。
    const fn type_value(self) -> u32 {
        match self {
            HandshakeKind::Init => TYPE_INIT,
            HandshakeKind::Response => TYPE_RESPONSE,
            HandshakeKind::Cookie => TYPE_COOKIE,
        }
    }
}

/// 已通过类型与长度检查的握手原始字节。
///
/// `bytes` **未经 MAC 验证、未经解密**（响应与 COOKIE 的正文本身是密文），
/// 调用方不得据此认定报文可信。Debug 只输出种类与长度，不输出字节内容，
/// 避免把疑似凭据的材料带进日志。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMessage<'a> {
    pub kind: HandshakeKind,
    bytes: &'a [u8],
}

impl<'a> HandshakeMessage<'a> {
    /// 原始借用字节，长度等于 `kind.exact_len()`。内容未经验证。
    #[must_use]
    pub fn unverified_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl core::fmt::Debug for HandshakeMessage<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HandshakeMessage")
            .field("kind", &self.kind)
            .field("len", &self.bytes.len())
            // 故意不输出 bytes：本模块无法验证 MAC，也不得把疑似凭据写入日志。
            .finish_non_exhaustive()
    }
}

/// 运输报文头部字段与密文切片。
///
/// Debug 不输出 `encrypted` 内容，只输出长度：密文与其明文的边界在本模块
/// 之外，任何载荷字节都不得进入日志。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransportMessage<'a> {
    /// 接收者标识：类型字段后的 4 字节 little endian。
    pub receiver: u32,
    /// 报文计数器：8..16 字节 little endian。
    pub counter: u64,
    /// 头部之后的密文（含 AEAD 标签），即 `&packet[16..]`。
    pub encrypted: &'a [u8],
}

impl core::fmt::Debug for TransportMessage<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TransportMessage")
            .field("receiver", &self.receiver)
            .field("counter", &self.counter)
            .field("encrypted_len", &self.encrypted.len())
            // 故意不输出 encrypted。
            .finish_non_exhaustive()
    }
}

/// 解析出的报文。借用输入字节，不复制、不改写。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    /// 类型 1 握手初始化（原始字节，未验证 MAC）。
    Init(HandshakeMessage<'a>),
    /// 类型 2 握手响应（原始字节，正文为密文，未解密、未验证 MAC）。
    Response(HandshakeMessage<'a>),
    /// 类型 3 COOKIE（原始字节，正文为密文，未解密、未验证 MAC）。
    Cookie(HandshakeMessage<'a>),
    /// 类型 4 运输报文（头部字段 + 密文切片，未解密）。
    Transport(TransportMessage<'a>),
}

impl Message<'_> {
    /// 运输报文的计数器读数；握手类报文没有该字段，返回 `None`。
    #[must_use]
    pub fn counter(&self) -> Option<u64> {
        match self {
            Message::Transport(transport) => Some(transport.counter),
            _ => None,
        }
    }
}

/// 解析单个 WireGuard 报文头部。
///
/// 只做：长度足够读取类型字段、类型字段保留位为零、类型已知、长度符合该类型
/// 要求。其它一切（MAC、解密、序号语义、对端身份）都不在本函数职责内。
pub fn parse(packet: &[u8]) -> Result<Message<'_>, Error> {
    if packet.len() < MESSAGE_TYPE_LEN {
        return Err(Error::Incomplete);
    }
    let raw = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
    // 高 3 字节是保留位，必须为 0；非零说明流错位或伪造，直接拒绝。
    if raw >> 8 != 0 {
        return Err(Error::ReservedType(raw));
    }
    match raw {
        TYPE_INIT => Ok(Message::Init(handshake(packet, HandshakeKind::Init)?)),
        TYPE_RESPONSE => Ok(Message::Response(handshake(
            packet,
            HandshakeKind::Response,
        )?)),
        TYPE_COOKIE => Ok(Message::Cookie(handshake(packet, HandshakeKind::Cookie)?)),
        TYPE_TRANSPORT => Ok(Message::Transport(transport(packet)?)),
        other => Err(Error::UnknownType(other)),
    }
}

fn handshake(packet: &[u8], kind: HandshakeKind) -> Result<HandshakeMessage<'_>, Error> {
    let expected = kind.exact_len();
    if packet.len() != expected {
        return Err(Error::HandshakeLength {
            kind: kind.type_value(),
            actual: packet.len(),
            expected,
        });
    }
    Ok(HandshakeMessage {
        kind,
        bytes: packet,
    })
}

fn transport(packet: &[u8]) -> Result<TransportMessage<'_>, Error> {
    if packet.len() < TRANSPORT_MIN_LEN {
        return Err(Error::TransportTooShort(packet.len()));
    }
    // 结构下限只有 32 字节：整包长度是否为 16 的倍数取决于未解密的明文长度，
    // 属于 AEAD 认证解密与内层 IP 解析之后的范畴，本层不判定、也不背书。
    // 长度已保证 >= 32，这里的带检查取切片只是将越界可能性显式排除。
    let too_short = || Error::TransportTooShort(packet.len());
    let receiver = packet.get(4..8).ok_or_else(too_short)?;
    let counter = packet.get(8..TRANSPORT_HEADER_LEN).ok_or_else(too_short)?;
    Ok(TransportMessage {
        receiver: u32::from_le_bytes([receiver[0], receiver[1], receiver[2], receiver[3]]),
        counter: u64::from_le_bytes([
            counter[0], counter[1], counter[2], counter[3], counter[4], counter[5], counter[6],
            counter[7],
        ]),
        encrypted: packet.get(TRANSPORT_HEADER_LEN..).ok_or_else(too_short)?,
    })
}
