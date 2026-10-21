//! L4 协商消息的**载荷格式**与编解码。
//!
//! 协商消息**不走明文旁路**：它是 L3 密文帧的**明文载荷**，
//! 且必须封进 `FrameType::Control` 帧（见 [`decode_control`]）。
//!
//! # 载荷格式（定长头 40 字节 + 扩展块）
//!
//! 一律**大端（网络字节序）**：
//!
//! ```text
//! 偏移  宽度  字段            语义
//! 0     2    magic           0x4E47（"NG"）
//! 2     1    version         协议版本（当前 1）
//! 3     1    kind            消息类型（1=提案 2=应答）
//! 4     1    channel_mode    通道模式（1=p2p 2=relay）
//! 5     1    flags           保留位，必须为 0
//! 6     2    ext_len         扩展块字节数
//! 8     8    generation      世代号（u64）
//! 16    8    local_caps      本端能力位掩码（u64）
//! 24    8    effective_caps  生效能力位掩码（u64；提案里恒为 0）
//! 32    1    local_modes     本端支持的模式集（1 字节位掩码）
//! 33    1    common_modes    共同模式集（1 字节位掩码；提案里恒为 0）
//! 34    2    reserved        保留，必须为 0
//! 36    4    reserved2       保留，必须为 0
//! 40    ..   ext             扩展块（ext_len 字节）
//! ```
//!
//! 扩展块是 **TLV 序列**：`type(1) + len(1) + data(len)` 反复排列。
//! 未知 `type` ⇒ **忽略并记录**（单项 fail-open）；
//! TLV 结构非法（长度越界）⇒ **整个消息拒绝**（整体 fail-closed）。
//!
//! # 长度上限
//!
//! 协商载荷最终要封进 L3 密文帧 ⇒ 明文长度不得超过
//! [`crate::frame::MAX_PLAIN_LEN`]。超限 ⇒ [`NegotiateError::PayloadTooLarge`]，
//! **绝不截断**。
//!
//! # 为什么载荷里没有明文业务内容
//!
//! `relay` 模式下中继**只转发密文**。本格式只承载协商元数据
//! （模式 / 世代号 / 能力位 / 扩展），**不含任何 ACP 业务载荷**。

use crate::frame::{FrameType, MAX_PLAIN_LEN};
use crate::negotiate::capabilities::CapabilitySet;
use crate::negotiate::channel::{ChannelMode, ModeSet};
use crate::negotiate::error::NegotiateError;

/// 协商载荷魔数：`0x4E47`（ASCII "NG"）。
pub const NEGOTIATE_MAGIC: u16 = 0x4E47;

/// 协商载荷协议版本（当前 1）。
pub const NEGOTIATE_VERSION: u8 = 1;

/// 协商载荷**定长头**长度。
pub const NEGOTIATE_HEADER_LEN: usize = 40;

/// 扩展块里单个 TLV 的**最大**数据长度（1 字节长度字段 ⇒ ≤ 255）。
pub const MAX_EXTENSION_DATA_LEN: usize = u8::MAX as usize;

/// 协商消息类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// 提案：发起方 → 响应方（带请求的模式 + 本端能力集 + 世代号）。
    Proposal,
    /// 应答：响应方 → 发起方（带**选中**的模式 + 能力集**交集** + 世代号）。
    Response,
}

impl MessageKind {
    /// 线上字节值。
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Proposal => 0x01,
            Self::Response => 0x02,
        }
    }

    /// 由线上字节值还原；**未知值返回 `None`**。
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Proposal),
            0x02 => Some(Self::Response),
            _ => None,
        }
    }

    /// 稳定英文名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Response => "response",
        }
    }
}

/// 协商扩展项（TLV）。
///
/// 已知 `ext_type` 才有语义；未知类型被**忽略并记录**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationExtension {
    /// 扩展类型号。
    pub ext_type: u8,
    /// 扩展数据。
    pub data: Vec<u8>,
}

impl NegotiationExtension {
    /// 构造一个扩展项。
    #[must_use]
    pub const fn new(ext_type: u8, data: Vec<u8>) -> Self {
        Self { ext_type, data }
    }
}

/// 一条协商消息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationMessage {
    /// 消息类型。
    pub kind: MessageKind,
    /// 通道模式（提案里是**请求**的模式；应答里是**选中**的模式）。
    pub channel_mode: ChannelMode,
    /// 世代号（来自 L2 会话对象）。
    pub generation: u64,
    /// 本端能力位掩码。
    pub local_caps: CapabilitySet,
    /// 生效能力位掩码（**交集**）：提案里恒为空，应答里是交集。
    pub effective_caps: CapabilitySet,
    /// 本端支持的模式集。
    pub local_modes: ModeSet,
    /// 共同模式集（**交集**）：提案里恒为空，应答里是交集。
    pub common_modes: ModeSet,
    /// 扩展项。
    pub extensions: Vec<NegotiationExtension>,
}

impl NegotiationMessage {
    /// 构造一条提案。
    #[must_use]
    pub const fn proposal(
        channel_mode: ChannelMode,
        generation: u64,
        local_caps: CapabilitySet,
        local_modes: ModeSet,
    ) -> Self {
        Self {
            kind: MessageKind::Proposal,
            channel_mode,
            generation,
            local_caps,
            effective_caps: CapabilitySet::empty(),
            local_modes,
            common_modes: ModeSet::empty(),
            extensions: Vec::new(),
        }
    }

    /// 构造一条应答。
    #[must_use]
    pub const fn response(
        channel_mode: ChannelMode,
        generation: u64,
        local_caps: CapabilitySet,
        effective_caps: CapabilitySet,
        local_modes: ModeSet,
        common_modes: ModeSet,
    ) -> Self {
        Self {
            kind: MessageKind::Response,
            channel_mode,
            generation,
            local_caps,
            effective_caps,
            local_modes,
            common_modes,
            extensions: Vec::new(),
        }
    }

    /// 编码成线上字节（定长头 40 字节 + 扩展块）。
    ///
    /// # Errors
    /// 扩展项数据超过 255 字节，或编码后总长超过
    /// [`crate::frame::MAX_PLAIN_LEN`] ⇒
    /// [`NegotiateError::PayloadTooLarge`]（**不截断**）。
    pub fn encode(&self) -> Result<Vec<u8>, NegotiateError> {
        let mut ext = Vec::new();
        for extension in &self.extensions {
            if extension.data.len() > MAX_EXTENSION_DATA_LEN {
                return Err(NegotiateError::payload_too_large(
                    extension.data.len(),
                    MAX_EXTENSION_DATA_LEN,
                ));
            }
            ext.push(extension.ext_type);
            ext.push(extension.data.len() as u8);
            ext.extend_from_slice(&extension.data);
        }
        if ext.len() > u16::MAX as usize {
            return Err(NegotiateError::payload_too_large(
                ext.len(),
                u16::MAX as usize,
            ));
        }
        let total = NEGOTIATE_HEADER_LEN + ext.len();
        if total > MAX_PLAIN_LEN {
            return Err(NegotiateError::payload_too_large(total, MAX_PLAIN_LEN));
        }

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&NEGOTIATE_MAGIC.to_be_bytes());
        out.push(NEGOTIATE_VERSION);
        out.push(self.kind.to_u8());
        out.push(self.channel_mode.to_u8());
        out.push(0); // flags：保留，当前必须为 0
        out.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.local_caps.to_bytes());
        out.extend_from_slice(&self.effective_caps.to_bytes());
        out.push(self.local_modes.bits());
        out.push(self.common_modes.bits());
        out.extend_from_slice(&[0u8; 2]); // reserved
        out.extend_from_slice(&[0u8; 4]); // reserved2
        out.extend_from_slice(&ext);
        Ok(out)
    }

    /// 解码一条协商消息。
    ///
    /// # Errors
    /// 长度不足、魔数不符、版本不符、类型/模式未知、保留位非零、
    /// 扩展块长度越界 ⇒ 明确的 [`NegotiateError`]（**不返回部分消息**）。
    pub fn decode(buf: &[u8]) -> Result<Self, NegotiateError> {
        if buf.len() < NEGOTIATE_HEADER_LEN {
            return Err(NegotiateError::malformed("载荷不足一个协商头"));
        }
        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != NEGOTIATE_MAGIC {
            return Err(NegotiateError::malformed("协商魔数不匹配"));
        }
        let version = buf[2];
        if version != NEGOTIATE_VERSION {
            return Err(NegotiateError::UnsupportedVersion {
                expected: NEGOTIATE_VERSION,
                got: version,
            });
        }
        let Some(kind) = MessageKind::from_u8(buf[3]) else {
            return Err(NegotiateError::malformed("未知协商消息类型"));
        };
        let Some(channel_mode) = ChannelMode::from_u8(buf[4]) else {
            return Err(NegotiateError::malformed("未知通道模式"));
        };
        if buf[5] != 0 {
            return Err(NegotiateError::malformed("保留位非零"));
        }
        let ext_len = usize::from(u16::from_be_bytes([buf[6], buf[7]]));
        if buf.len() != NEGOTIATE_HEADER_LEN + ext_len {
            return Err(NegotiateError::malformed("扩展块长度与实际不符"));
        }
        if buf[34] != 0 || buf[35] != 0 {
            return Err(NegotiateError::malformed("保留位非零"));
        }
        if buf[36] != 0 || buf[37] != 0 || buf[38] != 0 || buf[39] != 0 {
            return Err(NegotiateError::malformed("保留位非零"));
        }
        let generation = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let local_caps = CapabilitySet::from_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]);
        let effective_caps = CapabilitySet::from_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        let local_modes = ModeSet::from_bytes([buf[32]]);
        let common_modes = ModeSet::from_bytes([buf[33]]);

        let mut extensions = Vec::new();
        let mut cursor = NEGOTIATE_HEADER_LEN;
        let end = NEGOTIATE_HEADER_LEN + ext_len;
        while cursor < end {
            if cursor + 2 > end {
                return Err(NegotiateError::malformed("扩展块 TLV 头被截断"));
            }
            let ext_type = buf[cursor];
            let data_len = usize::from(buf[cursor + 1]);
            cursor += 2;
            if cursor + data_len > end {
                return Err(NegotiateError::malformed("扩展块 TLV 数据越界"));
            }
            extensions.push(NegotiationExtension::new(
                ext_type,
                buf[cursor..cursor + data_len].to_vec(),
            ));
            cursor += data_len;
        }

        Ok(Self {
            kind,
            channel_mode,
            generation,
            local_caps,
            effective_caps,
            local_modes,
            common_modes,
            extensions,
        })
    }
}

/// 从**控制帧**里解出一条协商消息。
///
/// 协商**只允许**走 `FrameType::Control`：
/// 走数据帧 ⇒ [`NegotiateError::WrongFrameType`]（fail-closed，
/// ⛔ 不接受「明文旁路」）。
///
/// # Errors
/// - 帧类型不是 `Control` ⇒ `NegotiateError::WrongFrameType`。
/// - 载荷不是合法协商消息 ⇒ `NegotiateError::MalformedMessage` / `UnsupportedVersion`。
/// - 载荷超长 ⇒ `NegotiateError::PayloadTooLarge`。
pub fn decode_control(
    frame_type: FrameType,
    plaintext: &[u8],
) -> Result<NegotiationMessage, NegotiateError> {
    if frame_type != FrameType::Control {
        return Err(NegotiateError::WrongFrameType {
            got: match frame_type {
                FrameType::Data => "data",
                FrameType::Keepalive => "keepalive",
                FrameType::Control => "control",
            },
        });
    }
    if plaintext.len() > MAX_PLAIN_LEN {
        return Err(NegotiateError::payload_too_large(
            plaintext.len(),
            MAX_PLAIN_LEN,
        ));
    }
    NegotiationMessage::decode(plaintext)
}
