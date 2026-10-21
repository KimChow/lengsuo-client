//! L4 通道模式：`p2p`（直连）与 `relay`（经协调面中继）。
//!
//! # 语义
//!
//! | 模式 | 前提 | 失败条件 | 错误码 |
//! |---|---|---|---|
//! | `p2p` | 双方都声明支持 `p2p`（模式集交集含 `p2p`），且 L1 打洞/直连成功 | 模式集交集不含 `p2p`；或 L1 直连失败 | `NO_COMMON_CHANNEL_MODE` / `CHANNEL_MODE_NOT_ACCEPTED` |
//! | `relay` | 双方都声明支持 `relay`（模式集交集含 `relay`） | 模式集交集不含 `relay` | `NO_COMMON_CHANNEL_MODE` |
//!
//! # `relay` 的「只转密文」纪律
//!
//! 协调面中继**只转发密文**（规划稿 §线F）：它看到的是 L3 密文帧，
//! 看不到 ACP 明文。⇒ **协商消息里绝不能出现明文业务内容**——
//! 本卡的协商载荷只含：消息类型、通道模式、世代号、能力位掩码、扩展块。
//! 中继即便能解开协商载荷（它有会话密钥的话），也**只应**看到这些元数据。
//!
//! # 模式选择规则（**绝无「默认直连」**）
//!
//! - 发起方**显式**请求一个模式（`p2p` 或 `relay`）；
//! - 响应方在**双方共同支持**的模式里选一个：**优先满足请求**；
//!   请求的模式不被响应方支持时，**只有当交集里存在另一种模式**才回退，
//!   并在应答里**显式**写明选中的模式；
//! - 交集为空 ⇒ **明确错误** `NO_COMMON_CHANNEL_MODE`，
//!   ⛔ **绝不**回退到 `p2p`（那会在 NAT 后面静默失败）。
//!
//! 选中的模式**必须**落在模式集交集里 ⇒ 由此天然保证
//! 「选中的模式 ⇒ 双方都支持它」。
//!
//! # 模式集与能力集是**两条轴**
//!
//! 模式集（[`ModeSet`]）是 2 位的**小掩码**（位 0 = `p2p`，位 1 = `relay`），
//! 与 [`crate::negotiate::CapabilitySet`]（`u64` 可选特性位）**分开**。
//! 理由见 `capabilities.rs` 的模块文档。

use crate::negotiate::error::NegotiateError;

/// 通道模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelMode {
    /// `p2p`：端到端直连（L1 打洞成功后使用）。
    P2p,
    /// `relay`：经协调面中继（**只转密文**）。
    Relay,
}

impl ChannelMode {
    /// 线上字节值（**稳定**，跨端对齐用）。
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::P2p => 0x01,
            Self::Relay => 0x02,
        }
    }

    /// 由线上字节值还原；**未知值返回 `None`**（调用方据此 fail-closed 拒绝）。
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::P2p),
            0x02 => Some(Self::Relay),
            _ => None,
        }
    }

    /// 稳定英文名（不用 `Debug` 文本当码）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P2p => "p2p",
            Self::Relay => "relay",
        }
    }

    /// 该模式在**模式集**里的位号。
    #[must_use]
    pub const fn bit_index(self) -> u8 {
        match self {
            Self::P2p => 0,
            Self::Relay => 1,
        }
    }

    /// 该模式对应的位掩码。
    #[must_use]
    pub const fn bit(self) -> u8 {
        1u8 << self.bit_index()
    }

    /// 全部已知模式（按选择优先级排列：`p2p` 在前）。
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::P2p, Self::Relay]
    }
}

impl core::fmt::Display for ChannelMode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// 通道**模式集**（2 位小掩码）。
///
/// 位 0 = `p2p`，位 1 = `relay`。线上是 **1 字节**。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ModeSet {
    bits: u8,
}

impl ModeSet {
    /// 空模式集。
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// 由原始位掩码构造（**只认低 2 位**，其余位被忽略）。
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self {
            bits: bits & 0b0000_0011,
        }
    }

    /// 原始位掩码（只含低 2 位）。
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// 是否为空（没有任何共同模式）。
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// 是否含某个模式。
    #[must_use]
    pub const fn contains(self, mode: ChannelMode) -> bool {
        self.bits & mode.bit() != 0
    }

    /// 加入一个模式。
    #[must_use]
    pub const fn with(self, mode: ChannelMode) -> Self {
        Self {
            bits: self.bits | mode.bit(),
        }
    }

    /// 交集（**按位与**）。
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// 并集（**仅供对照与诊断**）。
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// 本集合支持的模式（按选择优先级排列：`p2p` 在前）。
    pub fn iter(self) -> impl Iterator<Item = ChannelMode> {
        ChannelMode::all()
            .into_iter()
            .filter(move |mode| self.contains(*mode))
    }

    /// 线上表示：1 字节。
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 1] {
        [self.bits]
    }

    /// 由 1 字节还原。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 1]) -> Self {
        Self::from_bits(bytes[0])
    }
}

impl core::fmt::Debug for ModeSet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<&str> = self.iter().map(|mode| mode.as_str()).collect();
        formatter
            .debug_struct("ModeSet")
            .field("bits", &format_args!("{:#04x}", self.bits))
            .field("modes", &names)
            .finish()
    }
}

/// 在**模式集交集**里挑一个通道模式。
///
/// 规则（见模块文档）：
/// 1. 交集里含请求的模式 ⇒ 选它；
/// 2. 否则按 `ChannelMode::all()` 的顺序挑**交集里第一个**可用的模式
///    （**显式回退**，不是「默认直连」——回退目标必须落在交集里）；
/// 3. 交集为空 ⇒ **明确错误** `NO_COMMON_CHANNEL_MODE`。
///
/// # Errors
/// 交集为空 ⇒ `NegotiateError::NoCommonChannelMode`。
pub fn select_channel_mode(
    common: ModeSet,
    requested: ChannelMode,
) -> Result<ChannelMode, NegotiateError> {
    if common.is_empty() {
        return Err(NegotiateError::NoCommonChannelMode {
            requested: requested.as_str(),
        });
    }
    if common.contains(requested) {
        return Ok(requested);
    }
    for mode in ChannelMode::all() {
        if common.contains(mode) {
            return Ok(mode);
        }
    }
    Err(NegotiateError::NoCommonChannelMode {
        requested: requested.as_str(),
    })
}
