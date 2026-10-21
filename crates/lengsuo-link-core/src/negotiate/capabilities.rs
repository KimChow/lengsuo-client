//! L4 能力集：能力位定义、位集合运算与**交集**规则。
//!
//! # 能力集 ≠ 通道模式
//!
//! 本卡把两件事**分开**：
//!
//! | 轴 | 类型 | 回答的问题 | 交集为空的后果 |
//! |---|---|---|---|
//! | **通道模式** | [`crate::negotiate::ModeSet`]（2 位） | 「这条链路走 `p2p` 还是 `relay`？」 | **协商失败**（`NO_COMMON_CHANNEL_MODE`） |
//! | **能力集** | [`CapabilitySet`]（`u64` 位掩码） | 「双方共同支持哪些可选特性？」 | 只表示「没有共同特性」，**协商仍可成功** |
//!
//! 为什么不合并：通道模式是**互斥的二选一**（一次协商只能有一种），
//! 而能力位是**可叠加的开关集合**。混在一个掩码里会导致
//! 「能力集有交集 ⇒ 必然有共同模式」这种并不成立的推断。
//!
//! # 为什么是位掩码
//!
//! 能力集要**跨端一致**（移动端与桌面端对同一组位有同一理解），
//! 所以格式必须**稳定**：本卡用 **u64 位掩码**，位号见 [`Capability`]。
//! 位掩码的好处是**天然可扩展**：新端多出几位时，旧端看到的是「自己不认识的位」，
//! 可以**忽略并记录**（见 [`CapabilitySet::unknown_bits`]），而不是拒掉整个协商。
//!
//! # 交集规则（逐字节说明）
//!
//! 能力集是 **u64 大端序** 线上表示（8 字节）。
//! 有效能力 = `本端位集 & 对端位集`（**按位与**）——
//! ⛔ **不是**并集（`|`）：只有**双方都支持**的能力才可用。
//!
//! ```text
//!   线上 8 字节（大端）：  b0 b1 b2 b3 b4 b5 b6 b7
//!   有效位 = b0[i] & b1[i]   （逐位与，i = 0..63）
//! ```
//!
//! 一句话：**每个字节分别做按位与**。因为位掩码的 8 个字节在数值上是一个
//! 整体 `u64`，按位与的结果**在数值上等价于**「先把两端都转成 `u64` 再 `&`」，
//! 但实现上按字节做更直白（也让「逐字节」在代码里可验证）。
//!
//! # 未知位纪律
//!
//! - **单项 fail-open**：未知位**不参与**交集结果，也**不导致**协商失败；
//! - **整体 fail-closed**：通道模式无交集 ⇒ 协商失败（明确错误码），
//!   **不**回退默认模式；
//! - 未知位**被记录**（[`CapabilitySet::unknown_bits`]），供跨版本排查。

/// 能力位定义（**可选特性**开关）。
///
/// ⚠️ **位号一旦发布就不再改动**（只增不改），否则新旧端对同一组位会
/// 有不同理解 ⇒ 交集算错 ⇒ 静默的能力错配。
///
/// 完整表见 `docs/link-negotiate-spec.md` §4。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// 位 0：支持 keepalive 保活帧。
    Keepalive,
    /// 位 1：支持在**已协商完成的通道**上继续协商（重协商 / 模式切换）。
    Renegotiate,
    /// 位 2：中继**只转发密文**（不得看到明文业务内容）。
    CiphertextOnlyRelay,
    /// 位 3：支持**双向**流式业务（不只是请求/响应）。
    StreamBothDirections,
}

impl Capability {
    /// 该能力的位号（0..=63）。
    #[must_use]
    pub const fn bit_index(self) -> u8 {
        match self {
            Self::Keepalive => 0,
            Self::Renegotiate => 1,
            Self::CiphertextOnlyRelay => 2,
            Self::StreamBothDirections => 3,
        }
    }

    /// 该能力对应的位掩码（`1 << bit_index`）。
    #[must_use]
    pub const fn bit(self) -> u64 {
        1u64 << self.bit_index()
    }

    /// 稳定英文名（用于日志与跨端对齐，**不用 `Debug` 文本**）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keepalive => "keepalive",
            Self::Renegotiate => "renegotiate",
            Self::CiphertextOnlyRelay => "ciphertext_only_relay",
            Self::StreamBothDirections => "stream_both_directions",
        }
    }

    /// 由位号还原能力位；**未知位号返回 `None`**（调用方据此忽略并记录）。
    #[must_use]
    pub const fn from_bit_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Keepalive),
            1 => Some(Self::Renegotiate),
            2 => Some(Self::CiphertextOnlyRelay),
            3 => Some(Self::StreamBothDirections),
            _ => None,
        }
    }

    /// 本实现**认识**的全部能力位（掩码形式）。
    #[must_use]
    pub const fn known_mask() -> u64 {
        Self::Keepalive.bit()
            | Self::Renegotiate.bit()
            | Self::CiphertextOnlyRelay.bit()
            | Self::StreamBothDirections.bit()
    }
}

/// 能力位集合。
///
/// 内部就是一个 `u64` 位掩码。`Debug` 输出位掩码与**能力名列表**
/// （未知位只报数量，不报位号——位号本身不是机密，但保持输出紧凑）。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CapabilitySet {
    bits: u64,
}

impl CapabilitySet {
    /// 空集合。
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// 由原始位掩码构造（**不校验**是否含未知位）。
    ///
    /// 含未知位是**允许**的：未知位会被忽略并记录，而不是拒掉协商。
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// 原始位掩码。
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// 是否为空。
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// 是否含某个能力。
    #[must_use]
    pub const fn contains(self, capability: Capability) -> bool {
        self.bits & capability.bit() != 0
    }

    /// 加入一个能力。
    #[must_use]
    pub const fn with(self, capability: Capability) -> Self {
        Self {
            bits: self.bits | capability.bit(),
        }
    }

    /// 移除一个能力。
    #[must_use]
    pub const fn without(self, capability: Capability) -> Self {
        Self {
            bits: self.bits & !capability.bit(),
        }
    }

    /// 交集（**按位与**）：双方都支持的能力。
    ///
    /// ⛔ 这是协商结果的**唯一**来源：**不是并集**。
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// 并集（**仅供对照与诊断**，⛔ **不是**协商结果的来源）。
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// 本集合里**本实现不认识**的位（未知位）。
    ///
    /// 这些位在交集计算里**被忽略**（即：不进入对外的有效能力集），
    /// 但会被**记录**下来供跨版本排查。
    #[must_use]
    pub const fn unknown_bits(self) -> u64 {
        self.bits & !Capability::known_mask()
    }

    /// 掩掉所有未知位后的集合。
    #[must_use]
    pub const fn known_only(self) -> Self {
        Self {
            bits: self.bits & Capability::known_mask(),
        }
    }

    /// 本集合认识的能力位数量。
    #[must_use]
    pub const fn known_count(self) -> u32 {
        (self.bits & Capability::known_mask()).count_ones()
    }

    /// 列出本集合**认识**的能力位（按位号升序）。
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        let bits = self.bits & Capability::known_mask();
        (0u8..64).filter_map(move |index| {
            if bits & (1u64 << index) == 0 {
                return None;
            }
            Capability::from_bit_index(index)
        })
    }

    /// 线上表示：8 字节**大端** `u64`。
    ///
    /// 8 字节恰好放进一个 UDP 数据报的剩余空间，也便于逐字节比对
    /// （跨端测试向量卡按此格式做字节级对拍）。
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        self.bits.to_be_bytes()
    }

    /// 从 8 字节**大端** `u64` 还原。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            bits: u64::from_be_bytes(bytes),
        }
    }
}

impl core::fmt::Debug for CapabilitySet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: Vec<&str> = self.iter().map(|c| c.as_str()).collect();
        formatter
            .debug_struct("CapabilitySet")
            .field("bits", &format_args!("{:#018x}", self.bits))
            .field("known", &names)
            .field("unknown_bit_count", &self.unknown_bits().count_ones())
            .finish()
    }
}
