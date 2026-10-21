//! L2 会话的**状态 / 角色 / 世代号**类型。
//!
//! 这三个类型是本卡对外的「会话语义」入口：
//! - [`SessionRole`]：本端在这次会话里是发起方还是响应方（**跨端不对称**：
//!   PC 端固定当响应方、移动端固定当发起方，见 `docs/link-session-spec.md`）。
//! - [`SessionState`]：会话状态机的四个状态（未握手 / 握手中 / 已建立 / 已失效）。
//! - [`Generation`]：连接世代号（单调计数器），供 L4 区分「旧连接的迟到包」。
//!
//! 这里**没有**密钥材料，因此三个类型都可以安全地 `Debug` / 序列化。

/// 会话角色。
///
/// 角色在**一次会话内固定**：要么由本端发 initiation，要么由本端回 response。
/// 跨端部署时两端角色不对称（一方固定 initiator、另一方固定 responder），
/// 但**本卡不强制**「哪一端必须是 initiator」——两种组合都合法，
/// 由部署方在注入会话材料时决定（见 `docs/link-session-spec.md` §4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionRole {
    /// 发起方：先产出 initiation，消费 response。
    Initiator,
    /// 响应方：先消费 initiation，产出 response。
    Responder,
}

impl SessionRole {
    /// 是否是发起方。
    #[must_use]
    pub const fn is_initiator(self) -> bool {
        matches!(self, Self::Initiator)
    }

    /// 是否是响应方。
    #[must_use]
    pub const fn is_responder(self) -> bool {
        matches!(self, Self::Responder)
    }

    /// 稳定的英文名（用于错误文本与日志，不含任何机密）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

/// 会话状态机的状态。
///
/// ```text
///                    start_initiation / accept_initiation
///        Unhandshaked ─────────────────────────────────▶ Handshaking
///             │                                            │
///             │                                  complete_* │ (握手成功)
///             │                                            ▼
///             │              start_initiation / accept_initiation
///             │            ┌─────────────────────── Established
///             │            │                              │
///             ▼            ▼                              │
///        Invalidated ◀────────────────────────────────────┘
///             ▲        （认证失败 / 显式失效）
/// ```
///
/// `Invalidated` 表示**当前传输上下文已作废**（AEAD 认证失败、显式
/// [`crate::session::Session::invalidate`] 等）。此时收发一律被拒绝，
/// 但**允许**再开一轮握手（重连）——重连成功后世代号继续递增。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// 未握手：还没有任何传输上下文。
    Unhandshaked,
    /// 握手中：已产出/已消费握手报文，传输上下文尚未落地。
    Handshaking,
    /// 已建立：传输密钥与收发上下文就绪，可以收发密文帧。
    Established,
    /// 已失效：当前会话作废，拒绝收发（可重连）。
    Invalidated,
}

impl SessionState {
    /// 是否已建立（可收发）。
    #[must_use]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }

    /// 是否已失效。
    #[must_use]
    pub const fn is_invalidated(self) -> bool {
        matches!(self, Self::Invalidated)
    }

    /// 稳定的英文名（用于错误文本与日志）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unhandshaked => "unhandshaked",
            Self::Handshaking => "handshaking",
            Self::Established => "established",
            Self::Invalidated => "invalidated",
        }
    }
}

/// 连接世代号：每次**握手成功**就 +1 的单调计数器。
///
/// 语义：
/// - 初始值 [`Generation::INITIAL`]（= 0）表示「还没有任何成功会话」；
/// - 第一次握手成功 ⇒ 世代号 = 1；此后每成功一轮 ⇒ +1；
/// - 世代号**只在握手成功时前进**，失败的握手不消耗号段。
///
/// ⚠️ 世代号是**本端局部**的计数器：两端各自按「成功建立的轮次」递增，
/// 因此只要两端成功次数相同，世代号就相同；成功次数不同步时（对端重连、
/// 本端未察觉）由 L4 负责对齐（`docs/link-session-spec.md` §5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Generation(u64);

impl Generation {
    /// 初始世代号（尚未建立任何会话）。
    pub const INITIAL: Self = Self(0);

    /// 世代号数值。
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// 下一个世代号（`u64::MAX` 时饱和在 `u64::MAX`，绝不回绕）。
    #[must_use]
    pub const fn next(self) -> Self {
        match self.0.checked_add(1) {
            Some(value) => Self(value),
            None => Self(u64::MAX),
        }
    }
}
