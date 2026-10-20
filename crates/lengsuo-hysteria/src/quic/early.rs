//! QUIC 0-RTT（早数据）与会话恢复。
//!
//! 参考实现：Xray `transport/internet/hysteria/dialer.go` 用
//! `quic.DialEarly(ctx, pktConn, remote, tlsCfg, cfg)` 发起连接，认证请求
//! 作为早数据随首次飞行发出。本仓用 quinn 的
//! [`quinn::Connection::into_0rtt`]（`connection.rs:126`）对齐该路径：
//!
//! - 客户端只有在 rustls `ClientConfig::enable_early_data = true` 且
//!   `resumption` 能命中上一次会话票据时，`into_0rtt` 才返回 `Ok`；
//! - 握手完成时 [`quinn::ZeroRttAccepted`] 解析为 `true`（服务端接受）
//!   或 `false`（拒绝）。被拒时，握手前打开/写入的流与数据**不会**到达
//!   对端，本地读写返回 `ZeroRttRejected` 类错误。
//!
//! # 安全铁律
//!
//! 0-RTT 数据可被重放。因此：
//! 1. 只有**幂等**操作可以走早数据（[`OperationKind::Idempotent`]）；
//!    非幂等操作在 [`run_early`] 中直接 fail-closed 拒绝，绝不发送。
//! 2. 0-RTT 被拒必须可观测：结果以 [`ZeroRttOutcome`] /
//!    [`ZeroRttStatus`] 暴露，**不得**静默按 1-RTT 成功处理。
//! 3. 被拒后的重放必须由调用方通过显式 `fallback` 闭包发起；
//!    早数据本身已被传输层丢弃，不会二次交付。
//!
//! 本模块不改变 `EarlyDataConfig::default()`（`enabled = false`）下的任何
//! 既有行为；关闭时 [`configure_tls`] 不触碰 rustls 配置。会话票据存储与
//! rustls 接线在 `cache` 子模块。
//!
//! # 与参考的实现性差异
//!
//! quinn 客户端不暴露「单个连接可发送的早数据字节上限」；`max_early_data`
//! 因此作为本仓自设的应用层预算（[`EarlyBudget`]），而非线上传输参数。
//! quinn 也没有 `quic.DialEarly` 的等价单函数：本仓先 `Endpoint::connect`
//! 再 `into_0rtt()`，语义相同（`Err` 即退回普通 1-RTT 握手）。

use std::fmt;

use tokio::sync::watch;

mod cache;
pub use cache::{configure_tls, EarlyDataError, MemorySessionCache, SessionCache};

/// 0-RTT 配置。默认关闭，不改变既有 1-RTT 行为。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyDataConfig {
    /// 是否尝试 0-RTT（只有会话恢复命中时才可能真正发出早数据）。
    pub enabled: bool,
    /// 本端自设的早数据字节预算；`None` 表示不限制。
    /// quinn/rustls 客户端不暴露连接级早数据上限，故这不是传输参数。
    pub max_early_data: Option<usize>,
    /// 会话票据缓存容量（服务端名数量），默认 256（与 rustls 内置缓存一致）。
    pub resumption_capacity: usize,
}

impl Default for EarlyDataConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_early_data: None,
            resumption_capacity: 256,
        }
    }
}

/// 0-RTT 被服务端拒绝。早数据未送达对端，连接本身可继续用于 1-RTT。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroRttRejected;

impl fmt::Display for ZeroRttRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0-RTT 被服务端拒绝：早数据未送达对端，必须显式回退 1-RTT")
    }
}

impl std::error::Error for ZeroRttRejected {}

/// 一次 0-RTT 尝试的结果。拒绝路径必须被调用方观测，不得静默忽略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroRttOutcome {
    /// 服务端接受早数据（`ZeroRttAccepted` 解析为 true）。
    Accepted,
    /// 服务端拒绝早数据；早数据被丢弃，调用方须显式走 1-RTT 重放。
    Rejected(ZeroRttRejected),
    /// 未尝试 0-RTT（配置关闭，或本端无可用票据导致 `into_0rtt` 返回 `Err`）。
    NotAttempted,
}

impl ZeroRttOutcome {
    /// 把「是否尝试 + 握手结果」映射为三态。未尝试时结果恒为 `NotAttempted`。
    #[must_use]
    pub fn from_handshake(attempted: bool, accepted: bool) -> Self {
        if !attempted {
            Self::NotAttempted
        } else if accepted {
            Self::Accepted
        } else {
            Self::Rejected(ZeroRttRejected)
        }
    }

    /// 是否被拒绝（供调用方 fail-closed 分支使用）。
    #[must_use]
    pub fn is_rejected(self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

const STATUS_NOT_ATTEMPTED: u8 = 0;
const STATUS_PENDING: u8 = 1;
const STATUS_ACCEPTED: u8 = 2;
const STATUS_REJECTED: u8 = 3;

/// 可克隆的 0-RTT 状态观察器。握手完成前为 pending；完成后
/// [`ZeroRttStatus::wait`] 返回 [`ZeroRttOutcome`]。
#[derive(Debug, Clone)]
pub struct ZeroRttStatus {
    tx: watch::Sender<u8>,
}

impl ZeroRttStatus {
    /// 未尝试 0-RTT（配置关闭，或 `into_0rtt` 返回 `Err`）。
    #[must_use]
    pub fn not_attempted() -> Self {
        Self {
            tx: watch::channel(STATUS_NOT_ATTEMPTED).0,
        }
    }

    /// 已发起 0-RTT，等待握手结果。
    #[must_use]
    pub fn attempted() -> Self {
        Self {
            tx: watch::channel(STATUS_PENDING).0,
        }
    }

    /// 记录握手结果（幂等；只有第一次记录生效）。
    pub fn record(&self, accepted: bool) {
        let value = if accepted {
            STATUS_ACCEPTED
        } else {
            STATUS_REJECTED
        };
        let _ = self.tx.send_if_modified(|cur| {
            if *cur == STATUS_PENDING {
                *cur = value;
                true
            } else {
                false
            }
        });
    }

    /// 当前结果；握手尚未完成时返回 `None`。
    #[must_use]
    pub fn current(&self) -> Option<ZeroRttOutcome> {
        match *self.tx.borrow() {
            STATUS_NOT_ATTEMPTED => Some(ZeroRttOutcome::NotAttempted),
            STATUS_ACCEPTED => Some(ZeroRttOutcome::Accepted),
            STATUS_REJECTED => Some(ZeroRttOutcome::Rejected(ZeroRttRejected)),
            _ => None,
        }
    }

    /// 等待握手完成并返回最终结果（未尝试时立即返回）。
    pub async fn wait(&self) -> ZeroRttOutcome {
        let mut rx = self.tx.subscribe();
        loop {
            match *rx.borrow_and_update() {
                STATUS_NOT_ATTEMPTED => return ZeroRttOutcome::NotAttempted,
                STATUS_ACCEPTED => return ZeroRttOutcome::Accepted,
                STATUS_REJECTED => return ZeroRttOutcome::Rejected(ZeroRttRejected),
                _ => {}
            }
            if rx.changed().await.is_err() {
                // 观察器被丢弃前不会发生；保持 fail-closed 口径。
                return ZeroRttOutcome::Rejected(ZeroRttRejected);
            }
        }
    }
}

/// 操作幂等性分类。0-RTT 路径只接受 `Idempotent`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// 可安全重放（例如无副作用的查询/认证）。
    Idempotent,
    /// 不可重放（例如写入/扣款）。0-RTT 路径 fail-closed。
    NonIdempotent,
}

/// [`run_early`] 的错误。
#[derive(Debug, PartialEq, Eq)]
pub enum EarlyError<E> {
    /// 未尝试 0-RTT；不会发生（该分支走 fallback 并返回成功）。
    NotAttempted,
    /// 非幂等操作被拒绝，早数据未发送。
    NonIdempotent,
    /// 早数据被服务端拒绝（早数据丢弃，调用方应已显式重放）。
    Rejected(ZeroRttRejected),
    /// 操作自身失败。
    Operation(E),
}

impl<E: fmt::Display> fmt::Display for EarlyError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAttempted => f.write_str("未尝试 0-RTT"),
            Self::NonIdempotent => f.write_str("非幂等操作禁止走 0-RTT（fail-closed）"),
            Self::Rejected(e) => e.fmt(f),
            Self::Operation(e) => write!(f, "早数据操作失败: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for EarlyError<E> {}

/// 显式的「早数据 + 被拒后重放」入口。
///
/// - `kind == NonIdempotent`：直接返回 [`EarlyError::NonIdempotent`]，
///   **不调用** `early` 或 `fallback`（非幂等操作绝不进入 0-RTT 路径）。
/// - `early == None`：走 `fallback`，结果为 `NotAttempted`。
/// - `early` 存在：先执行一次早数据操作（对应握手完成前已发出的字节），
///   再按 `accepted` 结算：
///   - `true`：返回早数据结果，不重放；
///   - `false`：早结果被传输层丢弃，调用方提供的 `fallback` 在 1-RTT 上
///     执行**一次**。这不构成重复交付：早数据从未到达对端。
#[allow(clippy::result_large_err)]
pub fn run_early<T, E>(
    kind: OperationKind,
    early: Option<impl FnOnce() -> Result<T, E>>,
    fallback: impl FnOnce() -> Result<T, E>,
    accepted: bool,
) -> Result<(T, ZeroRttOutcome), EarlyError<E>> {
    if kind == OperationKind::NonIdempotent {
        return Err(EarlyError::NonIdempotent);
    }
    match (early.map(|op| op()), accepted) {
        (None, _) => fallback()
            .map(|v| (v, ZeroRttOutcome::NotAttempted))
            .map_err(EarlyError::Operation),
        (Some(Ok(v)), true) => Ok((v, ZeroRttOutcome::Accepted)),
        (Some(Err(e)), true) => Err(EarlyError::Operation(e)),
        (Some(_), false) => fallback()
            .map(|v| (v, ZeroRttOutcome::Rejected(ZeroRttRejected)))
            .map_err(EarlyError::Operation),
    }
}

/// 早数据发送预算（应用层自设；见模块文档中的偏离说明）。
#[derive(Debug, Clone)]
pub struct EarlyBudget {
    remaining: Option<usize>,
}

impl EarlyBudget {
    /// 由 [`EarlyDataConfig::max_early_data`] 构造。
    #[must_use]
    pub fn new(max_early_data: Option<usize>) -> Self {
        Self {
            remaining: max_early_data,
        }
    }

    /// 扣减预算；超限 fail-closed，调用方不得退回 0-RTT 发送。
    pub fn charge(&mut self, len: usize) -> Result<(), EarlyBudgetExceeded> {
        match self.remaining {
            None => Ok(()),
            Some(remaining) if len <= remaining => {
                self.remaining = Some(remaining - len);
                Ok(())
            }
            Some(remaining) => Err(EarlyBudgetExceeded { len, remaining }),
        }
    }
}

/// 早数据超过自设预算。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("早数据 {len} 字节超过剩余预算 {remaining} 字节")]
pub struct EarlyBudgetExceeded {
    /// 本次尝试发送的字节数。
    pub len: usize,
    /// 剩余预算。
    pub remaining: usize,
}
