//! Brutal 拥塞器的配置与校验（fail-closed）。

/// 参考 `GetCongestionWindow()` 中 `rtt <= 0` 分支的缺省窗口：10 KiB。
pub const DEFAULT_INITIAL_WINDOW: u64 = 10 * 1024;

/// 最小合法带宽：1 字节/秒 = 8 比特/秒。
const MIN_BANDWIDTH_BPS: u64 = 8;

/// Brutal 拥塞器的配置。
///
/// `bandwidth` 为**比特/秒**；`initial_window` 为**字节**，`0` 表示采用参考
/// 缺省值 [`DEFAULT_INITIAL_WINDOW`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrutalConfig {
    /// 协商得到的发送速率（**比特/秒**）。
    pub bandwidth: u64,
    /// 初始拥塞窗口（字节）；`0` = 参考缺省 10240。
    pub initial_window: u64,
}

impl BrutalConfig {
    /// 构造配置并校验。零速率 / 非法速率 **fail-closed**（返回 `Err`）。
    pub fn new(bandwidth_bps: u64, initial_window: u64) -> Result<Self, ConfigError> {
        if bandwidth_bps == 0 {
            return Err(ConfigError::ZeroBandwidth);
        }
        if bandwidth_bps < MIN_BANDWIDTH_BPS {
            return Err(ConfigError::BandwidthTooLow {
                got: bandwidth_bps,
                min: MIN_BANDWIDTH_BPS,
            });
        }
        Ok(Self {
            bandwidth: bandwidth_bps,
            initial_window,
        })
    }

    /// 由**字节/秒**构造（本仓 `Bandwidth::bps()` 的单位）。
    ///
    /// 协商面 `negotiate_client_rate` / `negotiate_server_rate` 返回的是
    /// **字节/秒**（对齐参考 `Bandwidth.Bps()`），接线时用本构造器折算为
    /// 比特/秒。
    pub fn from_bytes_per_sec(
        bytes_per_sec: u64,
        initial_window: u64,
    ) -> Result<Self, ConfigError> {
        Self::new(bytes_per_sec.saturating_mul(8), initial_window)
    }

    /// 配置是否合法（工厂在 `build` 时复查，防止绕过 [`BrutalConfig::new`]）。
    pub fn is_valid(&self) -> bool {
        self.bandwidth >= MIN_BANDWIDTH_BPS
    }

    /// 折算后的字节/秒速率。
    pub fn bytes_per_sec(&self) -> u64 {
        self.bandwidth / 8
    }

    /// 生效的初始窗口（字节）。
    pub fn effective_initial_window(&self) -> u64 {
        if self.initial_window == 0 {
            DEFAULT_INITIAL_WINDOW
        } else {
            self.initial_window
        }
    }

    /// 由**协商结果**构造配置（字节/秒）。
    ///
    /// `negotiated` 即协议 crate 的 `negotiate_client_rate` /
    /// `negotiate_server_rate` 的返回值（**字节/秒**；`None` = 参考的回落
    /// 分支：`BrutalUp == 0 || clientDown == 0` ⇒ 回落 BBR）。
    ///
    /// # 参考的回落语义
    ///
    /// 参考 `hub.go` 行 194-200：
    /// ```text
    /// case "brutal", "":
    ///     if h.quicParams.BrutalUp == 0 || clientDown == 0 {
    ///         congestion.UseBBR(h.conn)      // 回落 BBR
    ///     } else {
    ///         congestion.UseBrutal(h.conn, min(BrutalUp, clientDown))
    ///     }
    /// ```
    /// 即**协商不出非零速率 ⇒ 不用 Brutal**。本函数忠实表达这一点：
    /// `None` 或 `Some(0)` 一律返回 `Err`（fail-closed），调用方据此
    /// **不注入** Brutal 拥塞器（沿用 quinn 默认 CUBIC），**不得**用
    /// `bandwidth = 0` 构造控制器。
    ///
    /// # 与参考的差异
    ///
    /// 参考回落目标是 BBR；本仓 **BBR 未移植**（见
    /// `docs/congestion-status.md` 的偏离清单），故接线时建议回落
    /// **CUBIC**（quinn 默认）并显式记录日志，**不要静默**。
    pub fn from_negotiated(
        negotiated: Option<u64>,
        initial_window: u64,
    ) -> Result<Self, ConfigError> {
        match negotiated {
            None => Err(ConfigError::NotNegotiated),
            Some(0) => Err(ConfigError::ZeroBandwidth),
            Some(bytes_per_sec) => Self::from_bytes_per_sec(bytes_per_sec, initial_window),
        }
    }
}

/// Brutal 配置校验失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// 速率为 0（未配置 / 非法）—— fail-closed。
    #[error("Brutal 速率为 0，非法（必须 > 0）")]
    ZeroBandwidth,

    /// 速率低于 1 字节/秒。
    #[error("Brutal 速率 {got} bps 过小（最小 {min} bps = 1 字节/秒）")]
    BandwidthTooLow { got: u64, min: u64 },

    /// 协商结果为 `None`（参考的回落分支：任一侧带宽为 0 ⇒ 不用 Brutal）。
    #[error("未协商出 Brutal 速率（对齐参考回落分支：不注入 Brutal 拥塞器）")]
    NotNegotiated,
}
