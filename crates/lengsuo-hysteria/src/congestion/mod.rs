//! Brutal 拥塞控制的**参数面与协商面**（对齐 Xray `proxy/hysteria/` 与
//! `transport/internet/hysteria/{config,hub,dialer}.go`、
//! `infra/conf/transport_internet.go`）。
//!
//! # 本层做什么
//! - `Bandwidth` 解析/校验（单位、上下界、缺省 `0` 语义）；
//! - `Hysteria-CC-RX` / `Hysteria-CC-TX` 头编解码（与参考逐字节对齐）；
//! - `CongestionConfig` 的 fail-closed 校验（未识别 mode 一律拒绝）；
//! - 协商结果推导（`negotiate_*`），复刻参考 `switch congestion` 分支。
//!
//! # 本层**不**做什么（必须如实声明）
//! **它不改变 QUIC 拥塞器实现。** 拥塞器内核见 `lengsuo-congestion`
//! （quinn `Controller` / `ControllerFactory`）；本层只承载**参数 + 协商**，
//! 协商结果经子模块 `wire`（[`inject`]）注入 `TransportConfig`。
//! **默认**路径仍为 quinn 默认 CUBIC。**BBR 仍未移植。**
//! 接线落点与偏离清单见 `docs/congestion-status.md`。

pub mod bandwidth;
pub mod header;
pub mod wire;

pub use bandwidth::{Bandwidth, BandwidthError, BRUTAL_MIN_BPS};
pub use header::{CcHeader, HeaderError, CC_AUTO, HEADER_CC_RX, HEADER_CC_TX};
pub use wire::{
    announce_frame, client_rate, inject, parse_announce, parse_mode, server_send_rate,
    CongestionError, PacedReader, Pacer, ANNOUNCE_LEN,
};

/// 拥塞控制模式，对齐参考 `quicParams.Congestion` 的取值集
/// （`infra/conf/transport_internet.go` 行 1913-1920）：
/// `"" | "brutal" | "reno" | "bbr" | "force-brutal"`。
///
/// 参考中空串 `""` 与 `"brutal"` 同分支（默认走 Brutal 协商，
/// 服务端/客户端在缺参数时回落 BBR）。本仓把空串显式折为 `Brutal`
/// 以保持同一分支语义，并在 `FromStr` 里记录该折算。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionMode {
    /// 协商式 Brutal：取 `min(本地 up, 对端 down)`；任一侧为 0 则回落 BBR。
    Brutal,
    /// 强制 Brutal：直接用本地 `up`，不做协商（参考 `force-brutal`）。
    ForceBrutal,
    /// BBR（参考 `congestion.UseBBR`）。
    Bbr,
    /// Reno（参考 `case "reno"`，实为 quinn/go 默认分支）。
    Reno,
}

impl CongestionMode {
    /// 解析配置字符串。**大小写不敏感**（对齐参考
    /// `strings.ToLower(...Congestion)`），两端空白容忍（对齐 JSON 习惯）。
    ///
    /// 未识别值返回 `Err`（fail-closed），**不静默落到 CUBIC**。
    pub fn parse(s: &str) -> Result<CongestionMode, ConfigError> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            // 参考把 "" 与 "brutal" 归为同一 case。
            "" | "brutal" => Ok(CongestionMode::Brutal),
            "force-brutal" => Ok(CongestionMode::ForceBrutal),
            "bbr" => Ok(CongestionMode::Bbr),
            "reno" => Ok(CongestionMode::Reno),
            other => Err(ConfigError::UnknownMode {
                mode: other.to_string(),
            }),
        }
    }
}

/// `CongestionConfig` 构造/校验失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// 未识别的 congestion mode（对齐参考 `unknown congestion control: ...`）。
    #[error(
        "未知的拥塞控制模式：{mode:?}（合法：reno、bbr、brutal、force-brutal，空串等价 brutal）"
    )]
    UnknownMode { mode: String },

    /// `force-brutal` 要求显式 up（对齐参考 `force-brutal requires up`）。
    #[error("force-brutal 必须显式指定 up（rx）带宽")]
    ForceBrutalRequiresRx,

    /// 带宽解析失败（单位/数值）。
    #[error(transparent)]
    Bandwidth(#[from] BandwidthError),
}

/// Brutal 参数与拥塞模式的配置载体（对齐参考 `QuicParams.Congestion` /
/// `BrutalUp` / `BrutalDown` 三字段的组合）。
///
/// **`rx` / `tx` 的含义按参考的行文方向命名**：
/// - `rx` = 本端**接收**方向容量 = 参考 `BrutalDown`（下行）；
/// - `tx` = 本端**发送**方向容量 = 参考 `BrutalUp`（上行）。
///
/// 该命名是为与 `Hysteria-CC-RX`（承载 `BrutalDown`）保持一致；
/// 二者数值上恒等，见 `rx_matches_cc_rx` 断言测试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionConfig {
    /// 拥塞模式。
    pub mode: CongestionMode,
    /// 本端接收容量（= 参考 `BrutalDown`），单位字节/秒；`0` = 未配置。
    pub rx: Bandwidth,
    /// 本端发送容量（= 参考 `BrutalUp`），单位字节/秒；`0` = 未配置。
    pub tx: Bandwidth,
}

impl Default for CongestionConfig {
    /// 缺省等价参考的空配置：mode 空串（→ `Brutal`），上下行均未配置。
    fn default() -> Self {
        CongestionConfig {
            mode: CongestionMode::Brutal,
            rx: Bandwidth(0),
            tx: Bandwidth(0),
        }
    }
}

impl CongestionConfig {
    /// 构造并校验。校验矩阵（逐条对齐参考 `QuicParams` 构建期检查）：
    /// - 上下行若非 `0`，必须 `>= 65536`（参考行 1906-1911）；
    /// - `force-brutal` 必须 `tx != 0`（参考 `force-brutal requires up`，
    ///   注意参考判的是 `up`，即本仓的 `tx`）；
    /// - 其余模式不要求带宽存在（缺省即回落 BBR，由协商函数处理）。
    pub fn new(
        mode: CongestionMode,
        rx: Bandwidth,
        tx: Bandwidth,
    ) -> Result<CongestionConfig, ConfigError> {
        bandwidth::check_brutal_min(rx, "BrutalDown(rx)")?;
        bandwidth::check_brutal_min(tx, "BrutalUp(tx)")?;
        if mode == CongestionMode::ForceBrutal && tx.is_unset() {
            return Err(ConfigError::ForceBrutalRequiresRx);
        }
        Ok(CongestionConfig { mode, rx, tx })
    }

    /// 从原始字符串三元组构造（mode + 两侧带宽文本）。
    ///
    /// 缺省/空串带宽解析为 `0`（未配置），非法值 fail-closed。
    pub fn from_strs(mode: &str, rx: &str, tx: &str) -> Result<CongestionConfig, ConfigError> {
        let mode = CongestionMode::parse(mode)?;
        let rx = Bandwidth::parse(rx)?;
        let tx = Bandwidth::parse(tx)?;
        CongestionConfig::new(mode, rx, tx)
    }

    /// 本端声明给对端接收的容量，即写入 `Hysteria-CC-RX` 头的值
    /// （对齐 `dialer.go` 行 274：请求头写 `BrutalDown`，即本仓 `rx`）。
    pub fn cc_rx_value(&self) -> Bandwidth {
        self.rx
    }
}

/// 客户端协商结果：给定本地 `CongestionConfig` 与服务端 `Hysteria-CC-RX`
/// 响应头，推导**参考会选取的目标发送速率**。
///
/// 逐条对齐 `dialer.go` 行 300-315 的 `switch`：
/// - `reno` → `None`（参考仅打日志，不改拥塞器）；
/// - `bbr` → `None`（参考 `UseBBR`，非 Brutal）；
/// - `brutal`/`""`：若服务端为 `"auto"`、或本地 `up==0`、或服务端 `down==0`
///   → 回落 BBR（`None`）；否则 `min(local up, server down)`；
/// - `force-brutal` → 直接 `local up`（参考不做 min）；
/// - 未识别 → 参考落到 `default: reno`（`None`）。
///
/// 返回 `Some(bps)` 表示参考路径会调用 `UseBrutal(conn, bps)` —— **本仓
/// 不替换拥塞器**，该值仅用于校验/日志/上层决策，请见模块级声明。
pub fn negotiate_client_rate(local: &CongestionConfig, server_cc_rx: CcHeader) -> Option<u64> {
    match local.mode {
        CongestionMode::Reno | CongestionMode::Bbr => None,
        CongestionMode::ForceBrutal => Some(local.tx.bps()),
        CongestionMode::Brutal => match server_cc_rx {
            CcHeader::Auto => None,
            CcHeader::Bps(server_down) => {
                if local.tx.is_unset() || server_down.is_unset() {
                    None
                } else {
                    Some(local.tx.bps().min(server_down.bps()))
                }
            }
        },
    }
}

/// 服务端协商结果：给定服务端 `QuicParams`（本仓 `CongestionConfig`）与客户端
/// 请求头 `Hysteria-CC-RX` 中的 `clientDown`，推导参考选取的目标发送速率。
///
/// 逐条对齐 `hub.go` 行 190-206：
/// - `brutal`/`""`：若 `BrutalUp == 0 || clientDown == 0` → BBR（`None`）；
///   否则 `min(BrutalUp, clientDown)` —— 注意服务端**没有** `"auto"` 分支，
///   客户端若发 `"auto"` 按参考 `ParseUint` 失败退化为 0（见 `decode_or_unset`）；
/// - `force-brutal` → 直接 `BrutalUp`；
/// - `reno`/`bbr`/未识别 → `None`。
pub fn negotiate_server_rate(local: &CongestionConfig, client_cc_rx: CcHeader) -> Option<u64> {
    match local.mode {
        CongestionMode::Reno | CongestionMode::Bbr => None,
        CongestionMode::ForceBrutal => Some(local.tx.bps()),
        CongestionMode::Brutal => match client_cc_rx {
            // 服务端不认 "auto"：按参考 ParseUint 失败 → 0 → BBR。
            CcHeader::Auto => None,
            CcHeader::Bps(client_down) => {
                if local.tx.is_unset() || client_down.is_unset() {
                    None
                } else {
                    Some(local.tx.bps().min(client_down.bps()))
                }
            }
        },
    }
}
