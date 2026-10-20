//! 拥塞控制实现（独立 crate，避免与协议 crate 的 touches 冲突）。
//!
//! **为什么独立成 crate**：`quinn-proto` 的 `congestion::Controller` 与
//! `congestion::ControllerFactory` 都是**公开 trait**（`quinn-proto-0.11.19/
//! src/congestion.rs:17` 与 `:100`），而
//! `TransportConfig::congestion_controller_factory()`（`config/transport.rs:333`）
//! 是**公开 API** ⇒ 自研拥塞器**不需要 fork quinn**，可以放在独立 crate 里
//! 实现，再由协议 crate 注入。
//!
//! 独立成 crate 的额外好处：协议 crate（vless/vmess/hysteria/…）与拥塞控制
//! crate 可以**并行开发**，互不抢同一块代码（`card_guard` 的 touches 不会冲突）。
//!
//! 语义基线：Hysteria2 的 **Brutal** 拥塞控制（固定速率 + 窗口上限，
//! 丢包不激进降速），带宽由 `Hysteria-CC-RX` / `Hysteria-CC-TX` 头协商。

/// Brutal 拥塞器（固定速率 + 窗口上限）。
pub mod brutal;

pub use brutal::{Brutal, BrutalConfig, ConfigError};

/// 拥塞控制模式（与 Hysteria2 的 `CongestionMode` 语义对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Brutal：固定速率，丢包不降速。
    Brutal,
}

impl Mode {
    /// 由线上/配置字符串解析；**未识别值返回 `Err`**（fail-closed），
    /// **不静默落到 quinn 默认 CUBIC**。
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        match text.trim().to_ascii_lowercase().as_str() {
            "brutal" => Ok(Self::Brutal),
            other => Err(ParseError::UnknownMode(other.to_owned())),
        }
    }
}

/// 模式解析失败。
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// 未识别的拥塞控制模式名。
    #[error("未识别的拥塞控制模式：{0}")]
    UnknownMode(String),
}
