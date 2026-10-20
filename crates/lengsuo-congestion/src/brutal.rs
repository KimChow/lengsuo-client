//! Brutal 拥塞器（固定速率 + 窗口上限）——占位骨架，由对应开发卡填充实现。
//!
//! 语义基线：Hysteria2 Brutal。丢包**不**激进降速（与 CUBIC/BBR 的关键差别），
//! 速率由 `Hysteria-CC-RX` / `Hysteria-CC-TX` 协商后注入。

/// Brutal 拥塞器的配置。
#[derive(Debug, Clone, Copy)]
pub struct BrutalConfig {
    /// 协商得到的速率（bps）。
    pub bandwidth: u64,
    /// 初始拥塞窗口（字节）。
    pub initial_window: u64,
}
