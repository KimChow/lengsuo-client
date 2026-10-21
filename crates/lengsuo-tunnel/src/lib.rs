#![forbid(unsafe_code)]
//! `lengsuo-tunnel` — 跨端链路隧道运行时（**有 IO，只在 PC 端使用**）。
//!
//! 职责边界：
//! - **有**：UDP socket 封装、NAT 打洞的收发循环、peer endpoint 漫游更新
//!   （手机切 WiFi↔5G 或 NAT 重绑后必需）、persistent keepalive 驱动、
//!   与 `lengsuo-link-core` 的装配。
//! - **没有**：协议语义。帧编解码、密钥派生、通道协商全在
//!   `lengsuo-link-core`（无 IO）里，本 crate 只负责搬运字节与驱动状态机。
//!
//! ⚠️ **移动端不依赖本 crate**：它引入 tokio 与平台 socket，
//! 会把移动端构建链拖垮。移动端只用 `lengsuo-link-core`。
//!
//! ⚠️ **endpoint 漫游是待建项**：`lengsuo-wireguard` 当前**没有**
//! peer endpoint 更新能力（`grep roam / set_endpoint / update_endpoint` 零命中），
//! 本 crate 需要给它补上，否则「连上之后掉线」无法处理。

/// 骨架占位：随首批卡逐块填充。保持 crate 可编译、可被下游引用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_constructible() {
        assert_eq!(Placeholder, Placeholder);
    }
}
