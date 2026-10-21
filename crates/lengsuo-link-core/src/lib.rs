#![forbid(unsafe_code)]
//! `lengsuo-link-core` — 跨端链路协议核心（**无 IO**）。
//!
//! 职责边界（**刻意收窄，避免它长成第二个网络栈**）：
//! - **有**：会话密钥派生、密文帧编解码、通道协商（`p2p` / `relay`）、
//!   连接世代号、能力集协商。
//! - **没有**：任何 socket、任何文件、任何计时器驱动、任何线程。
//!   时间的推进由调用方通过显式传入的时间戳决定。
//!
//! 为什么要「无 IO」：本 crate 是**唯一会被编成移动端静态库的 Rust 代码**
//! （iOS / Android 通过 FFI 调用）。一旦它引入 tokio 或平台相关依赖，
//! 移动端构建链就会被拖垮。
//!
//! 依赖方向：本 crate 只依赖 `lengsuo-wireguard`（Noise IK 握手与
//! ChaCha20Poly1305 传输密钥的来源），**不依赖任何 lengsuo 业务仓**。
//!
//! ⚠️ **本 crate 不是标准 WireGuard 协议**：它复用 wireguard-go 的握手与
//! AEAD 算法（开源参照，保留署名），但**不复用其 IP/TUN 封装**——
//! 我方直接在 UDP 之上承载 ACP 帧。详见仓内 `docs/spec/`。

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
