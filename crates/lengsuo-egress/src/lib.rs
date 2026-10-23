//! 统一出口（egress）：把八协议的「连接参数 → 已建隧道」收敛成**一份共享实现**。
//!
//! # 为什么有这个 crate
//!
//! 八协议的出站实现原本只存在于 `lengsuo-node/src/outbound*.rs`（服务端转发侧），
//! 而客户端 `ss-client/src/outbound/dialer.rs` **只实现了 Shadowsocks** ⇒
//! 客户端实际可用协议为 1/8（见 `docs/client-e2e-status.md` §4）。
//! 本 crate 的目标是让 **lengsuo-node（服务端）** 与 **ss-client（客户端）**
//! 复用同一份出口实现，而不是各维护一套（项目铁律：不复制两套协议实现）。
//!
//! # 现状与迁移计划（2026-10-24 建立骨架）
//!
//! 本 crate 目前**只有骨架**：协议枚举、统一错误、以及迁移所需的依赖已配齐。
//! 八协议的具体拨号实现仍留在 `lengsuo-node/src/outbound_*.rs`，由后续卡迁移：
//!
//! | 卡 | 做什么 |
//! |---|---|
//! | `ec1-egress-port-protocols` | 把 `outbound_{ss,ss2022,vless,vmess,trojan,hysteria,anytls,wireguard}.rs` 与 `outbound.rs` 的**跨协议共用设施**整体搬入本 crate；`lengsuo-node` 改为 `pub use` 转出，保持既有引用路径可用 |
//! | `ec2-client-dialer-all-protocols` | `ss-client` 的 `Dialer` 改为按协议分发到本 crate（八协议），并在 `docs/client-e2e-status.md` §4 翻绿 |
//!
//! ⛔ **迁移卡不要重新设计接口**：以 `lengsuo-node::outbound` 现有 API 形状为准
//! （每协议一个 `*Outbound` 类型 + 一个 `dial_*` 入口），只做搬迁与 re-export。
//! 统一 trait 抽象属后续独立议题，不在本批范围内。
//!
//! # 分层
//!
//! - [`Protocol`]：八协议枚举（与 `lengsuo-node::config::Protocol` 同形，两处一致性由测试守住）
//! - [`EgressError`]：统一出口错误。**fail-closed** —— 认证/解码失败一律报错，
//!   绝不静默回退明文或直连；错误文本只描述形状，**不含口令/密钥/明文**。

#![forbid(unsafe_code)]

/// 出口协议（八协议）。
///
/// ⚠️ 与 `lengsuo-node::config::Protocol` **同形**（同样的八个变体、同样的语义）。
/// 迁移完成后 `lengsuo-node` 应改为引用本类型，避免两处枚举漂移。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// Shadowsocks（AEAD）。
    Shadowsocks,
    /// Shadowsocks 2022。
    Ss2022,
    /// VLESS。
    Vless,
    /// VMess。
    Vmess,
    /// Trojan。
    Trojan,
    /// Hysteria2。
    Hysteria,
    /// AnyTLS。
    AnyTls,
    /// WireGuard。
    WireGuard,
}

impl Protocol {
    /// 协议的小写规范名。用于错误消息、日志与文档（**不含任何品牌或来源标识**）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shadowsocks => "shadowsocks",
            Self::Ss2022 => "ss2022",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Hysteria => "hysteria",
            Self::AnyTls => "anytls",
            Self::WireGuard => "wireguard",
        }
    }

    /// 八协议全表。供迁移卡逐项接线时遍历断言覆盖（**缺一项即漏协议**）。
    pub const ALL: [Self; 8] = [
        Self::Shadowsocks,
        Self::Ss2022,
        Self::Vless,
        Self::Vmess,
        Self::Trojan,
        Self::Hysteria,
        Self::AnyTls,
        Self::WireGuard,
    ];
}

/// 统一出口错误。
///
/// **fail-closed 纪律**：任何认证失败、解码失败、形状非法都必须返回错误，
/// 不得静默回退为明文或直连；所有变体只承载**形状**信息，不承载取值。
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// 该协议尚未接入本 crate（迁移过程中的诚实占位，不是"静默跳过"）。
    #[error("egress not wired yet: {0}")]
    NotWiredYet(&'static str),
    /// 协议名不被识别。
    #[error("unsupported protocol: {0}")]
    Unsupported(&'static str),
    /// 端点或凭据形状非法（不回显取值）。
    #[error("invalid endpoint or credential shape")]
    InvalidConfig,
    /// 拨号期 IO 错误。
    #[error("io error while dialing egress")]
    Io(#[from] std::io::Error),
    /// 握手/认证超时。
    #[error("egress handshake timed out")]
    Timeout,
    /// 对端拒绝或认证失败（凭据错、被篡改）。
    #[error("egress authentication failed (bad credential or tampering)")]
    AuthFailed,
}

#[cfg(test)]
mod tests {
    use super::{EgressError, Protocol};
    use std::collections::BTreeSet;

    #[test]
    fn all_eight_protocols_listed() {
        assert_eq!(Protocol::ALL.len(), 8, "八协议一个都不能少");
    }

    #[test]
    fn protocol_names_are_lowercase_and_unique() {
        let mut seen = BTreeSet::new();
        for p in Protocol::ALL {
            let s = p.as_str();
            assert_eq!(s, s.to_lowercase(), "协议名必须小写: {s}");
            assert!(!s.is_empty(), "协议名不能为空");
            assert!(seen.insert(s), "协议名重复: {s}");
        }
    }

    #[test]
    fn error_text_never_leaks_secret_shapes() {
        for e in [
            EgressError::InvalidConfig,
            EgressError::Timeout,
            EgressError::AuthFailed,
            EgressError::NotWiredYet("demo"),
        ] {
            let msg = e.to_string();
            for bad in ["password", "secret", "key=", "token"] {
                assert!(!msg.contains(bad), "错误文本泄漏了 {bad}: {msg}");
            }
        }
    }

    #[test]
    fn not_wired_error_names_the_gap_honestly() {
        let e = EgressError::NotWiredYet("vmess");
        assert!(
            e.to_string().contains("vmess"),
            "未接线错误必须点名是哪个协议"
        );
    }
}
