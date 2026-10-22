//! 出口协议枚举。

use serde::{Deserialize, Serialize};

/// 支持的出口协议。八种全部注册；未注册的协议在解析层即拒绝，
/// 避免静默落到错误实现。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Trojan,
    /// 线上名 `anytls`；枚举名避开 `Tls` 后缀歧义（对齐已有实现）。
    #[serde(rename = "anytls")]
    AnyTls,
    Vless,
    Vmess,
    Shadowsocks,
    Ss2022,
    Hysteria,
    Wireguard,
}

impl Protocol {
    /// 该协议是否要求 `tls` 配置块（缺省且必需时校验失败）。
    ///
    /// - trojan / anytls / vless / vmess / hysteria：参考实现的出站都跑在 TLS
    ///   之上（hysteria 是 QUIC/TLS1.3）；本卡不提供「明文降级」路径。
    /// - shadowsocks / ss2022 / wireguard：协议自带加密或握手，不经 TLS。
    #[must_use]
    pub const fn requires_tls(self) -> bool {
        matches!(
            self,
            Protocol::Trojan
                | Protocol::AnyTls
                | Protocol::Vless
                | Protocol::Vmess
                | Protocol::Hysteria
        )
    }

    /// 该协议是否使用 `auth.password` 之外的密钥材料。
    #[must_use]
    pub const fn uses_secret_fields(self) -> bool {
        matches!(
            self,
            Protocol::Shadowsocks | Protocol::Ss2022 | Protocol::Wireguard
        )
    }
}
