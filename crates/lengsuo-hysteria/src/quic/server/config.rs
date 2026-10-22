//! 服务端配置与启动错误类型。

use std::net::SocketAddr;

use super::constants::DEFAULT_UDP_IDLE_TIMEOUT_SECS;

/// 服务端配置。
///
/// `auth` 是唯一的认证口令；日志与错误文本都不得出现该值。
#[derive(Clone)]
pub struct ServerConfig {
    /// 监听地址（UDP）。参考实现拒绝域名地址，这里由调用方保证是 IP。
    pub listen_addr: SocketAddr,
    /// 证书链（DER，至少一张）。
    pub cert_chain_der: Vec<Vec<u8>>,
    /// 私钥（DER，PKCS#8/PKCS#1/SEC1 由 rustls 判别）。
    pub key_der: Vec<u8>,
    /// 认证口令（对齐 `Config.Auth`）。
    pub auth: String,
    /// 服务端 Brutal 下行带宽（字节/秒），回给客户端的 `Hysteria-CC-RX`
    /// 即 `quicParams.BrutalDown`。
    pub brutal_down: u64,
    /// 服务端 Brutal 上行带宽（字节/秒），即 `quicParams.BrutalUp`：服务端
    /// **发送方向**的速率，与客户端 `Hysteria-CC-RX` 取 `min`
    /// （hub.go 194-200）。`0` = 未配置 ⇒ 参考回落分支。
    pub brutal_up: u64,
    /// 是否开放 UDP datagram（对齐 `hyCtx.RequireDatagramFromContext` 的
    /// 服务端侧配置：由入站设置决定，不由客户端请求头决定）。
    pub udp_enabled: bool,
    /// UDP 会话空闲超时（秒），对齐 `Config.UdpIdleTimeout`。
    pub udp_idle_timeout_secs: u64,
    /// 拥塞控制模式字符串（配置里的 `"congestion"`）。空串 = quinn 默认
    /// CUBIC；`"brutal"` = 按 `brutal_down` 静态装配发送方向 Brutal；未识别值
    /// **fail-closed**（`bind` 报错），不静默回落 CUBIC。
    pub congestion: String,
}

impl ServerConfig {
    /// 缺省 UDP 超时（60s，对齐参考 `udpIdleTimeout` 语义）的最小构造。
    #[must_use]
    pub fn new(
        listen_addr: SocketAddr,
        cert_chain_der: Vec<Vec<u8>>,
        key_der: Vec<u8>,
        auth: String,
    ) -> Self {
        Self {
            listen_addr,
            cert_chain_der,
            key_der,
            auth,
            brutal_down: 0,
            brutal_up: 0,
            udp_enabled: true,
            udp_idle_timeout_secs: DEFAULT_UDP_IDLE_TIMEOUT_SECS,
            congestion: String::new(),
        }
    }
}

/// 服务端启动/监听错误。错误文本不包含认证口令。
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("本机 UDP 端口绑定失败: {0}")]
    Bind(String),
    #[error("TLS 配置构造失败: {0}")]
    Tls(String),
    #[error("证书或私钥缺失/非法")]
    MissingCredentials,
    #[error("拥塞控制配置非法: {0}")]
    Congestion(#[from] crate::congestion::CongestionError),
    #[error("混淆口令非法: {0}")]
    Obfs(#[from] crate::obfs::PskTooShort),
}
