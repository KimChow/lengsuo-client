//! 客户端配置与建连错误类型。

use std::net::SocketAddr;

use crate::congestion::CcHeader;

/// 客户端到 Hysteria2 服务端的配置。
#[derive(Clone)]
pub struct ClientConfig {
    /// 服务端 UDP 地址。
    pub server_addr: SocketAddr,
    /// TLS SNI / 证书校验名（Xray `streamSettings.tlsSettings.serverName`）。
    pub server_name: String,
    /// `Hysteria-Auth` 头的值；日志与错误信息不得出现该值。
    pub auth: String,
    /// 追加受信根证书（DER）。证书验证始终开启，不提供跳过校验选项。
    pub roots_der: Vec<Vec<u8>>,
    /// `Hysteria-CC-RX` 请求头取值（Brutal 下行带宽，字节/秒；0 = 未设置）。
    pub brutal_down: u64,
    /// 本端发送速率（参考 `BrutalUp`，字节/秒；0 = 未配置 ⇒ 参考回落分支）。
    pub brutal_up: u64,
    /// 拥塞模式字符串（配置里的 `"congestion"`）。空串 = quinn 默认 CUBIC；
    /// `"brutal"` = 按其协商结果注入 Brutal；未识别值 **fail-closed**。
    pub congestion: String,
    /// 服务端 `Hysteria-CC-RX`（字节/秒，= 参考 `BrutalDown`）：由
    /// [`super::HysteriaClient::probe_peer_cc_rx`] 在一条探测连接上取得后
    /// 回填到本配置。`None` ⇒ 未探测 ⇒ 参考回落分支（不注入 Brutal，
    /// 沿用 CUBIC）。
    pub peer_cc_rx: Option<CcHeader>,
}

impl Default for ClientConfig {
    /// 仅供测试/结构体更新语法（`..Default::default()`）：**不**建连，
    /// 也**不**提供凭据；地址为回环 :0，`congestion` 为空（CUBIC）。
    fn default() -> Self {
        Self {
            server_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            server_name: "localhost".to_string(),
            auth: String::new(),
            roots_der: Vec::new(),
            brutal_down: 0,
            brutal_up: 0,
            congestion: String::new(),
            peer_cc_rx: None,
        }
    }
}

/// 建连/会话错误。错误文本不包含认证密码。
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("本机 UDP 端口绑定失败: {0}")]
    Bind(String),
    #[error("TLS 配置构造失败: {0}")]
    Tls(String),
    #[error("QUIC 端点/连接失败: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("H3 认证失败: {0}")]
    Auth(#[from] crate::h3_auth::AuthError),
    #[error("服务端未声明支持 UDP（Hysteria-UDP 响应头为假）")]
    UdpUnsupported,
    #[error("0-RTT 配置失败: {0}")]
    EarlyData(#[from] crate::quic::early::EarlyDataError),
    #[error("拥塞控制配置非法: {0}")]
    Congestion(#[from] crate::congestion::CongestionError),
}

impl ConnectError {
    /// 认证被拒（HTTP 状态非 233）时返回状态码，供上层区分。
    #[must_use]
    pub fn rejected_status(&self) -> Option<u16> {
        match self {
            ConnectError::Auth(crate::h3_auth::AuthError::Rejected { status }) => Some(*status),
            _ => None,
        }
    }
}
