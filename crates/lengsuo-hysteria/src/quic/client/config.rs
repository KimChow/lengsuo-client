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

/// 客户端的「混淆 + 端口跳跃」参数。
///
/// 对照参考：`finalmask.udp[].settings.password`（Salamander 口令）与
/// `finalmask.quicParams.udpHop`（端口跳跃）。
///
/// **为什么不放进 [`ClientConfig`]**：`ClientConfig` 在本仓有 9 处**全字段**
/// 结构体字面量（含 `crates/lengsuo-node/src/outbound_hysteria.rs`），
/// 加字段会连带改动本卡边界外的文件。改为独立参数类型 + 独立入口
/// [`super::HysteriaClient::connect_with_obfs`]，边界内的行为完全一致。
#[derive(Clone, Default, Debug)]
pub struct ObfsHopConfig {
    psk: Option<Vec<u8>>,
    hop: Option<crate::transport::HopSpec>,
}

impl ObfsHopConfig {
    /// 不混淆、不跳跃（与参考「未配置 finalmask」一致）。
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// 只做 Salamander 混淆。
    ///
    /// **fail-closed**：口令不足 4 字节（参考 `smPSKMinLen`）时直接报错，
    /// 不静默忽略、更不退化为明文。
    pub fn obfs(psk: Vec<u8>) -> Result<Self, crate::obfs::PskTooShort> {
        Self::new(psk, None)
    }

    /// 混淆 + 端口跳跃。
    ///
    /// **fail-closed**：口令不足 4 字节时直接报错。
    pub fn new(
        psk: Vec<u8>,
        hop: Option<crate::transport::HopSpec>,
    ) -> Result<Self, crate::obfs::PskTooShort> {
        if psk.len() < crate::obfs::PSK_MIN_LEN {
            return Err(crate::obfs::PskTooShort);
        }
        Ok(Self {
            psk: Some(psk),
            hop,
        })
    }

    /// 混淆口令（`None` = 不混淆）。
    #[must_use]
    pub fn psk(&self) -> Option<&[u8]> {
        self.psk.as_deref()
    }

    /// 追加端口跳跃规格（参考 `finalmask.quicParams.udpHop`）。
    ///
    /// 端口区间/间隔非法由 [`crate::transport::HopSpec`] 自己校验
    /// （间隔 < 5s 拒绝，0/0 取 30s），本方法只做装配。
    #[must_use]
    pub fn with_hop(mut self, hop: crate::transport::HopSpec) -> Self {
        self.hop = Some(hop);
        self
    }

    /// 端口跳跃规格（`None` = 不跳跃）。
    #[must_use]
    pub fn hop(&self) -> Option<&crate::transport::HopSpec> {
        self.hop.as_ref()
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
    #[error("混淆口令非法: {0}")]
    Obfs(#[from] crate::obfs::PskTooShort),
    #[error("端口跳跃配置非法: {0}")]
    Hop(#[from] crate::transport::hop::HopError),
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
