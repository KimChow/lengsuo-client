//! 出口分发：按协议把 `NodeConfig` 分发到本仓各协议 crate 的客户端 API。
//!
//! 不为统一接口改协议 crate：trojan 走 `lengsuo_trojan` 的请求头写出，
//! anytls 走 `lengsuo_anytls` 的认证块 + 帧原语 + 客户端状态机，TLS 统一由
//! `lengsuo_tls` 承担（对齐参考：两协议的认证都只在已认证 TLS 之上进行）。
//!
//! 本文件只保留**分发**与**八协议共用**的设施；各协议的具体拨号实现分散在
//! 各自的 `outbound_*` 模块里（`outbound_trojan` / `outbound_ss` /
//! `outbound_ss2022` / `outbound_vmess` / `outbound_vless` /
//! `outbound_hysteria` / `outbound_wireguard`）。
//!
//! “握手到认证完成”在两协议的观测方式不同，与参考一致：
//! - trojan 没有成功响应头（参考 `client.go` 写完头部即转发）：认证完成只能
//!   负向排除——请求头完整写出后开一个观察窗，窗内对端关闭（EOF/读错误）即
//!   判拒绝（参考服务端认证失败的表达就是关闭连接）；窗内收到数据或安静
//!   到超时都视为未被拒绝。实现见 `crate::outbound_trojan`。
//! - anytls 服务端认证通过后下发 ServerSettings：收到它即认证完成的正向证据
//!   （对齐 anytls-go `session.go` 的客户端分支），断连或 Alert 即拒绝。

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use lengsuo_tls::{CertificateDer, TlsClient};
use rustls::pki_types::pem::PemObject as _;
use ss_core::target::TargetAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

use crate::config::{Endpoint, NodeConfig, Protocol};
use crate::outbound_hysteria::HysteriaOutbound;
use crate::outbound_ss::ShadowsocksOutbound;
use crate::outbound_ss2022::Ss2022Outbound;
use crate::outbound_trojan::{
    TrojanError, TrojanOutbound, TROJAN_PROBE_FALLBACK_HOST, TROJAN_PROBE_FALLBACK_PORT,
};
use crate::outbound_vless::VlessOutbound;
use crate::outbound_vmess::VmessOutbound;
use crate::outbound_wireguard::WireguardOutbound;
use lengsuo_anytls::auth::Credential as AnyTlsCredential;
use lengsuo_anytls::client_state::ClientState;
use lengsuo_anytls::frame::{Command as AnyTlsCommand, Frame};

/// anytls 客户端单会话活跃流上限（对齐参考默认，见 interop 客户端组装）。
const ANYTLS_MAX_STREAMS: usize = 16;
/// anytls 客户端标识；服务端不校验该键，如实上报自身。
const ANYTLS_CLIENT_IDENT: &str = "lengsuo-node";
/// 默认 padding 方案的 md5（anytls-go v0.0.13 `pad/padding.go` 逐字节算出），
/// 上报它使服务端不必先下发 UpdatePadding 即完成 v2 协商。
/// 与 `lengsuo-anytls/tests/interop_client/session.rs` 同源同值。
const ANYTLS_DEFAULT_SCHEME_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";
/// 认证块 padding：参考客户端按默认方案 `0=30-30` 生成，0 号记录恒 30 字节零值。
const ANYTLS_AUTH_PADDING: [u8; 30] = [0; 30];

/// 已完成的 TLS 连接类型别名。
pub type NodeTlsStream = TlsStream<TcpStream>;

/// 按协议分发建立的出口连接；返回即代表该协议“认证完成”的可观测判据满足。
pub enum Outbound {
    /// trojan：请求头已完整写出且观察窗内未被对端拒绝。
    Trojan(TrojanOutbound),
    /// anytls：认证块 + 客户端 Settings 已写出，且已收到服务端 ServerSettings。
    AnyTls(Box<AnyTlsOutbound>),
    /// vless：请求头已完整写出且已收到服务端成功响应头 `[0, 0]`。
    Vless(Box<VlessOutbound>),
    /// vmess：AEAD 请求头已写出、加密数据帧已送达，且已收到认证响应头。
    Vmess(Box<VmessOutbound>),
    /// shadowsocks（经典 AEAD）：salt + 目标地址 + 首批载荷已写出，
    /// 且回程方向已成功解出至少一个通过认证的 chunk。
    Shadowsocks(Box<ShadowsocksOutbound>),
    /// ss2022（SIP022）：请求流开场（salt + 固定头 + 变长头）已写出，
    /// 且服务端响应流开场已通过 salt 归属校验。
    Ss2022(Box<Ss2022Outbound>),
    /// hysteria2：QUIC + H3 认证已完成（status=233），且 TCP 承载请求已被接受。
    Hysteria(Box<HysteriaOutbound>),
    /// wireguard：Noise IK 响应已认证解封并派生 transport 会话密钥。
    Wireguard(WireguardOutbound),
}

/// anytls 出站会话：已认证、已协商版本，可继续开流（SYN/PUSH）转发业务。
pub struct AnyTlsOutbound {
    pub stream: NodeTlsStream,
    pub state: ClientState,
}

/// 分发失败。所有 Display 都不含密码或其摘要。
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("TLS 配置非法：{0}")]
    InvalidTls(String),
    #[error("TLS 握手/连接失败：{0}")]
    Tls(#[from] lengsuo_tls::Error),
    #[error("节点地址解析失败：{0}")]
    Resolve(String),
    #[error("trojan 握手失败：{0}")]
    Trojan(#[from] TrojanError),
    #[error("anytls 协议错误：{0}")]
    AnyTls(#[from] lengsuo_anytls::Error),
    #[error("anytls 客户端状态机拒绝：{0}")]
    AnyTlsState(String),
    #[error("vless 协议错误：{0}")]
    Vless(#[from] lengsuo_vless::stream::Error),
    #[error("vless 请求头编码失败：{0}")]
    VlessHeader(#[from] lengsuo_vless::header::Error),
    #[error("REALITY 配置非法：{0}")]
    RealityConfig(#[from] lengsuo_vless::reality_config::ConfigError),
    #[error("REALITY 握手失败：{0}")]
    Reality(#[from] lengsuo_vless::reality_link::Error),
    #[error("vmess 协议错误：{0}")]
    Vmess(#[from] lengsuo_vmess::Error),
    #[error("shadowsocks 协议错误：{0}")]
    Shadowsocks(#[from] lengsuo_shadowsocks::TcpError),
    #[error("ss2022 协议错误：{0}")]
    Ss2022(#[from] lengsuo_ss2022::Error),
    #[error("hysteria 协议错误：{0}")]
    Hysteria(#[from] lengsuo_hysteria::proxy::ProxyError),
    #[error("hysteria QUIC/H3 建连失败：{0}")]
    HysteriaConnect(#[from] lengsuo_hysteria::quic::ConnectError),
    #[error("wireguard 协议错误：{0}")]
    Wireguard(#[from] lengsuo_wireguard::TransportError),
    #[error("wireguard 握手失败：{0}")]
    WireguardHandshake(#[from] lengsuo_wireguard::handshake::ResponderError),
    #[error("认证被对端拒绝：{0}")]
    Rejected(String),
    #[error("等待认证确认超时")]
    Timeout,
}

/// 解析节点端点：IP 直用，域名走异步解析后取首个地址。
pub(crate) async fn resolve(
    host: &str,
    port: u16,
    wait: Duration,
) -> Result<SocketAddr, DialError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let resolved = timeout(wait, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| DialError::Timeout)?
        .map_err(|err| DialError::Resolve(format!("{host}:{port}: {err}")))?;
    resolved
        .into_iter()
        .next()
        .ok_or_else(|| DialError::Resolve(format!("{host}:{port}: 无地址")))
}

/// [`resolve`] 的公开别名：QUIC/UDP 承载（hysteria、wireguard）需要
/// `SocketAddr` 而不是 `TargetAddr`。
pub(crate) async fn resolve_public(
    host: &str,
    port: u16,
    wait: Duration,
) -> Result<SocketAddr, DialError> {
    resolve(host, port, wait).await
}

/// 由配置构造 TLS 客户端：名称缺省用 endpoint.host，信任锚来自 `ca_pem`。
pub(crate) fn tls_client(config: &NodeConfig, wait: Duration) -> Result<TlsClient, DialError> {
    let Some(tls) = config.tls.as_ref() else {
        return Err(DialError::InvalidTls(
            "本卡两协议都要求 tls 配置（参考默认均经 TLS）".to_owned(),
        ));
    };
    if tls.insecure {
        return Err(DialError::InvalidTls(
            "tls.insecure 尚未实现；自签场景请用 tls.ca_pem 固定信任锚".to_owned(),
        ));
    }
    let name = tls
        .server_name
        .clone()
        .unwrap_or_else(|| config.endpoint.host.clone());
    let pem = tls.ca_pem.as_deref().unwrap_or_default();
    let roots: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|err| DialError::InvalidTls(format!("ca_pem 解析失败：{err}")))?;
    if roots.is_empty() {
        return Err(DialError::InvalidTls(
            "tls.ca_pem 未包含任何证书（本卡不加载系统根）".to_owned(),
        ));
    }
    TlsClient::new(&name, roots, wait).map_err(|err| match err {
        lengsuo_tls::Error::InvalidServerName => {
            DialError::InvalidTls(format!("serverName 非法：{name}"))
        }
        other => DialError::Tls(other),
    })
}

/// 按协议分发建立出口连接。`observe` 是 trojan 观察窗时长（负向排除窗口）。
pub async fn dial(
    config: &NodeConfig,
    wait: Duration,
    observe: Duration,
) -> Result<Outbound, DialError> {
    match config.protocol {
        Protocol::Trojan => crate::outbound_trojan::dial_trojan(config, wait, observe)
            .await
            .map(Outbound::Trojan),
        Protocol::AnyTls => dial_anytls(config, wait)
            .await
            .map(Box::new)
            .map(Outbound::AnyTls),
        Protocol::Vless => crate::outbound_vless::dial_vless(config, wait)
            .await
            .map(Box::new)
            .map(Outbound::Vless),
        Protocol::Vmess => crate::outbound_vmess::dial_vmess(config, wait)
            .await
            .map(Box::new)
            .map(Outbound::Vmess),
        Protocol::Shadowsocks => crate::outbound_ss::dial_shadowsocks(config, wait)
            .await
            .map(Box::new)
            .map(Outbound::Shadowsocks),
        Protocol::Ss2022 => crate::outbound_ss2022::dial_ss2022(config, wait)
            .await
            .map(Box::new)
            .map(Outbound::Ss2022),
        Protocol::Hysteria => crate::outbound_hysteria::dial_hysteria(config, wait)
            .await
            .map(Box::new)
            .map(Outbound::Hysteria),
        Protocol::Wireguard => crate::outbound_wireguard::dial_wireguard(config, wait)
            .await
            .map(Outbound::Wireguard),
    }
}

/// 由配置取 dry-run 握手目标（缺省 `127.0.0.1:9` discard，与 trojan 一致）。
pub(crate) fn probe_target(config: &NodeConfig) -> TargetAddr {
    let probe = config.probe_target.clone().unwrap_or_else(|| Endpoint {
        host: TROJAN_PROBE_FALLBACK_HOST.to_owned(),
        port: TROJAN_PROBE_FALLBACK_PORT,
    });
    match probe.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => TargetAddr::V4(v4.octets(), probe.port),
        Ok(IpAddr::V6(v6)) => TargetAddr::V6(v6.octets(), probe.port),
        Err(_) => TargetAddr::Domain(probe.host, probe.port),
    }
}

/// 解析并连接节点端点，返回已完成的 TLS 连接。
pub(crate) async fn connect_tls(
    config: &NodeConfig,
    wait: Duration,
) -> Result<NodeTlsStream, DialError> {
    let client = tls_client(config, wait)?;
    let addr = resolve(&config.endpoint.host, config.endpoint.port, wait).await?;
    Ok(client.connect(addr).await?)
}

/// 解析并连接节点端点，返回裸 TCP 连接（shadowsocks / ss2022 用）。
pub(crate) async fn connect_tcp(
    config: &NodeConfig,
    wait: Duration,
) -> Result<TcpStream, DialError> {
    let addr = resolve(&config.endpoint.host, config.endpoint.port, wait).await?;
    let connect = TcpStream::connect(addr);
    timeout(wait, connect)
        .await
        .map_err(|_| DialError::Timeout)?
        .map_err(|err| DialError::Resolve(format!("连接 {} 失败：{}", config.endpoint.host, err)))
}

/// anytls 出站：TLS → 认证块 → 客户端 Settings(v=2) → 等服务端 ServerSettings。
pub async fn dial_anytls(config: &NodeConfig, wait: Duration) -> Result<AnyTlsOutbound, DialError> {
    let client = tls_client(config, wait)?;
    let addr = resolve(&config.endpoint.host, config.endpoint.port, wait).await?;
    let mut stream = client.connect(addr).await?;

    AnyTlsCredential::new(config.auth.password.as_bytes())
        .send(&mut stream, &ANYTLS_AUTH_PADDING, wait)
        .await?;
    let mut state = ClientState::new(ANYTLS_MAX_STREAMS)
        .map_err(|err| DialError::AnyTlsState(err.to_string()))?;
    state
        .mark_settings_sent()
        .map_err(|err| DialError::AnyTlsState(err.to_string()))?;
    let settings =
        format!("v=2\nclient={ANYTLS_CLIENT_IDENT}\npadding-md5={ANYTLS_DEFAULT_SCHEME_MD5}");
    Frame {
        command: AnyTlsCommand::Settings,
        stream_id: 0,
        data: settings.into_bytes(),
    }
    .write(&mut stream, wait)
    .await?;

    // 等认证完成的正向证据：ServerSettings。断连/Alert = 拒绝；其他帧按状态机处理。
    loop {
        let frame = Frame::read(&mut stream, u16::MAX, wait).await?;
        let event = state
            .accept(&frame)
            .map_err(|err| DialError::AnyTlsState(format!("cmd={}: {err}", frame.command as u8)))?;
        match frame.command {
            AnyTlsCommand::ServerSettings => {
                let _ = event;
                return Ok(AnyTlsOutbound { stream, state });
            }
            AnyTlsCommand::Alert => {
                return Err(DialError::Rejected("服务端 Alert".to_owned()));
            }
            // Waste/心跳/padding 更新/迟到帧：状态机已归类，继续等待。
            _ => continue,
        }
    }
}
