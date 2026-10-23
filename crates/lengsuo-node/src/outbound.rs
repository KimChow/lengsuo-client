//! 出口分发：按协议把 `NodeConfig` 分发到本仓各协议 crate 的客户端 API。
//!
//! 不为统一接口改协议 crate：trojan 走 `lengsuo_trojan` 的请求头写出，
//! anytls 走 `lengsuo_anytls` 的认证块 + 帧原语 + 客户端状态机，TLS 统一由
//! `lengsuo_tls` 承担（对齐参考：两协议的认证都只在已认证 TLS 之上进行）。
//!
//! 本文件只保留**分发**与**八协议共用**的设施；各协议的具体拨号实现分散在
//! 各自的 `outbound_*` 模块里（`outbound_trojan` / `outbound_anytls` /
//! `outbound_ss` /
//! `outbound_ss2022` / `outbound_vmess` / `outbound_vless` /
//! `outbound_hysteria` / `outbound_wireguard`）。
//!
//!
//! anytls 的实现与常量已搬到协议专属模块 `outbound_anytls`（其它六协议
//! 同样各自独立成文件）；本模块只保留**跨协议共享**的部分：分发、类型别名、
//! 解析、TLS 客户端构造与错误枚举。anytls 的出口会话、拨号入口与错误变体
//! 在此转出（`pub use`），既有引用路径 `outbound::dial_anytls` /
//! `outbound::AnyTlsOutbound` 保持可用。
//! “握手到认证完成”在两协议的观测方式不同，与参考一致：
//! - trojan 没有成功响应头（参考 `client.go` 写完头部即转发）：认证完成只能
//!   负向排除——请求头完整写出后开一个观察窗，窗内对端关闭（EOF/读错误）即
//!   判拒绝（参考服务端认证失败的表达就是关闭连接）；窗内收到数据或安静
//!   到超时都视为未被拒绝。实现见 `crate::outbound_trojan`。
//! - anytls 服务端认证通过后下发 ServerSettings：收到它即认证完成的正向证据
//!   （对齐 anytls-go `session.go` 的客户端分支），断连或 Alert 即拒绝。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::{CertificateDer, TlsClient};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use ss_core::target::TargetAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::config::{Endpoint, NodeConfig, Protocol};
/// anytls 拨号入口转出到 `outbound_anytls`（协议专属实现），保持
/// `outbound::dial_anytls` 这条路径对既有调用方（`forward`）继续可用。
pub use crate::outbound_anytls::dial_anytls;
/// anytls 专属错误变体（协议错误 / 客户端状态机拒绝），定义在
/// `outbound_anytls`；`DialError::AnyTls` 以 `transparent` 承载它。
pub use crate::outbound_anytls::AnyTlsError;
/// anytls 出站会话：已认证、已协商版本，可继续开流（SYN/PUSH）转发业务。
/// 定义在 `outbound_anytls`（协议专属模块）；此处转出以保持既有引用路径可用。
pub use crate::outbound_anytls::AnyTlsOutbound;
use crate::outbound_hysteria::HysteriaOutbound;
use crate::outbound_ss::ShadowsocksOutbound;
use crate::outbound_ss2022::Ss2022Outbound;
use crate::outbound_trojan::{
    TrojanError, TrojanOutbound, TROJAN_PROBE_FALLBACK_HOST, TROJAN_PROBE_FALLBACK_PORT,
};
use crate::outbound_vless::VlessOutbound;
use crate::outbound_vmess::VmessOutbound;
use crate::outbound_wireguard::WireguardOutbound;

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
    #[error(transparent)]
    AnyTls(#[from] AnyTlsError),
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

/// `tls.insecure: true` 时使用的证书验证器：**无条件接受**服务端证书与
/// TLS 握手签名。
///
/// **仅用于自签/测试场景**，且只在配置显式给出 `insecure: true` 时生效
/// （`config/validate.rs` 已拒绝它与 `ca_pem` 同时出现）。TLS **握手仍完整
/// 执行**——SNI、密钥交换、握手签名与记录层加密都不跳过，只跳过「证书链 +
/// 主机名」这一项校验；因此对端不是 TLS 服务端时握手照旧失败，绝不会回落到
/// 明文直连。
///
/// 安全提示：它使中间人攻击不可检测，任何非测试配置都不应启用。
#[derive(Debug)]
pub struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS 客户端：`insecure = false` 走完整证书校验（委托 [`TlsClient`]），
/// `insecure = true` 走 [`NoCertificateVerification`]。
pub struct NodeTlsClient {
    inner: Kind,
}

enum Kind {
    /// 既有路径：证书链 + 主机名校验全程开启。
    Verified(TlsClient),
    /// 仅 `insecure: true`：跳过证书/主机名校验，握手仍完整执行。
    Insecure {
        name: ServerName<'static>,
        connector: TlsConnector,
        deadline: Duration,
    },
}

impl NodeTlsClient {
    /// 解析并连接节点端点；错误语义与 [`TlsClient::connect`] 一致。
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<NodeTlsStream, lengsuo_tls::Error> {
        match &self.inner {
            Kind::Verified(client) => client.connect(endpoint).await,
            Kind::Insecure {
                name,
                connector,
                deadline,
            } => {
                let stream = timeout(*deadline, async {
                    let socket = TcpStream::connect(endpoint).await?;
                    connector.connect(name.clone(), socket).await
                })
                .await
                .map_err(|_| lengsuo_tls::Error::Timeout)??;
                Ok(stream)
            }
        }
    }
}

/// 构造跳过证书校验的 rustls 连接器（唯一一份 verifier，供 insecure 复用）。
fn insecure_connector() -> Result<TlsConnector, lengsuo_tls::Error> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(lengsuo_tls::Error::Configuration)?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// 由配置构造 TLS 客户端：名称缺省用 endpoint.host，信任锚来自 `ca_pem`。
///
/// `insecure = true` 时跳过证书与主机名校验（见 [`NoCertificateVerification`]）；
/// `insecure = false` 的路径逐字节保持原有语义（`ca_pem` 为空仍拒绝）。
pub fn tls_client(config: &NodeConfig, wait: Duration) -> Result<NodeTlsClient, DialError> {
    let Some(tls) = config.tls.as_ref() else {
        return Err(DialError::InvalidTls(
            "本卡两协议都要求 tls 配置（参考默认均经 TLS）".to_owned(),
        ));
    };
    let name = tls
        .server_name
        .clone()
        .unwrap_or_else(|| config.endpoint.host.clone());
    if tls.insecure {
        // TlsClient::new 对零 deadline 的拒绝语义在 insecure 路径同样保留。
        if wait.is_zero() {
            return Err(DialError::Tls(lengsuo_tls::Error::InvalidDeadline));
        }
        let server_name = ServerName::try_from(name.clone())
            .map_err(|_| DialError::InvalidTls(format!("serverName 非法：{name}")))?;
        let connector = insecure_connector().map_err(DialError::Tls)?;
        // 每次构造配置一次告警（不逐连接刷屏）。
        eprintln!(
            "[lengsuo-node] tls.insecure 已启用：证书与主机名校验被跳过（endpoint={}）",
            config.endpoint.host
        );
        return Ok(NodeTlsClient {
            inner: Kind::Insecure {
                name: server_name,
                connector,
                deadline: wait,
            },
        });
    }
    let pem = tls.ca_pem.as_deref().unwrap_or_default();
    let roots: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|err| DialError::InvalidTls(format!("ca_pem 解析失败：{err}")))?;
    if roots.is_empty() {
        return Err(DialError::InvalidTls(
            "tls.ca_pem 未包含任何证书（本卡不加载系统根）".to_owned(),
        ));
    }
    let client = TlsClient::new(&name, roots, wait).map_err(|err| match err {
        lengsuo_tls::Error::InvalidServerName => {
            DialError::InvalidTls(format!("serverName 非法：{name}"))
        }
        other => DialError::Tls(other),
    })?;
    Ok(NodeTlsClient {
        inner: Kind::Verified(client),
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
