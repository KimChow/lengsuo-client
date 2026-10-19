//! 出口分发：按协议把 `NodeConfig` 分发到本仓各协议 crate 的客户端 API。
//!
//! 不为统一接口改协议 crate：trojan 走 `lengsuo_trojan` 的请求头写出，
//! anytls 走 `lengsuo_anytls` 的认证块 + 帧原语 + 客户端状态机，TLS 统一由
//! `lengsuo_tls` 承担（对齐参考：两协议的认证都只在已认证 TLS 之上进行）。
//!
//! “握手到认证完成”在两协议的观测方式不同，与参考一致：
//! - trojan 没有成功响应头（参考 `client.go` 写完头部即转发）：认证完成只能
//!   负向排除——请求头完整写出后开一个观察窗，窗内对端关闭（EOF/读错误）即
//!   判拒绝（参考服务端认证失败的表达就是关闭连接）；窗内收到数据或安静
//!   到超时都视为未被拒绝。
//! - anytls 服务端认证通过后下发 ServerSettings：收到它即认证完成的正向证据
//!   （对齐 anytls-go `session.go` 的客户端分支），断连或 Alert 即拒绝。

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use lengsuo_tls::{CertificateDer, TlsClient};
use rustls::pki_types::pem::PemObject as _;
use ss_core::target::TargetAddr;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

use crate::config::Endpoint;

use crate::config::NodeConfig;
use lengsuo_anytls::auth::Credential as AnyTlsCredential;
use lengsuo_anytls::client_state::ClientState;
use lengsuo_anytls::frame::{Command as AnyTlsCommand, Frame};
use lengsuo_trojan::session::Session as TrojanSession;
use lengsuo_trojan::{Command as TrojanCommand, Credential as TrojanCredential, Request};

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
/// trojan dry-run 缺省握手目标（discard 端口），见 `NodeConfig::probe_target`。
const TROJAN_PROBE_FALLBACK_HOST: &str = "127.0.0.1";
const TROJAN_PROBE_FALLBACK_PORT: u16 = 9;

/// 已完成的 TLS 连接类型别名。
pub type NodeTlsStream = TlsStream<TcpStream>;
/// trojan 出站会话：握手（写头）已完成，可转发 TCP 载荷。
pub type TrojanOutbound = TrojanSession<ReadHalf<NodeTlsStream>, WriteHalf<NodeTlsStream>>;

/// 按协议分发建立的出口连接；返回即代表该协议“认证完成”的可观测判据满足。
pub enum Outbound {
    /// trojan：请求头已完整写出且观察窗内未被对端拒绝。
    Trojan(TrojanOutbound),
    /// anytls：认证块 + 客户端 Settings 已写出，且已收到服务端 ServerSettings。
    AnyTls(Box<AnyTlsOutbound>),
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
    Trojan(#[from] lengsuo_trojan::stream::Error),
    #[error("anytls 协议错误：{0}")]
    AnyTls(#[from] lengsuo_anytls::Error),
    #[error("anytls 客户端状态机拒绝：{0}")]
    AnyTlsState(String),
    #[error("认证被对端拒绝：{0}")]
    Rejected(String),
    #[error("等待认证确认超时")]
    Timeout,
}

/// 解析节点端点：IP 直用，域名走异步解析后取首个地址。
async fn resolve(host: &str, port: u16, wait: Duration) -> Result<SocketAddr, DialError> {
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

/// 由配置构造 TLS 客户端：名称缺省用 endpoint.host，信任锚来自 `ca_pem`。
fn tls_client(config: &NodeConfig, wait: Duration) -> Result<TlsClient, DialError> {
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
        crate::config::Protocol::Trojan => dial_trojan(config, wait, observe)
            .await
            .map(Outbound::Trojan),
        crate::config::Protocol::AnyTls => dial_anytls(config, wait)
            .await
            .map(Box::new)
            .map(Outbound::AnyTls),
    }
}

/// trojan 出站：TLS → 写请求头 → 观察窗负向排除。
async fn dial_trojan(
    config: &NodeConfig,
    wait: Duration,
    observe: Duration,
) -> Result<TrojanOutbound, DialError> {
    let client = tls_client(config, wait)?;
    let addr = resolve(&config.endpoint.host, config.endpoint.port, wait).await?;
    let stream = client.connect(addr).await?;
    let (read, write) = tokio::io::split(stream);
    let credential = TrojanCredential::new(&config.auth.password);
    let probe = config.probe_target.clone().unwrap_or_else(|| Endpoint {
        host: TROJAN_PROBE_FALLBACK_HOST.to_owned(),
        port: TROJAN_PROBE_FALLBACK_PORT,
    });
    let target = match probe.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => TargetAddr::V4(v4.octets(), probe.port),
        Ok(IpAddr::V6(v6)) => TargetAddr::V6(v6.octets(), probe.port),
        Err(_) => TargetAddr::Domain(probe.host, probe.port),
    };
    let request = Request {
        command: TrojanCommand::Tcp,
        target,
    };
    let mut session = TrojanSession::connect(read, write, &request, &credential, wait).await?;
    // 观察窗：对端关闭 = 认证被拒（参考服务端拒绝的唯一表达）；
    // 安静或收到数据 = 未被拒绝，返回可继续转发业务的会话。
    let mut probe = [0u8; 1];
    match timeout(observe, session.read(&mut probe)).await {
        Ok(Ok(0)) => Err(DialError::Rejected(
            "连接被对端关闭（trojan 无响应头）".to_owned(),
        )),
        Ok(Ok(_)) => Ok(session),
        Ok(Err(_)) => Err(DialError::Rejected("连接在观察窗内断开".to_owned())),
        Err(_) => Ok(session),
    }
}

/// anytls 出站：TLS → 认证块 → 客户端 Settings(v=2) → 等服务端 ServerSettings。
async fn dial_anytls(config: &NodeConfig, wait: Duration) -> Result<AnyTlsOutbound, DialError> {
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
