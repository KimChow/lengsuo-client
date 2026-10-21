//! 服务端端点与每连接上下文。

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::VarInt;

use crate::h3_auth;

use super::config::{ServerConfig, ServerError};
use super::constants::{DEFAULT_MAX_IDLE_TIMEOUT_MS, DEFAULT_MAX_INCOMING_STREAMS};

/// 已绑定的 Hysteria2 服务端（等价 `hub.go` `Listener`）。
pub struct HysteriaServer {
    endpoint: quinn::Endpoint,
    auth: Arc<String>,
    brutal_down: u64,
    udp_enabled: bool,
    udp_idle_timeout_secs: u64,
    /// 拥塞模式 + 本端发送速率（`bind` 期已 fail-closed 校验模式串）。
    congestion: crate::congestion::CongestionConfig,
}

impl HysteriaServer {
    /// 绑定端点（不开始 accept）：`EndpointConfig` + 自签 TLS + ALPN=h3。
    pub fn bind(config: ServerConfig) -> Result<Self, ServerError> {
        // 配置校验先于任何 IO：未识别/非法值 fail-closed，且不受运行时约束。
        // 端点级 `TransportConfig` 保持 quinn 默认 CUBIC：参考在认证后按
        // `min(BrutalUp, clientDown)` 逐连接装配（hub.go 187-205），quinn 0.11
        // 没有连接期替换入口 ⇒ 由本端 TCP 端口做用户态节流（见 `wire`）。
        crate::congestion::parse_mode(&config.congestion)?;
        let server_config = build_server_config(&config)?;
        if config.cert_chain_der.is_empty() || config.key_der.is_empty() {
            return Err(ServerError::MissingCredentials);
        }
        let socket = std::net::UdpSocket::bind(config.listen_addr)
            .map_err(|e| ServerError::Bind(e.to_string()))?;
        let runtime =
            quinn::default_runtime().ok_or_else(|| ServerError::Bind("无可用异步运行时".into()))?;
        let endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
                .map_err(|e| ServerError::Bind(e.to_string()))?;

        endpoint.set_server_config(Some(server_config));
        // `tx` = 本端发送速率 = 参考 `BrutalUp`（hub.go:187-205 的协商对象）。
        let congestion =
            crate::congestion::wire::local_config(&config.congestion, config.brutal_up)?;
        Ok(Self {
            endpoint,
            auth: Arc::new(config.auth),
            brutal_down: config.brutal_down,
            udp_enabled: config.udp_enabled,
            udp_idle_timeout_secs: config.udp_idle_timeout_secs,
            congestion,
        })
    }

    /// 实际绑定的地址（`port = 0` 时由系统分配）。
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        self.endpoint
            .local_addr()
            .map_err(|e| ServerError::Bind(e.to_string()))
    }

    /// 端点引用（诊断/关闭用）。
    #[must_use]
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// 关闭端点（对齐 `Listener.Close`：列表器与 pktConn 一并关闭）。
    pub fn close(&self) {
        self.endpoint
            .close(VarInt::from_u32(h3_auth::CLOSE_ERR_CODE_OK), b"");
    }

    /// 持续接受连接（对齐 `keepAccepting`），每连接一个服务例程。
    /// 端点关闭后返回。
    pub async fn accept_loop(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                // 服务例程不跨 await 持有 Arc<Self> 之外的状态；
                // `SessionCtx` 是每连接的共享状态。
                let ctx = ServerSessionCtx {
                    auth: Arc::clone(&server.auth),
                    brutal_down: server.brutal_down,
                    udp_enabled: server.udp_enabled,
                    udp_idle_timeout_secs: server.udp_idle_timeout_secs,
                    congestion: server.congestion,
                };
                let _ = crate::h3_server::serve_connection(conn.clone(), ctx).await;
                // 对齐 hub.go：ServeQUICConn 返回后 CloseWithError(closeErrCodeOK)
                conn.close(VarInt::from_u32(h3_auth::CLOSE_ERR_CODE_OK), b"");
            });
        }
    }
}

/// 每连接认证与承载上下文（等价 `hub.go` `httpHandler` 的不可变部分：
/// `config`/`quicParams`/`validator`）。可变部分（`auth` 标志、
/// 已认证用户）由 `h3_auth::serve_connection` 内部状态持有。
#[derive(Clone)]
pub struct ServerSessionCtx {
    /// 认证口令（fail-closed 比较；不得进入日志）。
    pub auth: Arc<String>,
    /// `Hysteria-CC-RX` 响应头取值（`quicParams.BrutalDown`）。
    pub brutal_down: u64,
    /// 是否开放 UDP datagram（`RequireDatagramFromContext` 服务端配置）。
    pub udp_enabled: bool,
    /// UDP 会话空闲超时（秒）。
    pub udp_idle_timeout_secs: u64,
    /// 拥塞参数载体（`tx` = 服务端发送速率 = 参考 `BrutalUp`），供逐连接
    /// 协商 `min(BrutalUp, clientDown)`（hub.go 194-200）。
    pub congestion: crate::congestion::CongestionConfig,
}

/// 构造 quinn 服务端配置：ALPN=h3、TLS1.3、无客户端证书验证。
fn build_server_config(config: &ServerConfig) -> Result<quinn::ServerConfig, ServerError> {
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let certs: Vec<CertificateDer<'static>> = config
        .cert_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let key = PrivateKeyDer::try_from(config.key_der.clone())
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    let mut tls = quinn::rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|e| ServerError::Tls(e.to_string()))?
        // 对齐参考：服务端侧未启用 `VerifyPeerCertificate`，客户端不验证
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC 要求 max_early_data_size 为 0 或 u32::MAX。
    tls.max_early_data_size = u32::MAX;

    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    let mut quic = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));

    let mut transport = quinn::TransportConfig::default();
    // EnableDatagrams + MaxDatagramFrameSize（对齐 hub.go 的 quic.Config）。
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.max_idle_timeout(Some(quinn::IdleTimeout::from(VarInt::from_u32(
        DEFAULT_MAX_IDLE_TIMEOUT_MS,
    ))));
    // 流接收窗口：hub.go 缺省 Init/MaxStreamReceiveWindow = 8MiB，
    // Init/MaxConnReceiveWindow = 8MiB * 5 / 2。
    transport.stream_receive_window(VarInt::from_u32(8 * 1024 * 1024));
    transport.receive_window(VarInt::from_u32(8 * 1024 * 1024 * 5 / 2));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(DEFAULT_MAX_INCOMING_STREAMS));
    // 服务端发送方向：参考在认证后逐连接 `UseBrutal(min(BrutalUp, clientDown))`
    // （hub.go:187-205）；quinn 端点级 `TransportConfig` 先于该头到达、也没有
    // 连接期替换入口 ⇒ 由 TCP 端口按同一协商结果节流（`congestion::wire`）。
    quic.transport_config(Arc::new(transport));
    Ok(quic)
}
