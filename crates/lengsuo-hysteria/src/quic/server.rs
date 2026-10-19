//! quinn 服务端端点与 QUIC 连接（对齐 `transport/internet/hysteria/hub.go`
//! 的 `Listener`/`handleClient`/`udpSessionManagerServer`）。
//!
//! 建连流程与参考一致：`Endpoint::new` 绑定 UDP → rustls（ALPN=h3，
//! 无客户端证书验证 `with_no_client_auth`，对齐 `tlsConfig.GetTLSConfig()`
//! 未启用 `VerifyPeerCertificate` 的服务端路径）→ QUIC 握手 →
//! 每连接一个 HTTP/3 服务例程（见 `h3_auth::serve_connection`）。
//!
//! 与参考的实现性差异（详见 docs 偏离清单）：
//! - 拥塞控制用 quinn 默认（BBR/Brutal 不移植）；
//! - UDP 发送经 `h3_auth::SeedFiller` 桥（依赖冻结拿不到 `bytes` crate，
//!   `send_datagram` 只接受 `Bytes`；复用接收路径返回的独占缓冲，见
//!   `h3_auth` 模块文档）；
//! - masquerade 只实现参考的缺省分支（404），`file`/`proxy`/`string`
//!   需要 Xray 的配置/HTTP 栈，不在本卡范围。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::VarInt;
use tokio::sync::mpsc;

use crate::h3_auth::{self, SeedFiller};

/// QUIC datagram 上的会话 ID 长度（字节），对齐 `udpSessionManagerServer.run`
/// 的 `len(d) < 4` 判据与 `binary.BigEndian.Uint32(d[:4])`。
pub const UDP_SESSION_ID_LEN: usize = 4;
/// 会话分发通道容量，对齐 `config.go` `udpMessageChanSize`。
pub const UDP_MESSAGE_CHAN_SIZE: usize = 1024;
/// 服务端 UDP 会话空闲回收周期，对齐 `hub.go` `idleCleanupInterval`。
pub const UDP_IDLE_CLEANUP_INTERVAL_SECS: u64 = 5;
/// 服务端 UDP 会话空闲超时缺省值（秒），对齐 `config.go` `UdpIdleTimeout`。
pub const DEFAULT_UDP_IDLE_TIMEOUT_SECS: u64 = 60;
/// QUIC 最大空闲超时缺省值（毫秒），对齐 `hub.go` `quicParams.MaxIdleTimeout`。
pub const DEFAULT_MAX_IDLE_TIMEOUT_MS: u32 = 30_000;
/// 最大入站流数缺省值，对齐 `hub.go` `quicParams.MaxIncomingStreams`。
pub const DEFAULT_MAX_INCOMING_STREAMS: u32 = 1024;

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
    /// 服务端 Brutal 下行带宽（bps），回给客户端的 `Hysteria-CC-RX`
    /// 即 `quicParams.BrutalDown`。
    pub brutal_down: u64,
    /// 是否开放 UDP datagram（对齐 `hyCtx.RequireDatagramFromContext` 的
    /// 服务端侧配置：由入站设置决定，不由客户端请求头决定）。
    pub udp_enabled: bool,
    /// UDP 会话空闲超时（秒），对齐 `Config.UdpIdleTimeout`。
    pub udp_idle_timeout_secs: u64,
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
            udp_enabled: true,
            udp_idle_timeout_secs: DEFAULT_UDP_IDLE_TIMEOUT_SECS,
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
}

/// 已绑定的 Hysteria2 服务端（等价 `hub.go` `Listener`）。
pub struct HysteriaServer {
    endpoint: quinn::Endpoint,
    auth: Arc<String>,
    brutal_down: u64,
    udp_enabled: bool,
    udp_idle_timeout_secs: u64,
}

impl HysteriaServer {
    /// 绑定端点（不开始 accept）：`EndpointConfig` + 自签 TLS + ALPN=h3。
    pub fn bind(config: ServerConfig) -> Result<Self, ServerError> {
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

        endpoint.set_server_config(Some(build_server_config(&config)?));
        Ok(Self {
            endpoint,
            auth: Arc::new(config.auth),
            brutal_down: config.brutal_down,
            udp_enabled: config.udp_enabled,
            udp_idle_timeout_secs: config.udp_idle_timeout_secs,
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
    quic.transport_config(Arc::new(transport));
    Ok(quic)
}

/// 服务端 UDP 会话句柄（对齐 `InterUdpConn`）：接收整条 datagram
/// （含前 4 字节会话 ID 前缀，分发器不剥头）。
pub struct UdpInboundSession {
    /// 本会话 ID（`udpSessionManagerServer.feed` 的 `d[:4]`）。
    pub id: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    /// 发送句柄：可克隆，供回程任务与主循环共享（对齐 `InterUdpConn.Write`）。
    send: UdpSendHandle,
}

/// 服务端 UDP 会话表 + 发送种子池（对齐 `udpSessionManagerServer`）。
/// 单锁足够：临界区只有查表投递与种子存取，无 IO。
pub(crate) struct UdpManager {
    sessions: std::collections::HashMap<u32, mpsc::Sender<Vec<u8>>>,
    /// 会话最后活跃时刻（对齐 `InterUdpConn.last`，用于空闲回收）。
    last_seen: std::collections::HashMap<u32, std::time::Instant>,
    /// 会话建立时把句柄交付应用层（对齐 `addConn(udpConn)`）。
    deliver_tx: mpsc::Sender<UdpInboundSession>,
    closed: bool,
    /// 可复用发送缓冲（Bytes 桥）；上限防无人发送时无限增长。
    seeds: Vec<SeedFiller>,
}

/// 种子池上限：超过即丢弃新种子。
const MAX_SEEDS: usize = 256;

impl UdpManager {
    /// 新会话表；`deliver_tx` 用于把新建会话交给应用层
    /// （对齐 `addConn(udpConn)` 把 `InterUdpConn` 交给 Xray）。
    pub(crate) fn new(deliver_tx: mpsc::Sender<UdpInboundSession>) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            last_seen: std::collections::HashMap::new(),
            deliver_tx,
            closed: false,
            seeds: Vec::new(),
        }
    }

    /// 投递整条 datagram（含 4 字节会话 ID，对齐 Go `feed` 不剥头）。
    /// 通道满即丢（Go select-default）。未知会话按参考新建。
    pub(crate) fn feed(
        &mut self,
        conn: &quinn::Connection,
        id: u32,
        datagram: &[u8],
        udp: &Arc<Mutex<UdpManager>>,
    ) {
        if !self.closed {
            self.last_seen.insert(id, std::time::Instant::now());
        }
        if let Some(tx) = self.sessions.get(&id) {
            let _ = tx.try_send(datagram.to_vec());
            return;
        }
        // 未知会话：新建（对齐参考 feed 的二次加锁路径），交给应用层。
        let (tx, rx) = mpsc::channel(UDP_MESSAGE_CHAN_SIZE);
        let _ = tx.try_send(datagram.to_vec());
        self.sessions.insert(id, tx);
        let _ = self.deliver_tx.try_send(UdpInboundSession {
            id,
            rx,
            send: UdpSendHandle {
                id,
                conn: conn.clone(),
                udp: Arc::clone(udp),
            },
        });
    }

    /// 补种：把可复用发送缓冲放入池（见 `h3_auth::SeedFiller`）。
    pub(crate) fn push_seed(&mut self, filler: SeedFiller) {
        if self.seeds.len() < MAX_SEEDS {
            self.seeds.push(filler);
        }
    }

    /// 空闲回收（对齐 `udpSessionManagerServer.clean`）：超过 `idle_secs`
    /// 未活跃的会话从表中删除（发送通道随之关闭 → 应用层 `recv_raw` 得 None）。
    pub(crate) fn clean(&mut self, idle_secs: u64) {
        let now = std::time::Instant::now();
        let stale: Vec<u32> = self
            .last_seen
            .iter()
            .filter(|(_, t)| now.duration_since(**t).as_secs() >= idle_secs)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.sessions.remove(&id);
            self.last_seen.remove(&id);
        }
    }

    /// 关闭全部会话（对齐 `run` 收尾：连接断开 → close 所有 udpConn）。
    pub(crate) fn close_all(&mut self) {
        self.closed = true;
        self.sessions.clear();
        self.last_seen.clear();
        self.seeds.clear();
    }
}

/// UDP 发送错误（服务端侧，与客户端 `UdpSendError` 同构）。
#[derive(Debug, thiserror::Error)]
pub enum UdpSendError {
    #[error("QUIC 连接已断开: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("datagram 过大（{len} 字节），对端上限不足")]
    TooLarge { len: usize },
    #[error("发送缓冲池为空：尚无可复用的独占 Bytes（依赖冻结限制，见 h3_auth::SeedFiller）")]
    NoSeedBuffer,
    #[error("对端/本端未启用 QUIC datagram: {0}")]
    Unsupported(String),
}

impl UdpInboundSession {
    /// 收一条完整 datagram（含 4 字节会话 ID 前缀）。会话关闭返回 None。
    pub async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// 可克隆的发送句柄（回程任务用）。
    #[must_use]
    pub fn sender(&self) -> UdpSendHandle {
        self.send.clone()
    }

    /// 发送一条已含会话 ID 前缀的 datagram（对齐 `InterUdpConn.Write`）。
    pub fn send_raw(&self, datagram: &[u8]) -> Result<(), UdpSendError> {
        self.send.send_raw(datagram)
    }

    /// 对端协商的 datagram 大小上限（含 4 字节会话 ID 前缀与消息头）。
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.send.max_datagram_size()
    }
}

/// 服务端 UDP 会话发送句柄（`InterUdpConn.Write` 的等价物）：可跨任务克隆，
/// 发送缓冲取自管理器种子池（Bytes 桥，见 `h3_auth::SeedFiller`）。
#[derive(Clone)]
pub struct UdpSendHandle {
    id: u32,
    conn: quinn::Connection,
    udp: Arc<Mutex<UdpManager>>,
}

impl UdpSendHandle {
    /// 本句柄对应的会话 ID。
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// 发送一条已含会话 ID 前缀的 datagram（对齐 `InterUdpConn.Write`）。
    ///
    /// 优先复用种子池里的独占缓冲（省一次分配）；池为空时退回
    /// [`crate::h3_auth::send_datagram_direct`]（每调用分配一次）。
    /// 服务端接收的 datagram 常为共享引用（`try_into_mut` 失败），
    /// 因此直接发送是常规路径而非错误。
    pub fn send_raw(&self, datagram: &[u8]) -> Result<(), UdpSendError> {
        let filler = self.udp.lock().expect("UDP 管理器锁中毒").seeds.pop();
        let sent = match filler {
            Some(mut filler) => filler(&self.conn, datagram),
            None => crate::h3_auth::send_datagram_direct(&self.conn, datagram),
        };
        sent.map_err(|e| match e {
            quinn::SendDatagramError::TooLarge => UdpSendError::TooLarge {
                len: datagram.len(),
            },
            quinn::SendDatagramError::ConnectionLost(e) => UdpSendError::Connection(e),
            quinn::SendDatagramError::UnsupportedByPeer => {
                UdpSendError::Unsupported("对端未协商 datagram 扩展".into())
            }
            quinn::SendDatagramError::Disabled => {
                UdpSendError::Unsupported("本端未启用 datagram".into())
            }
        })
    }

    /// 对端协商的 datagram 大小上限（含 4 字节会话 ID 前缀与消息头）。
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }
}

/// 服务端 UDP 会话分发循环（对齐 `udpSessionManagerServer.run` 与
/// `clean`）：按前 4 字节会话 ID 分发（`len(d) < 4` 丢弃），未知会话新建并
/// 交付应用层；连接错误时关闭全部会话并结束。会话空闲回收用 `clean` 的
/// ticker 语义（`UDP_IDLE_CLEANUP_INTERVAL_SECS`）。
pub(crate) async fn run_udp_manager(
    conn: &quinn::Connection,
    idle_timeout_secs: u64,
    udp: &Arc<Mutex<UdpManager>>,
    mut deliver_rx: mpsc::Receiver<UdpInboundSession>,
    max_datagram_size: usize,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        UDP_IDLE_CLEANUP_INTERVAL_SECS,
    ));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            datagram = conn.read_datagram() => {
                let Ok(d) = datagram else { break };
                if d.len() < UDP_SESSION_ID_LEN {
                    continue;
                }
                let id = u32::from_be_bytes(
                    d[..UDP_SESSION_ID_LEN].try_into().expect("已检查长度"),
                );
                // 种子池补种（Bytes 桥）：独占缓冲复用为下一条发送缓冲。
                let mut guard = udp.lock().expect("UDP 管理器锁中毒");
                match d.try_into_mut() {
                    Ok(mut m) => {
                        // 先补种再分发：新建会话的子任务会立刻尝试回发，
                        // 若先 feed 后 push_seed 会与子任务竞争种子池
                        //（子任务可能先取走 → NoSeedBuffer）。
                        let payload = m.to_vec();
                        guard.push_seed(Box::new(move |conn, payload| {
                            m.clear();
                            m.extend_from_slice(payload);
                            conn.send_datagram(std::mem::take(&mut m).freeze())
                        }));
                        guard.feed(conn, id, &payload, udp);
                    }
                    Err(d) => guard.feed(conn, id, &d, udp),
                }
            }
            Some(session) = deliver_rx.recv() => {
                // 会话交付（对齐 `addConn(udpConn)` → Process 协程）：
                // 起一个承载循环；`max_datagram_size` 为该连接协商上限。
                tokio::spawn(async move {
                    let _ = crate::proxy::serve_udp_session(session, max_datagram_size).await;
                });
            }
            _ = ticker.tick() => {
                udp.lock().expect("UDP 管理器锁中毒").clean(idle_timeout_secs);
            }
        }
    }
    udp.lock().expect("UDP 管理器锁中毒").close_all();
}
