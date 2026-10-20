//! quinn 客户端端点与 QUIC 连接（对齐 `transport/internet/hysteria/dialer.go`
//! 的 `client.dial`/`client.tcp`/`client.udp` 与 `conn.go`）。
//!
//! 建连流程与参考一致：绑定本机 UDP 端口 → rustls（ALPN=h3，证书验证
//! 默认开启，自签 CA 通过 `roots` 注入仍走完整验证链）→ QUIC 握手 →
//! HTTP/3 认证 → 按需提供 TCP 双向流 / UDP datagram 会话。
//!
//! 与参考的实现性差异（详见 docs 偏离清单）：
//! - 拥塞控制用 quinn 默认（BBR/Brutal 不移植），`Hysteria-CC-RX`
//!   请求头仍按参考发送、响应头仍解析保存；
//! - UDP 发送经 `h3_auth::SeedFiller` 桥（依赖冻结拿不到 `bytes` crate，
//!   `send_datagram` 只接受 `Bytes`；复用接收路径返回的独占缓冲，见
//!   `h3_auth` 模块文档），接收侧分发完整实现。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use quinn::rustls::pki_types::CertificateDer;
use quinn::VarInt;
use tokio::sync::mpsc;

use super::early::{self, EarlyDataConfig, MemorySessionCache, SessionCache, ZeroRttStatus};
use crate::h3_auth::{self, AuthOutcome, H3ControlStreams, SeedFiller};

/// QUIC datagram 上的会话 ID 长度（字节），对齐 `InterUdpConn.Write` 的前缀。
pub const UDP_SESSION_ID_LEN: usize = 4;
/// 会话分发通道容量，对齐 `config.go` `udpMessageChanSize`。
pub const UDP_MESSAGE_CHAN_SIZE: usize = 1024;
/// 客户端首个 UDP 会话 ID 从 1 开始（dialer.go `next: 1`）。
pub const FIRST_UDP_SESSION_ID: u32 = 1;

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
    /// `Hysteria-CC-RX` 请求头取值（Brutal 下行带宽；0 表示未设置）。
    pub brutal_down: u64,
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
    Auth(#[from] h3_auth::AuthError),
    #[error("服务端未声明支持 UDP（Hysteria-UDP 响应头为假）")]
    UdpUnsupported,
    #[error("0-RTT 配置失败: {0}")]
    EarlyData(#[from] early::EarlyDataError),
}

impl ConnectError {
    /// 认证被拒（HTTP 状态非 233）时返回状态码，供上层区分。
    #[must_use]
    pub fn rejected_status(&self) -> Option<u16> {
        match self {
            ConnectError::Auth(h3_auth::AuthError::Rejected { status }) => Some(*status),
            _ => None,
        }
    }
}

/// 已认证的 Hysteria2 QUIC 连接（等价 dialer.go `client` 认证成功后的状态）。
pub struct HysteriaClient {
    conn: quinn::Connection,
    udp_enabled: bool,
    /// 认证响应的 `Hysteria-CC-RX`（保留供上层拥塞决策）。
    server_cc_rx: u64,
    /// HTTP/3 控制流必须保活，drop 即FIN会被视为协议错误。
    _h3: H3ControlStreams,
    udp: Arc<Mutex<UdpManager>>,
    /// 0-RTT 结果观察器（未启用/未尝试时立即解析为 `NotAttempted`）。
    zero_rtt: ZeroRttStatus,
}

impl HysteriaClient {
    /// 建立端点、完成 TLS+QUIC 握手与 H3 认证（0-RTT 关闭）。
    pub async fn connect(config: ClientConfig) -> Result<Self, ConnectError> {
        Self::connect_with_early_data(config, EarlyDataConfig::default()).await
    }

    /// 以显式 0-RTT 配置建连。`enabled = false` 时代码路径与 [`Self::connect`]
    /// 完全一致（仍走普通 1-RTT 握手，不设置任何 rustls 早数据字段）。
    pub async fn connect_with_early_data(
        config: ClientConfig,
        early: EarlyDataConfig,
    ) -> Result<Self, ConnectError> {
        let cache = early.enabled.then(|| {
            Arc::new(MemorySessionCache::new(early.resumption_capacity)) as Arc<dyn SessionCache>
        });
        Self::connect_inner(config, &early, cache).await
    }

    /// 使用调用方显式持有的 [`SessionCache`] 建连，使票据可跨多次连接复用
    /// （第二次连接才可能命中恢复、进入 0-RTT）。
    pub async fn connect_with_session_cache(
        config: ClientConfig,
        early: EarlyDataConfig,
        cache: Arc<dyn SessionCache>,
    ) -> Result<Self, ConnectError> {
        Self::connect_inner(config, &early, Some(cache)).await
    }

    async fn connect_inner(
        config: ClientConfig,
        early: &EarlyDataConfig,
        cache: Option<Arc<dyn SessionCache>>,
    ) -> Result<Self, ConnectError> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| ConnectError::Bind(e.to_string()))?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| ConnectError::Bind("无可用异步运行时".into()))?;
        let mut endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
                .map_err(|e| ConnectError::Bind(e.to_string()))?;

        let tls = build_tls_config(&config, early, cache)?;
        let mut quic_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| ConnectError::Tls(e.to_string()))?,
        ));
        let mut transport = quinn::TransportConfig::default();
        // EnableDatagrams: true（quinn 侧：声明接收缓冲即启用 datagram；
        // 发送上限由对端传输参数协商，超限返回 TooLarge 错误）
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        // MaxIdleTimeout 默认 30s（dialer.go）
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(VarInt::from_u32(30_000))));
        quic_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(quic_config);

        let connecting = endpoint
            .connect(config.server_addr, &config.server_name)
            .map_err(|e| ConnectError::Bind(e.to_string()))?;
        // 对齐 dialer.go 的 `quic.DialEarly`：有恢复票据时立即进入 0-RTT；
        // `Err` 表示本端无法发早数据，退回普通握手（显式记日志）。
        let (conn, zero_rtt) = if early.enabled {
            match connecting.into_0rtt() {
                Ok((conn, accepted)) => {
                    let status = ZeroRttStatus::attempted();
                    let watcher = status.clone();
                    tokio::spawn(async move { watcher.record(accepted.await) });
                    (conn, status)
                }
                Err(connecting) => {
                    eprintln!(
                        "[lengsuo-hysteria] 0-RTT 不可用（本端无可用会话票据），回退 1-RTT 握手"
                    );
                    (connecting.await?, ZeroRttStatus::not_attempted())
                }
            }
        } else {
            (connecting.await?, ZeroRttStatus::not_attempted())
        };

        let auth = h3_auth::authenticate(&conn, &config.auth, config.brutal_down).await;
        let (
            AuthOutcome {
                udp_enabled,
                server_cc_rx,
            },
            mut h3,
        ) = match auth {
            Ok(v) => v,
            Err(e) if e.is_zero_rtt_rejected() => {
                // 早数据被拒：握手结果必须先落成可观测状态，再在同一连接上
                // 以 1-RTT 重放认证。认证请求幂等，重放不产生额外副作用。
                let outcome = zero_rtt.wait().await;
                eprintln!(
                    "[lengsuo-hysteria] 服务端拒绝 0-RTT（{outcome:?}），在 1-RTT 上重放认证请求"
                );
                h3_auth::authenticate(&conn, &config.auth, config.brutal_down).await?
            }
            Err(e) => return Err(e.into()),
        };

        // 认证响应 chunk 派生的发送种子（见 h3_auth::SeedFiller）注入池，
        // 供首条 UDP datagram 发送；之后每收到一条服务端 datagram 再补种。
        let udp = Arc::new(Mutex::new(UdpManager {
            next_id: FIRST_UDP_SESSION_ID,
            sessions: HashMap::new(),
            closed: false,
            seeds: h3.take_seeds(),
        }));
        if udp_enabled {
            // 对齐 udpSessionManagerClient.run：datagram → 会话 ID 分发；
            // 未知/非法报文丢弃；连接错误时关闭全部会话。
            let dispatcher_conn = conn.clone();
            let dispatcher_udp = Arc::clone(&udp);
            tokio::spawn(async move {
                while let Ok(d) = dispatcher_conn.read_datagram().await {
                    // 补种：独占的接收缓冲复用为下一条发送缓冲（Bytes 桥）；
                    // 引用共享时无法补种，只走分发路径。
                    match d.try_into_mut() {
                        Ok(mut m) => {
                            if m.len() >= UDP_SESSION_ID_LEN {
                                let id = u32::from_be_bytes(
                                    m[..UDP_SESSION_ID_LEN].try_into().expect("已检查长度"),
                                );
                                dispatcher_udp
                                    .lock()
                                    .expect("UDP 管理器锁中毒")
                                    .feed(id, &m);
                            }
                            dispatcher_udp
                                .lock()
                                .expect("UDP 管理器锁中毒")
                                .push_seed(Box::new(move |conn, payload| {
                                    m.clear();
                                    m.extend_from_slice(payload);
                                    conn.send_datagram(std::mem::take(&mut m).freeze())
                                }));
                        }
                        Err(d) => {
                            if d.len() >= UDP_SESSION_ID_LEN {
                                let id = u32::from_be_bytes(
                                    d[..UDP_SESSION_ID_LEN].try_into().expect("已检查长度"),
                                );
                                dispatcher_udp
                                    .lock()
                                    .expect("UDP 管理器锁中毒")
                                    .feed(id, &d);
                            }
                        }
                    }
                }
                dispatcher_udp.lock().expect("UDP 管理器锁中毒").close_all();
            });
        }
        // 排空服务端发起的单向流（控制流 SETTINGS、QPACK 流），
        // 避免对端流堆积；内容按协议忽略。
        let drain_conn = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut s) = drain_conn.accept_uni().await {
                let mut buf = [0u8; 4096];
                while matches!(s.read(&mut buf).await, Ok(Some(_))) {}
            }
        });

        Ok(Self {
            conn,
            udp_enabled,
            server_cc_rx,
            _h3: h3,
            udp,
            zero_rtt,
        })
    }

    /// 0-RTT 状态观察器；握手完成前可能仍为 pending（[`ZeroRttStatus::current`]
    /// 返回 `None`）。
    #[must_use]
    pub fn zero_rtt_status(&self) -> &ZeroRttStatus {
        &self.zero_rtt
    }

    /// 等待握手完成并返回 0-RTT 最终结果。拒绝路径返回
    /// [`early::ZeroRttOutcome::Rejected`]，**不会**静默当作 1-RTT 成功。
    pub async fn zero_rtt_outcome(&self) -> early::ZeroRttOutcome {
        self.zero_rtt.wait().await
    }

    /// 打开 TCP 承载流（双向流；首写 `0x401` 前缀由 `proxy` 层负责，
    /// 对齐 `interConn.Write` 的 client 分支）。
    pub async fn open_tcp(&self) -> Result<(quinn::SendStream, quinn::RecvStream), ConnectError> {
        self.conn.open_bi().await.map_err(ConnectError::from)
    }

    /// 打开 UDP 会话（QUIC datagram + 会话 ID，对齐 `client.udp`）。
    /// 服务端未声明 `Hysteria-UDP` 时报错，与参考一致。
    pub async fn open_udp(&self) -> Result<UdpSession, ConnectError> {
        if !self.udp_enabled {
            return Err(ConnectError::UdpUnsupported);
        }
        let (tx, rx) = mpsc::channel(UDP_MESSAGE_CHAN_SIZE);
        let id = {
            let mut m = self.udp.lock().expect("UDP 管理器锁中毒");
            if m.closed {
                return Err(ConnectError::Quic(quinn::ConnectionError::LocallyClosed));
            }
            let id = m.next_id;
            m.sessions.insert(id, tx);
            m.next_id = m.next_id.wrapping_add(1);
            id
        };
        Ok(UdpSession {
            id,
            rx,
            conn: self.conn.clone(),
            udp: Arc::clone(&self.udp),
        })
    }

    /// 认证响应里的服务端 `Hysteria-CC-RX`。
    #[must_use]
    pub fn server_cc_rx(&self) -> u64 {
        self.server_cc_rx
    }

    /// 服务端是否声明支持 UDP datagram。
    #[must_use]
    pub fn udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// QUIC 连接引用（诊断用）。
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }
}

/// rustls 客户端配置：ALPN 固定 h3，验证链完整开启；根为系统缺省 +
/// 注入 DER。`builder_with_provider(ring)` 对应工作区 rustls 特性。
fn build_tls_config(
    config: &ClientConfig,
    early: &EarlyDataConfig,
    cache: Option<Arc<dyn SessionCache>>,
) -> Result<quinn::rustls::ClientConfig, ConnectError> {
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    let builder = quinn::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ConnectError::Tls(e.to_string()))?;
    let mut roots = quinn::rustls::RootCertStore::empty();
    for der in &config.roots_der {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| ConnectError::Tls(e.to_string()))?;
    }
    let mut tls = builder.with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // 关闭时该调用不做任何修改（既有 1-RTT 路径逐字节一致）。
    early::configure_tls(&mut tls, early, cache)?;
    Ok(tls)
}

/// 会话表 + 发送种子池（对齐 `udpSessionManagerClient`）。单锁足够：
/// 临界区只有查表投递与种子存取，无 IO。
struct UdpManager {
    next_id: u32,
    sessions: HashMap<u32, mpsc::Sender<Vec<u8>>>,
    closed: bool,
    /// 可复用发送缓冲（Bytes 桥）；上限防无人发送时无限增长。
    seeds: Vec<SeedFiller>,
}

/// 种子池上限：超过即丢弃新种子（发送侧一次取一个，正常场景远低于此）。
const MAX_SEEDS: usize = 256;

impl UdpManager {
    /// 投递整条 datagram（含前 4 字节会话 ID，解析方按完整报文处理，
    /// 对齐 Go `feed(id, d)` 不剥头）。通道满即丢（Go select-default）。
    fn feed(&mut self, id: u32, datagram: &[u8]) {
        if let Some(tx) = self.sessions.get(&id) {
            let _ = tx.try_send(datagram.to_vec());
        }
    }

    fn push_seed(&mut self, filler: SeedFiller) {
        if self.seeds.len() < MAX_SEEDS {
            self.seeds.push(filler);
        }
    }

    fn close_all(&mut self) {
        self.closed = true;
        self.sessions.clear();
        self.seeds.clear();
    }
}

/// UDP 发送错误。
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

/// UDP 会话句柄（对齐 `InterUdpConn`）：接收来自分发器的整条 datagram，
/// 发送需自加 4 字节会话 ID 前缀（由 `proxy` 层的组包函数负责）。
pub struct UdpSession {
    /// 本会话 ID（发送时报文首 4 字节）。
    pub id: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    conn: quinn::Connection,
    udp: Arc<Mutex<UdpManager>>,
}

impl UdpSession {
    /// 收一条完整 datagram（含 4 字节会话 ID 前缀）。会话关闭返回 None。
    pub async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// 发送一条已含会话 ID 前缀的 datagram（同步，对齐 quinn 的
    /// `send_datagram`）。优先复用种子池里的独占缓冲；池为空时退回
    /// [`h3_auth::send_datagram_direct`]（每调用分配一次）。分片判断请先用
    /// [`UdpSession::max_datagram_size`]。
    pub fn send_raw(&self, datagram: &[u8]) -> Result<(), UdpSendError> {
        let filler = self.udp.lock().expect("UDP 管理器锁中毒").seeds.pop();
        let sent = match filler {
            Some(mut filler) => filler(&self.conn, datagram),
            None => h3_auth::send_datagram_direct(&self.conn, datagram),
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
