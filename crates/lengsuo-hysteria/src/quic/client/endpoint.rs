//! 已认证的 Hysteria2 QUIC 连接：建连、认证与通道开放。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use quinn::rustls::pki_types::CertificateDer;
use quinn::VarInt;
use tokio::sync::mpsc;

use lengsuo_congestion::Mode;

use crate::congestion::{Bandwidth, CcHeader};
use crate::h3_auth::{self, AuthOutcome, H3ControlStreams};

use super::config::{ClientConfig, ConnectError};
use super::constants::{FIRST_UDP_SESSION_ID, UDP_MESSAGE_CHAN_SIZE, UDP_SESSION_ID_LEN};
use super::udp::{UdpManager, UdpSession};
use crate::quic::early::{self, EarlyDataConfig, MemorySessionCache, SessionCache, ZeroRttStatus};

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

    /// 探测连接：用缺省配置建连并认证，读服务端 `Hysteria-CC-RX` 后立即关闭，
    /// 返回该值（字节/秒）。供 [`Self::connect_with_negotiated`] 的回填路径
    /// （`Hysteria-CC-RX` 要认证后才拿到，而 quinn 的拥塞器只能建连前装配）。
    pub async fn probe_peer_cc_rx(
        config: &ClientConfig,
        early: EarlyDataConfig,
    ) -> Result<CcHeader, ConnectError> {
        let probe = Self::connect_with_early_data(config.clone(), early).await?;
        let header = CcHeader::Bps(Bandwidth(probe.server_cc_rx()));
        probe.connection().close(VarInt::from_u32(0), b"probe");
        Ok(header)
    }

    /// 建连后通告本端下行容量（对齐 dialer.go 274：每个 TCP 请求头都带
    /// `Hysteria-CC-RX: BrutalDown`）。`congestion = "brutal"` 时在认证连接上
    /// 发一条**不带数据**的 TCPRequest（`congestion::announce_frame`），
    /// 服务端据此逐连接协商其发送速率 `min(BrutalUp, clientDown)`
    /// （hub.go 194-200）。其余模式不发送，行为与改动前一致。
    pub async fn connect_with_negotiated(
        config: ClientConfig,
        early: EarlyDataConfig,
    ) -> Result<Self, ConnectError> {
        if crate::congestion::parse_mode(&config.congestion)? != Some(Mode::Brutal) {
            return Self::connect_with_early_data(config, early).await;
        }
        let client = Self::connect_with_early_data(config.clone(), early).await?;
        let (mut send, _recv) = client.open_tcp().await?;
        if let Err(e) = send
            .write_all(&crate::congestion::announce_frame(config.brutal_down))
            .await
        {
            // 通告失败不致命：服务端按 `clientDown = 0` 回落（CUBIC）。
            eprintln!("[lengsuo-hysteria] 下行容量通告失败（服务端回落 CUBIC）：{e}");
        }
        let _ = send.finish();
        Ok(client)
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
        // 拥塞器（客户端发送方向，对齐 dialer.go 297-315）：模式未识别 ⇒
        // fail-closed；Brutal 取 `min(本端 up, 服务端 Hysteria-CC-RX)`。
        // quinn 只能在建连前装配 ⇒ 该头由 [`Self::probe_peer_cc_rx`] 在探测连接上
        // 取得，由调用方回填 `config.peer_cc_rx`；未回填 ⇒ 参考回落分支（CUBIC）。
        let mode = crate::congestion::parse_mode(&config.congestion)?;
        if let Some(peer) = config.peer_cc_rx {
            let rate = crate::congestion::client_rate(config.brutal_up, peer)?;
            crate::congestion::inject(&mut transport, mode, rate)?;
        }
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
