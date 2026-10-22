//! 真实出口运行时：把 [`OutboundRuntime`] 接到 `lengsuo_node` 的八协议出口。
//!
//! 依赖方向**单向** `lengsuo-tun → lengsuo-node`；本模块只调用 node 的
//! `relay_bridge::open_relay`（应用字节流 ⇄ 协议流的现成桥），**不重写**任何
//! 协议分帧：
//!
//! ```text
//! 设备 IP 报文 ──► tcp::listener（用户态 TCP 栈，解出应用载荷）
//!                        │  feed.delivered（应用字节）
//!                        ▼
//!              NodeOutboundRuntime::forward
//!                        │  OutboundWriter::send
//!                        ▼
//!       lengsuo_node::relay_bridge::open_relay（trojan/vless/… 协议流）
//! ```
//!
//! 回程方向由一条后台任务读 [`OutboundReader`]，把明文块放进有界通道，上层用
//! [`OutboundExchange::take_response`] 取走。
//!
//! ## 安全语义（全部 fail-closed）
//!
//! - 设备没有配置 ⇒ [`RuntimeError::NoProtocol`]，**没有默认直连**。
//! - 请求的协议与配置不一致 ⇒ [`RuntimeError::Unavailable`]，**不静默换协议**。
//! - wireguard 是 L3 隧道，node 的转发层明确不支持（`SessionError::Unsupported`），
//!   本运行时的 [`OutboundRuntime::is_available`] 直接判不可用，**不降级**。
//! - 建连失败 ⇒ [`RuntimeError::Dial`]；写失败或读侧已失败 ⇒ [`RuntimeError::Forward`]。
//!   两者都只让调用方丢弃报文，**绝不**回落到直连。
//! - 错误类型不携带口令、密钥或明文载荷：[`RuntimeError`] 只有固定标签。
//!
//! ## 运行时边界
//!
//! `OutboundRuntime` 是同步 trait，node 的会话 API 是异步的。本实现持有一个
//! 专属的多线程 tokio 运行时：`open` / `forward` / `release` 在调用线程
//! `block_on`，回程读任务在 worker 线程持续推进。
//!
//! ⚠️ 因此**不得**在 tokio 运行时上下文里调用这些同步方法：`block_on` 在异步
//! 上下文里会 panic（不能嵌套启动运行时），`Runtime::drop` 在异步上下文里也会
//! panic。本仓的调用方是同步事件循环（`bin/runtime_entry/runtime.rs`），符合该前提。

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_node::config::{NodeConfig, Protocol as NodeProtocol};
use lengsuo_node::forward::{OutboundReader, OutboundWriter};
use lengsuo_node::relay_bridge;
use ss_core::target::TargetAddr;
use tokio::sync::mpsc;

use super::authority::DeviceId;
use super::runtime::{
    OutboundExchange, OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError,
};

/// 回程读侧状态：会话仍可用 / 对端正常 EOF / 读侧失败。
const STATE_OPEN: u8 = 0;
const STATE_EOF: u8 = 1;
const STATE_FAILED: u8 = 2;

/// 回程块通道容量。每块最大 `COPY_BUF`，单会话最多缓冲这么多块。
const RESPONSE_QUEUE: usize = 64;

/// 一条已建立的出口会话。
struct Session {
    writer: Box<dyn OutboundWriter>,
    inbound: mpsc::Receiver<Vec<u8>>,
    state: Arc<AtomicU8>,
    reader_task: tokio::task::JoinHandle<()>,
}

/// 按设备配置真实协议出口的运行时。
pub struct NodeOutboundRuntime {
    rt: tokio::runtime::Runtime,
    wait: Duration,
    observe: Duration,
    /// 设备 → 节点配置。持有的是 node 侧已校验的配置（含凭据，只在内存中）。
    configs: BTreeMap<DeviceId, NodeConfig>,
    sessions: BTreeMap<u64, Session>,
    next_session: u64,
}

impl NodeOutboundRuntime {
    /// 由「设备 → 节点配置」表构造。
    ///
    /// 配置应来自 [`lengsuo_node::config::load_nodes`]（已逐条校验）；本构造函数
    /// 只做映射，不重复校验，也不触碰网络或平台状态。
    pub fn new(
        nodes: impl IntoIterator<Item = (DeviceId, NodeConfig)>,
        wait: Duration,
        observe: Duration,
    ) -> Result<Self, RuntimeError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| RuntimeError::Unavailable)?;
        Ok(Self {
            rt,
            wait,
            observe,
            configs: nodes.into_iter().collect(),
            sessions: BTreeMap::new(),
            next_session: 1,
        })
    }

    /// 当前持有的出口会话数（诊断「是否泄漏」用）。
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// 该设备的配置是否可经 node 转发层承载载荷。
    ///
    /// wireguard 是 L3 隧道（收发 IP 包），`forward::session::open` 显式拒绝。
    fn relayable(config: &NodeConfig) -> bool {
        !matches!(config.protocol, NodeProtocol::Wireguard)
    }
}

impl OutboundRuntime for NodeOutboundRuntime {
    fn protocol_of(&self, device: DeviceId) -> Option<OutboundProtocol> {
        self.configs
            .get(&device)
            .map(|config| outbound_protocol_of(config.protocol))
    }

    fn is_available(&self, device: DeviceId, protocol: OutboundProtocol) -> bool {
        let Some(config) = self.configs.get(&device) else {
            return false;
        };
        // 协议必须与配置一致（不静默换协议），且必须能经转发层承载。
        self.protocol_of(device) == Some(protocol) && Self::relayable(config)
    }

    fn open(
        &mut self,
        device: DeviceId,
        protocol: OutboundProtocol,
        target: SocketAddr,
    ) -> Result<OutboundSession, RuntimeError> {
        let Some(config) = self.configs.get(&device) else {
            return Err(RuntimeError::NoProtocol);
        };
        if !self.is_available(device, protocol) {
            return Err(RuntimeError::Unavailable);
        }
        let config = config.clone();
        let target_addr = target_addr_of(target);
        let wait = self.wait;

        // 建连失败 ⇒ Dial（fail-closed，绝不回落直连）。
        let live = self
            .rt
            .block_on(relay_bridge::open_relay(
                &config,
                &target_addr,
                wait,
                self.observe,
            ))
            .map_err(|_| RuntimeError::Dial)?;

        let mut reader: Box<dyn OutboundReader> = live.reader;
        let writer = live.writer;
        let state = Arc::new(AtomicU8::new(STATE_OPEN));
        let task_state = Arc::clone(&state);
        let (tx, inbound) = mpsc::channel(RESPONSE_QUEUE);
        // 回程读任务：协议分帧（vmess / ss2022 / anytls）由各协议的 `recv` 完成，
        // 这里只搬明文块，不解释协议。
        let reader_task = self.rt.spawn(async move {
            let mut buf = vec![0u8; lengsuo_node::forward::COPY_BUF];
            loop {
                match reader.recv(&mut buf, wait).await {
                    Ok(0) => {
                        task_state.store(STATE_EOF, Ordering::Release);
                        break;
                    }
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            // 上层已不再取回程（会话被释放）。
                            break;
                        }
                    }
                    Err(_) => {
                        task_state.store(STATE_FAILED, Ordering::Release);
                        break;
                    }
                }
            }
        });

        let id = self.next_session;
        self.next_session = self.next_session.wrapping_add(1);
        self.sessions.insert(
            id,
            Session {
                writer,
                inbound,
                state,
                reader_task,
            },
        );
        Ok(OutboundSession(id))
    }

    fn forward(&mut self, session: OutboundSession, packet: &[u8]) -> Result<(), RuntimeError> {
        // 拆开借用：`rt` 与 `sessions` 是互不相干的字段，可以同时可变借用。
        let Self {
            rt, wait, sessions, ..
        } = self;
        let Some(entry) = sessions.get_mut(&session.0) else {
            return Err(RuntimeError::UnknownSession);
        };
        // 读侧已失败说明会话整体已坏：不再写入，避免半死会话继续吞字节。
        if entry.state.load(Ordering::Acquire) == STATE_FAILED {
            return Err(RuntimeError::Forward);
        }
        rt.block_on(entry.writer.send(packet, *wait))
            .map_err(|_| RuntimeError::Forward)
    }

    fn release(&mut self, session: OutboundSession) {
        let Self {
            rt, wait, sessions, ..
        } = self;
        let Some(mut entry) = sessions.remove(&session.0) else {
            return;
        };
        if entry.state.load(Ordering::Acquire) == STATE_OPEN {
            // 正常结束：尽力发 FIN（半关闭写侧），读侧仍可收到残余数据。
            // 失败只意味着会话已断，不改变「释放」语义。
            let _ = rt.block_on(entry.writer.half_close(*wait));
        }
        entry.reader_task.abort();
        // writer 在此 drop：底层连接随之关闭。
    }
}

impl OutboundExchange for NodeOutboundRuntime {
    fn take_response(&mut self, session: OutboundSession) -> Option<Vec<u8>> {
        let sessions = &mut self.sessions;
        let entry = sessions.get_mut(&session.0)?;
        let mut out = Vec::new();
        while let Ok(chunk) = entry.inbound.try_recv() {
            out.extend_from_slice(&chunk);
        }
        (!out.is_empty()).then_some(out)
    }
}

/// node 的协议枚举 ⇒ tun 的出口协议枚举。
fn outbound_protocol_of(protocol: NodeProtocol) -> OutboundProtocol {
    match protocol {
        NodeProtocol::Trojan => OutboundProtocol::Trojan,
        NodeProtocol::AnyTls => OutboundProtocol::AnyTls,
        NodeProtocol::Vless => OutboundProtocol::Vless,
        NodeProtocol::Vmess => OutboundProtocol::Vmess,
        NodeProtocol::Shadowsocks => OutboundProtocol::Shadowsocks,
        NodeProtocol::Ss2022 => OutboundProtocol::Ss2022,
        NodeProtocol::Hysteria => OutboundProtocol::Hysteria,
        NodeProtocol::Wireguard => OutboundProtocol::Wireguard,
    }
}

/// `SocketAddr` ⇒ node 的目标地址（不解析域名：trait 只给 IP:port）。
fn target_addr_of(target: SocketAddr) -> TargetAddr {
    match target.ip() {
        std::net::IpAddr::V4(ip) => TargetAddr::V4(ip.octets(), target.port()),
        std::net::IpAddr::V6(ip) => TargetAddr::V6(ip.octets(), target.port()),
    }
}
