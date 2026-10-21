//! 服务端 UDP 会话表、发送句柄与分发循环。

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::h3_auth::SeedFiller;

use super::constants::{UDP_IDLE_CLEANUP_INTERVAL_SECS, UDP_MESSAGE_CHAN_SIZE, UDP_SESSION_ID_LEN};

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
