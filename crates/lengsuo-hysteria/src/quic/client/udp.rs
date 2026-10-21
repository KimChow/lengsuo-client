//! 客户端 UDP 会话表、发送种子池与 UDP 会话句柄。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::h3_auth::SeedFiller;

/// 会话表 + 发送种子池（对齐 `udpSessionManagerClient`）。单锁足够：
/// 临界区只有查表投递与种子存取，无 IO。
pub(super) struct UdpManager {
    pub(super) next_id: u32,
    pub(super) sessions: HashMap<u32, mpsc::Sender<Vec<u8>>>,
    pub(super) closed: bool,
    /// 可复用发送缓冲（Bytes 桥）；上限防无人发送时无限增长。
    pub(super) seeds: Vec<SeedFiller>,
}

/// 种子池上限：超过即丢弃新种子（发送侧一次取一个，正常场景远低于此）。
const MAX_SEEDS: usize = 256;

impl UdpManager {
    /// 投递整条 datagram（含前 4 字节会话 ID，解析方按完整报文处理，
    /// 对齐 Go `feed(id, d)` 不剥头）。通道满即丢（Go select-default）。
    pub(super) fn feed(&mut self, id: u32, datagram: &[u8]) {
        if let Some(tx) = self.sessions.get(&id) {
            let _ = tx.try_send(datagram.to_vec());
        }
    }

    pub(super) fn push_seed(&mut self, filler: SeedFiller) {
        if self.seeds.len() < MAX_SEEDS {
            self.seeds.push(filler);
        }
    }

    pub(super) fn close_all(&mut self) {
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
    pub(super) rx: mpsc::Receiver<Vec<u8>>,
    pub(super) conn: quinn::Connection,
    pub(super) udp: Arc<Mutex<UdpManager>>,
}

impl UdpSession {
    /// 收一条完整 datagram（含 4 字节会话 ID 前缀）。会话关闭返回 None。
    pub async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// 发送一条已含会话 ID 前缀的 datagram（同步，对齐 quinn 的
    /// `send_datagram`）。优先复用种子池里的独占缓冲；池为空时退回
    /// [`crate::h3_auth::send_datagram_direct`]（每调用分配一次）。分片判断
    /// 请先用 [`UdpSession::max_datagram_size`]。
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
