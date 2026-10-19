//! UDP 传输层包装：Salamander 混淆与端口跳跃
//! （对照参考 `transport/internet/hysteria/dialer.go` 里
//! `udphop.NewUDPHopPacketConn` → `udpmaskManager.WrapPacketConnClient`
//! 的包装顺序，以及 `finalmask/salamander/conn.go` 的 `salamanderConn`）。
//!
//! 参考的封装顺序是「先端口跳跃、再混淆」：混淆层拿到的是跳跃层之上的
//! 整条 datagram，混淆后的字节再交给跳跃层选端口写出。这里用
//! [`HopSocket`] 复刻同一顺序：`HopSocket::send_to` 先在内部完成混淆，
//! 再把混淆后的报文交给轮换端口。
//!
//! 偏离（详见 docs/hysteria-status.md 偏离清单）：
//! - 参考的 hopping 建的是 **新 socket**（`ListenUDPFunc`），服务端必须
//!   在整段端口上分别监听；本项目冻结的依赖集只有 `tokio` 的 `UdpSocket`，
//!   无法绑定「多个本地端口」之外的等价物，因此 [`HopSocket`] 只轮换
//!   **远端端口**，本地 socket 单一（等价于把 `ListenUDPFunc` 换成复用
//!   同一 socket）。这只影响客户端本地端口选择，不影响 hop 语义。
//! - 参考用 `math/rand.Intn` 选端口、`crypto.RandBetween` 抽 hop 间隔；
//!   这里两者都由调用方注入的 [`TransportRng`] 提供，默认走
//!   `getrandom`（非 `unsafe` 的 OS 熵源）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::obfs::{self, Obfuscator};
use crate::transport::hop::{self, HopScheduler, HopSpec};
use crate::transport::TransportRng;

/// 端口跳跃最小间隔（秒），对照参考 `NewUDPHopPacketConn` 的 `< 5` 拒绝。
pub const MIN_HOP_INTERVAL_SECS: u64 = 5;

/// 跳跃/混淆传输的错误。错误文本不包含口令。
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("口径过短：{0}")]
    Psk(#[from] obfs::PskTooShort),
    #[error("端口区间非法：{0}")]
    Hop(#[from] hop::HopError),
}

/// 带 Salamander 混淆与（可选）端口跳跃的 UDP 发送套接字。
///
/// - `send(&self, payload)`：把应用层明文装成 datagram（混淆后）并按
///   当前端口写出；
/// - `recv_with`：由调用方给出「原始 datagram → 解混淆」的路径，
///   见 [`HopSocket::open`] 的 `recv` 参数。
pub struct HopSocket {
    socket: Arc<tokio::net::UdpSocket>,
    remote: SocketAddr,
    obfs: Option<Arc<Obfuscator>>,
    hop: Option<HopScheduler>,
    /// 当前远端端口（未跳端口时等于 `remote`）。
    current: Arc<std::sync::Mutex<SocketAddr>>,
}

impl HopSocket {
    /// 包装一个已连接的 UDP 套接字。
    ///
    /// `psk` 非空即启用 Salamander 混淆（对照 `finalmask` 配置里的
    /// `salamander.password`）；`hop` 给出端口区间与间隔，
    /// 与参考一致地由 [`HopScheduler`] 负责轮换。
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        remote: SocketAddr,
        psk: Option<Vec<u8>>,
        hop: Option<HopSpec>,
        rng: Arc<dyn TransportRng>,
    ) -> Result<Self, TransportError> {
        let obfs = match psk {
            Some(psk) => Some(Arc::new(Obfuscator::new(psk, Arc::clone(&rng))?)),
            None => None,
        };
        let hop = match hop {
            Some(spec) => Some(HopScheduler::new(spec, rng)?),
            None => None,
        };
        Ok(Self {
            socket,
            remote,
            obfs,
            hop,
            current: Arc::new(std::sync::Mutex::new(remote)),
        })
    }

    /// 当前目标地址（未跳端口即包装时的远端）。
    #[must_use]
    pub fn current_remote(&self) -> SocketAddr {
        *self.current.lock().expect("hop 状态锁中毒")
    }

    /// 是否启用混淆。
    #[must_use]
    pub fn obfuscated(&self) -> bool {
        self.obfs.is_some()
    }

    /// 是否启用端口跳跃。
    #[must_use]
    pub fn hopping(&self) -> bool {
        self.hop.is_some()
    }

    /// 启动跳跃循环（对照参考 `hopLoop` 的 ticker 周期）。
    /// 调度器关闭后循环退出。
    pub fn spawn_hop_loop(&self) -> Option<tokio::task::JoinHandle<()>> {
        let scheduler = Arc::new(self.hop.as_ref()?.clone());
        let dest = Arc::clone(&self.current);
        let base = self.remote;
        Some(tokio::spawn(async move {
            loop {
                let interval = scheduler.interval();
                if interval.is_zero() {
                    return;
                }
                tokio::time::sleep(interval).await;
                if scheduler.is_closed() {
                    return;
                }
                scheduler.next_hop();
                *dest.lock().expect("hop 状态锁中毒") = scheduler.current_dest(&base);
            }
        }))
    }

    /// 发送一条应用层明文（内部完成混淆）。
    pub async fn send(&self, payload: &[u8]) -> std::io::Result<usize> {
        match &self.obfs {
            Some(o) => {
                let mut buf = vec![0u8; payload.len() + obfs::SALT_LEN];
                let Some(n) = o.obfuscate(payload, &mut buf) else {
                    // 缓冲够大时不可达；真发生则视为发送失败，绝不发明文。
                    return Err(std::io::Error::other(
                        "混淆缓冲不足（长度计算不一致）",
                    ));
                };
                self.socket.send_to(&buf[..n], self.current_remote()).await
            }
            None => self.socket.send_to(payload, self.current_remote()).await,
        }
    }

    /// 解混淆一条收到的 datagram；未启用混淆时原样返回。
    /// 解混淆失败（长度不足/口令不符导致的解码失败）返回 `None`，
    /// 调用方必须丢弃该报文（fail-closed，绝不回退明文）。
    #[must_use]
    pub fn open(&self, raw: &[u8]) -> Option<Vec<u8>> {
        match &self.obfs {
            Some(o) => {
                let mut out = vec![0u8; raw.len().saturating_sub(obfs::SALT_LEN)];
                let n = o.deobfuscate(raw, &mut out)?;
                out.truncate(n);
                Some(out)
            }
            None => Some(raw.to_vec()),
        }
    }

    /// 合并参考 `hopLoop` 与 `salamanderConn` 的接收语义：等待一跳并
    /// 推进调度器（供测试注入时钟）。
    pub async fn wait_hop(&self, timeout: Duration) -> bool {
        let Some(scheduler) = &self.hop else {
            return false;
        };
        scheduler.wait_hop(timeout).await
    }
}
