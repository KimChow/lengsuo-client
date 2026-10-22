//! 线上 datagram 层的混淆/跳跃「编解码 + 目标地址状态」。
//!
//! 参考形状（`transport/internet/hysteria/dialer.go:206-217`）：
//!   1. `udphop.NewUDPHopPacketConn(...)` —— 端口跳跃层（**内层**）
//!   2. `c.udpmaskManager.WrapPacketConnClient(pktConn)` —— 混淆层（**外层**）
//!
//! ⇒ 数据流向是「先混淆、再由跳跃层选端口写出」。
//!
//! 服务端（`hub.go:379-386`）**只包混淆**，没有跳跃层。
//!
//! 本模块只提供与传输载体无关的核心：混淆/解混淆 + 当前跳跃目标地址。
//! 真实链路上的载体见 `transport::socket`（`quinn::AsyncUdpSocket` 包装）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::obfs::{self, Obfuscator};
use crate::transport::hop::{HopError, HopScheduler, HopSpec};
use crate::transport::TransportRng;

/// 构造 [`WireMask`] 的错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error(transparent)]
    Psk(#[from] obfs::PskTooShort),
    #[error(transparent)]
    Hop(#[from] HopError),
}

/// datagram 层的混淆/跳跃状态。
///
/// - `obfs`：`Some` 时每条 datagram 都做 Salamander 混淆/解混淆；
/// - `hop`：`Some` 时发送目标端口按调度器轮换（对照参考 `hop()`：
///   在**全部端口**里均匀随机、**允许自跳**）。
pub struct WireMask {
    obfs: Option<Arc<Obfuscator>>,
    hop: Option<HopScheduler>,
    /// 当前远端地址（未跳端口时等于 `remote`）。
    current: Mutex<SocketAddr>,
    remote: SocketAddr,
}

impl WireMask {
    /// 构造。`psk` 非空即启用 Salamander（不足 4 字节 ⇒ `Err(Psk)`）；
    /// `hop` 给出端口区间与间隔（非法 ⇒ `Err(Hop)`）。
    pub fn new(
        remote: SocketAddr,
        psk: Option<Vec<u8>>,
        hop: Option<HopSpec>,
        rng: Arc<dyn TransportRng>,
    ) -> Result<Self, WireError> {
        let obfs = match psk {
            Some(psk) => Some(Arc::new(Obfuscator::new(psk, Arc::clone(&rng))?)),
            None => None,
        };
        let hop = match hop {
            Some(spec) => Some(HopScheduler::new(spec, rng)?),
            None => None,
        };
        Ok(Self {
            obfs,
            hop,
            current: Mutex::new(remote),
            remote,
        })
    }

    /// 当前发送目标地址。
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

    /// 本跳的间隔时长（对照 `ticker.Reset` 的实参）。未启用跳跃时返回
    /// 缺省 30s。
    #[must_use]
    pub fn hop_interval(&self) -> std::time::Duration {
        match &self.hop {
            Some(s) => s.interval(),
            None => std::time::Duration::from_secs(
                crate::transport::hop::DEFAULT_HOP_INTERVAL_SECS as u64,
            ),
        }
    }

    /// 把收到的对端地址归一到规范地址。
    ///
    /// 跳跃时线上目标端口会变 ⇒ 对端从新端口回包。quinn 的**客户端**禁止
    /// 迁移（`quinn-proto`：`remote != path.remote && !remote_may_migrate()`
    /// ⇒ 丢包），所以这里把同 IP 的来源地址改写回规范地址，让 quinn 视角的
    /// 远端保持不变。IP 不同 ⇒ `None`（丢弃该来源）。
    ///
    /// 未启用跳跃时不做任何改写（服务端与不跳跃的客户端都按真实地址处理）。
    #[must_use]
    pub fn normalize_peer(&self, addr: SocketAddr) -> Option<SocketAddr> {
        if !self.hopping() {
            return Some(addr);
        }
        if addr.ip() != self.remote.ip() {
            return None;
        }
        Some(self.remote)
    }

    /// 推进一跳：随机选端口并更新当前目标地址（对照参考 `hop()`）。
    /// 未启用跳跃时返回 `None`。
    pub fn next_hop(&self) -> Option<SocketAddr> {
        let scheduler = self.hop.as_ref()?;
        scheduler.next_hop()?;
        let dest = scheduler.current_dest(&self.remote);
        *self.current.lock().expect("hop 状态锁中毒") = dest;
        Some(dest)
    }

    /// 混淆一条 datagram（启用混淆时）。返回写出的字节数。
    /// 未启用混淆时原样拷贝并返回输入长度。
    pub fn obfuscate(&self, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        match &self.obfs {
            Some(o) => o.obfuscate(payload, out),
            None => {
                if out.len() < payload.len() {
                    return None;
                }
                out[..payload.len()].copy_from_slice(payload);
                Some(payload.len())
            }
        }
    }

    /// 解混淆一条 datagram。返回明文。
    ///
    /// fail-closed：启用了混淆但解不开（长度不足 / 口令不符 / 哈希不可用）时
    /// 返回 `None`，调用方**必须丢弃该报文**，绝不回退明文。
    pub fn deobfuscate(&self, raw: &[u8]) -> Option<Vec<u8>> {
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
}
