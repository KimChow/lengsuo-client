//! Brutal 拥塞器的**接线层**：把 `lengsuo-congestion` 的内核装进 hysteria 的
//! 传输（逐条对齐参考 `dialer.go:297-315` 与 `hub.go:187-205` 的 `switch
//! congestion` → `congestion.UseBrutal(conn, min(up, peerDown))`）。
//!
//! # 模式选择（fail-closed）
//!
//! - **空串**（缺省）⇒ quinn 默认 CUBIC，不注入（D1：参考 `""` 与 `brutal`
//!   同分支，本仓缺省仍是 CUBIC）；
//! - **`"brutal"`** ⇒ 按协商速率注入 Brutal；
//! - **未识别值** ⇒ [`CongestionError::UnknownMode`]；
//! - **`"bbr"` / `"reno"` / `"force-brutal"`** ⇒ [`CongestionError::Unimplemented`]
//!   （参考有、本仓未移植；**不**假装生效、**不**静默落回 CUBIC）。
//!
//! # 协商（与参考同构，只有速率来源不同）
//!
//! - 客户端：`min(本端 up, 服务端 Hysteria-CC-RX)`，任一为 0 ⇒ `None` =
//!   参考回落分支（`serverAuto == "auto" || BrutalUp == 0 || serverDown == 0`）；
//! - 服务端：`min(本端 BrutalUp, 客户端 Hysteria-CC-RX)`，任一为 0 ⇒ `None`
//!   （`hub.go:194`）；
//! - 参考回落目标是 **BBR**，本仓 BBR 未移植 ⇒ 回落 CUBIC 并显式记日志（D2）；
//! - 协商出 `Some(0)` 或亚字节每秒 ⇒ `Err`，**不得**用 0 速率构造控制器。
//!
//! # 结构性偏离（quinn 0.11 没有连接期替换入口）
//!
//! 参考在认证后对**单条连接**调 `conn.SetCongestionControl(...)`。quinn 0.11
//! 的拥塞器只能经 `TransportConfig` 在**建连前**指定，故：
//!
//! - **客户端**：先建一条探测连接读服务端 `Hysteria-CC-RX` 并关闭，再以
//!   `min(up, serverDown)` 装配正式连接（`HysteriaClient::connect_with_negotiated`）；
//!   发送方向由 `lengsuo_congestion::brutal::BrutalConfig` 真控制器限速。
//! - **服务端**：`TransportConfig` 是端点级、先于对端 `Hysteria-CC-RX` 到达，
//!   参考的逐连接 `min(BrutalUp, clientDown)` 无法用工厂表达 ⇒ 服务端发送方向
//!   改由 **TCP 端口用户态节流**（[`PacedReader`]）执行同一协商结果（D4）；
//!   UDP datagram 路径仍只 `warn`。
//! - 客户端另发一条**不带数据**的 TCPRequest（[`announce_frame`]）携带同一
//!   `Hysteria-CC-RX`，服务端据此逐连接协商其发送方向（D3）。

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use lengsuo_congestion::brutal::BrutalConfig;
use lengsuo_congestion::ConfigError;
use lengsuo_congestion::Mode as CongestionModeKind;
use tokio::io::{AsyncRead, ReadBuf};

use super::header::CcHeader;
use super::{
    negotiate_client_rate, negotiate_server_rate, Bandwidth, CongestionConfig, CongestionMode,
};

/// 端口每次交给协议栈的块大小（≈ 两个 1500 MTU）。
pub const PACE_BLOCK: usize = 3 * 1024;
/// 端口读出量的下限：小于它的块不足以证明「速率真的在限速」。
pub const MIN_RATE_BPS: u64 = 1024;

/// 接线失败原因（全部 fail-closed）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CongestionError {
    /// 模式串未识别：fail-closed，**不静默落回 CUBIC**。
    #[error("未识别的拥塞控制模式：{mode:?}（fail-closed，不回落 CUBIC）")]
    UnknownMode { mode: String },
    /// 参考有、本仓未移植的模式（`bbr` / `reno` / `force-brutal`）。
    #[error("拥塞控制模式 {mode:?} 尚未移植（fail-closed，不回落 CUBIC）")]
    Unimplemented { mode: String },
    /// 协商速率非法（0 / 亚字节每秒）。
    #[error("Brutal 协商速率非法：{0}")]
    Rate(#[from] ConfigError),
}

/// 解析配置里的 `"congestion"`（取值集对齐 `transport_internet.go:1913-1920`，
/// 但只实现 `brutal`）。
pub fn parse_mode(text: &str) -> Result<Option<CongestionModeKind>, CongestionError> {
    let mode = text.trim();
    match mode.to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "brutal" => Ok(Some(CongestionModeKind::Brutal)),
        "bbr" | "reno" | "force-brutal" => Err(CongestionError::Unimplemented {
            mode: mode.to_owned(),
        }),
        _ => Err(CongestionError::UnknownMode {
            mode: mode.to_owned(),
        }),
    }
}

/// 由模式串 + 本端发送速率构造参数载体：`tx` = 本端发送速率（字节/秒）；
/// `rx` 由 `Hysteria-CC-RX` 承载。模式串经 [`parse_mode`] fail-closed 校验；
/// 空串（缺省）按参考 `""` 与 `"brutal"` 同分支折为 `Brutal`，但
/// `brutal_down == 0` 时协商必回落到 `None` ⇒ 不注入（CUBIC）。
pub fn local_config(mode: &str, up: u64) -> Result<CongestionConfig, CongestionError> {
    parse_mode(mode)?;
    Ok(config(CongestionMode::Brutal, up))
}

fn config(mode: CongestionMode, up: u64) -> CongestionConfig {
    CongestionConfig {
        mode,
        rx: Bandwidth(0),
        tx: Bandwidth(up),
    }
}

/// 客户端协商（对齐 `dialer.go:303-310`）：`min(本端 up, 服务端 down)`。
pub fn client_rate(up: u64, server_cc_rx: CcHeader) -> Result<Option<u64>, CongestionError> {
    validate(negotiate_client_rate(
        &config(CongestionMode::Brutal, up),
        server_cc_rx,
    ))
}

/// 服务端协商（对齐 `hub.go:193-200`）：`min(本端 BrutalUp, 客户端 down)`。
pub fn server_rate(up: u64, client_cc_rx: CcHeader) -> Result<Option<u64>, CongestionError> {
    validate(negotiate_server_rate(
        &config(CongestionMode::Brutal, up),
        client_cc_rx,
    ))
}

/// `Some(0)` / 亚字节每秒 ⇒ `Err`；`None` 是回落分支（交给调用方显式日志）。
fn validate(rate: Option<u64>) -> Result<Option<u64>, CongestionError> {
    if let Some(bytes) = rate {
        BrutalConfig::from_negotiated(Some(bytes), 0)?;
    }
    Ok(rate)
}

/// 把协商速率装配进 `TransportConfig`（客户端发送方向）。
pub fn inject(
    transport: &mut quinn::TransportConfig,
    mode: Option<CongestionModeKind>,
    negotiated_bytes_per_sec: Option<u64>,
) -> Result<(), CongestionError> {
    if mode != Some(CongestionModeKind::Brutal) {
        return Ok(());
    }
    let Some(bytes) = negotiated_bytes_per_sec else {
        // 参考回落 BBR（dialer.go:306 / hub.go:196）；BBR 未移植 ⇒ CUBIC + 日志。
        eprintln!("[lengsuo-hysteria] 未协商出 Brutal 速率（参考回落分支），沿用 quinn 默认 CUBIC");
        return Ok(());
    };
    let cc = BrutalConfig::from_negotiated(Some(bytes), 0)?;
    eprintln!(
        "[lengsuo-hysteria] QUIC 传输注入 Brutal 拥塞器：{} 字节/秒",
        cc.bytes_per_sec()
    );
    transport.congestion_controller_factory(Arc::new(cc));
    Ok(())
}

/// 服务端为该连接求发送速率（`hub.go:187-205`）：`brutal` ⇒
/// `min(本端 BrutalUp, 对端 down)`，任一为 0 ⇒ `Ok(0)`（参考回落分支：
/// 不限速并显式日志）；非法速率 ⇒ `Err`。
pub fn server_send_rate(
    local: &CongestionConfig,
    client_cc_rx: u64,
) -> Result<u64, CongestionError> {
    let header = CcHeader::Bps(Bandwidth(client_cc_rx));
    Ok(validate(negotiate_server_rate(local, header))?.unwrap_or(0))
}

/// 端口令牌桶：按 `rate` 字节/秒发放（`rate == 0` = 不限速）。
///
/// 惰性补发，桶容量 [`PACE_BLOCK`]；不会透支。
#[derive(Debug, Clone)]
pub struct Pacer {
    rate: u64,
    tokens: f64,
    last: Instant,
}

impl Pacer {
    #[must_use]
    pub fn new(rate: u64) -> Self {
        Self {
            rate,
            tokens: 0.0,
            last: Instant::now(),
        }
    }

    /// 取出不超过 `want` 字节的令牌；返回 0 时调用方应等 [`Self::wait`]。
    pub fn take(&mut self, want: usize) -> usize {
        if self.rate == 0 {
            return want;
        }
        let now = Instant::now();
        let refill = now.saturating_duration_since(self.last).as_secs_f64() * self.rate as f64;
        self.tokens = (self.tokens + refill).min(PACE_BLOCK as f64);
        self.last = now;
        let n = want.min(self.tokens as usize);
        self.tokens -= n as f64;
        n
    }

    /// 至少值 1 字节的令牌还需等待多久。
    #[must_use]
    pub fn wait(&self) -> Duration {
        if self.rate == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64((1.0 - self.tokens).max(0.0) / self.rate as f64)
    }
}

/// 服务端 TCP 端口的限速读端：`source` → 节拍器 → `PacedReader` → QUIC 流。
///
/// 执行参考「服务端发送方向 `UseBrutal(min(BrutalUp, clientDown))`」的速率；
/// 每次最多交出 [`PACE_BLOCK`] 字节，端口自身缓冲截断为一块，不会把整段
/// 目标数据先拥进内存。
pub struct PacedReader<R> {
    inner: R,
    pacer: Pacer,
    queue: VecDeque<u8>,
    chunk: Vec<u8>,
}

impl<R> PacedReader<R> {
    /// 包装 `inner`，按 `rate` 字节/秒放行（`0` = 不限速）。
    pub fn new(inner: R, rate: u64) -> Self {
        Self {
            inner,
            pacer: Pacer::new(rate),
            queue: VecDeque::with_capacity(PACE_BLOCK),
            chunk: vec![0u8; PACE_BLOCK],
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PacedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.queue.is_empty() {
            let mut rb = ReadBuf::new(&mut this.chunk);
            let filled = match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => rb.filled().len(),
            };
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }
            this.queue.extend(&this.chunk[..filled]);
        }
        let allowed = this.pacer.take(this.queue.len().min(buf.remaining()));
        if allowed == 0 {
            // 令牌不足：注册最短重试定时器后返回「暂无数据」（非 EOF）。
            let wait = this.pacer.wait().max(Duration::from_micros(100));
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                waker.wake();
            });
            return Poll::Ready(Ok(()));
        }
        let head: Vec<u8> = this.queue.drain(..allowed).collect();
        buf.put_slice(&head);
        Poll::Ready(Ok(()))
    }
}

/// 协议内**不带数据**的拥塞通告（D3）：收端据此逐连接装配
/// `min(BrutalUp, clientDown)`。
///
/// 负载 = `MAGIC(8) ‖ client_cc_rx: u64 BE(8) ‖ FINISH(1)`。首字节 `'l'` 高两位
/// 为 `01` ⇒ 按 QUIC varint 解析为非帧类型；参考对未知帧类型的 TCP 流不建立
/// 承载（只丢弃），故与参考互通时不会误连目标。
pub const ANNOUNCE_MAGIC: [u8; 8] = *b"lgs-cc1v";
/// 通告负载长度。
pub const ANNOUNCE_LEN: usize = 17;

/// 构造通告负载。
#[must_use]
pub fn announce_frame(client_cc_rx: u64) -> [u8; ANNOUNCE_LEN] {
    let mut out = [0u8; ANNOUNCE_LEN];
    out[..8].copy_from_slice(&ANNOUNCE_MAGIC);
    out[8..16].copy_from_slice(&client_cc_rx.to_be_bytes());
    out[16] = 0x01;
    out
}

/// 解析通告负载：返回 `client_cc_rx`；不是通告 ⇒ `None`（按普通 TCP 请求）。
#[must_use]
pub fn parse_announce(prefix: &[u8]) -> Option<u64> {
    if prefix.len() != ANNOUNCE_LEN || prefix[..8] != ANNOUNCE_MAGIC || prefix[16] != 0x01 {
        return None;
    }
    Some(u64::from_be_bytes(prefix[8..16].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_limits_to_rate() {
        let mut pacer = Pacer::new(10_000);
        std::thread::sleep(Duration::from_millis(100));
        // 100ms × 10000 B/s = 1000 字节（容许 ±10 字节的计时误差）。
        let got: usize = (0..20).map(|_| pacer.take(PACE_BLOCK)).sum();
        assert!((990..=1010).contains(&got), "放行 {got} 字节");
    }

    #[test]
    fn pacer_unlimited_when_zero() {
        let mut pacer = Pacer::new(0);
        assert_eq!(pacer.take(10), 10);
    }

    #[test]
    fn announce_roundtrip_rejects_foreign_prefix() {
        assert_eq!(
            parse_announce(&announce_frame(256 * 1024)),
            Some(256 * 1024)
        );
        let mut req = vec![0u8; ANNOUNCE_LEN];
        req[0] = 0x01; // TCPRequest 帧类型的首字节
        assert_eq!(parse_announce(&req), None);
        assert_eq!(parse_announce(&[]), None);
    }
}
