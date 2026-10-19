//! 端口跳跃：端口区间展开 + 定时轮换
//! （对照参考 `transport/internet/hysteria/udphop/addr.go` 的
//! `UDPHopAddr`/`Ports()` 与 `conn.go` 的 `hopLoop`/`hop`）。
//!
//! 语义逐点对齐：
//! - 端口列表 = 区间按声明顺序**闭区间展开**（`PortList.Ports()`）；
//! - 每跳间隔 `[IntervalMin, IntervalMax]` 秒内均匀取值（参考
//!   `crypto.RandBetween`），`IntervalMin/Max` 为 0 时取缺省 30s，
//!   任一小于 5s 直接拒绝（`hop interval must be at least 5 seconds`）；
//! - 每跳在**全部端口**里均匀随机选一个（参考 `hop()` 里的
//!   `rand.Intn(len(u.Addrs))`），允许选到当前端口（参考不排除自跳）。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use crate::transport::TransportRng;

/// 缺省跳端口间隔（秒），对照参考 `defaultHopInterval`。
pub const DEFAULT_HOP_INTERVAL_SECS: i64 = 30;
/// 最小跳端口间隔（秒），对照参考的 `intervalMin < 5` 判据。
pub const MIN_HOP_INTERVAL_SECS: i64 = 5;

/// 端口区间/间隔非法。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HopError {
    #[error("端口区间非法：起始 {from} 大于结束 {to}")]
    EmptyRange { from: u16, to: u16 },
    #[error("端口 {port} 不是合法端口（1..=65535）")]
    InvalidPort { port: u32 },
    #[error("端口列表为空")]
    NoPorts,
    #[error("跳端口间隔必须至少 {MIN_HOP_INTERVAL_SECS} 秒：{got}")]
    IntervalTooShort { got: i64 },
}

/// 端口区间（闭区间，含两端），对照 `net.PortRange`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    /// 展开为闭区间内的全部端口。
    fn expand(self, out: &mut Vec<u16>) {
        for p in self.from..=self.to {
            out.push(p);
        }
    }
}

/// 把参考的 `port_list` 配置（`"443,1000-2000"` 或单个数字）解析成端口区间。
///
/// 对照 `PortList.UnmarshalJSON`：逗号分隔，元素去空白后为空则忽略；
/// 含 `-` 视作区间，否则视作单端口。参考的 `env:` 形式绑定 Xray 的
/// 环境变量机制，本项目不复刻（见 docs 偏离清单）。
pub fn parse_port_list(spec: &str) -> Result<Vec<PortRange>, HopError> {
    let mut ranges = Vec::new();
    for item in spec.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.split_once('-') {
            Some((from, to)) => ranges.push(PortRange {
                from: parse_port(from)?,
                to: parse_port(to)?,
            }),
            None => {
                let port = parse_port(trimmed)?;
                ranges.push(PortRange {
                    from: port,
                    to: port,
                });
            }
        }
    }
    Ok(ranges)
}

fn parse_port(s: &str) -> Result<u16, HopError> {
    let value: u32 = s.trim().parse().map_err(|_| HopError::InvalidPort { port: 0 })?;
    if value == 0 || value > u32::from(u16::MAX) {
        return Err(HopError::InvalidPort { port: value });
    }
    Ok(value as u16)
}

/// 端口列表（区间保持声明顺序），对照 `net.PortList.Ports()`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortList {
    pub ranges: Vec<PortRange>,
}

impl PortList {
    /// 闭区间展开成端口序列。
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for r in &self.ranges {
            r.expand(&mut out);
        }
        out
    }

    /// 空的端口列表（未启用跳跃）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ports().is_empty()
    }
}

/// 端口跳跃配置（对照参考 `internet.UdpHop`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopSpec {
    pub ports: Vec<u16>,
    /// `IntervalMin`/`IntervalMax`（秒）；两者为 0 时取
    /// [`DEFAULT_HOP_INTERVAL_SECS`]，对照 `NewUDPHopPacketConn`。
    pub interval_min: i64,
    pub interval_max: i64,
}

impl HopSpec {
    /// 从 `port_list` 文本构造（对照 `UdpHop.Build()` + `addrs()`）。
    pub fn from_port_list(spec: &str, interval_min: i64, interval_max: i64) -> Result<Self, HopError> {
        let ports = PortList {
            ranges: parse_port_list(spec)?,
        }
        .ports();
        Self::new(ports, interval_min, interval_max)
    }

    /// 显式端口序列构造。
    pub fn new(mut ports: Vec<u16>, interval_min: i64, interval_max: i64) -> Result<Self, HopError> {
        if ports.is_empty() {
            return Err(HopError::NoPorts);
        }
        let (min, max) = normalize_interval(interval_min, interval_max)?;
        // 参考按 `len(u.Addrs)` 随机选，重复端口等价于提高权重；
        // 为让「逐点断言」可复现，这里保留调用方给定顺序。
        ports.dedup();
        Ok(Self {
            ports,
            interval_min: min,
            interval_max: max,
        })
    }
}

/// 归一化间隔：0/0 → 缺省 30s；任一非零且小于 5s → 拒绝。
fn normalize_interval(interval_min: i64, interval_max: i64) -> Result<(i64, i64), HopError> {
    if interval_min == 0 || interval_max == 0 {
        return Ok((DEFAULT_HOP_INTERVAL_SECS, DEFAULT_HOP_INTERVAL_SECS));
    }
    if interval_min < MIN_HOP_INTERVAL_SECS || interval_max < MIN_HOP_INTERVAL_SECS {
        let got = interval_min.min(interval_max);
        return Err(HopError::IntervalTooShort { got });
    }
    Ok((interval_min, interval_max))
}

/// 定时轮换调度器（对照 `hopLoop`：每跳后 `ticker.Reset` 重新取值）。
///
/// 状态机是纯函数 + 注入随机源，便于「注入时钟推进 hopInterval，
/// 逐点断言序列」；时间推进本身复用 `tokio::time`（测试可用
/// `start_paused` 虚拟时钟）。
pub struct HopScheduler {
    spec: HopSpec,
    rng: Arc<dyn TransportRng>,
    inner: Mutex<Inner>,
    tx: watch::Sender<u64>,
}

struct Inner {
    /// 当前端口在 `spec.ports` 中的下标（对照 `addrIndex`）。
    index: usize,
    /// 起跳次数（对照 `ticker` 触发次数）。
    hops: u64,
    /// 当前这一跳的时长（秒），对照 `ticker.Reset(...)` 的实参。
    interval_secs: i64,
    closed: bool,
}

impl Clone for HopScheduler {
    /// 克隆共享同一份轮换状态（等价参考里多个句柄指向同一个
    /// `UdpHopPacketConn`）；`Mutex` 在内，clone 不会分叉状态。
    fn clone(&self) -> Self {
        Self {
            spec: self.spec.clone(),
            rng: Arc::clone(&self.rng),
            inner: Mutex::new(Inner {
                index: self.inner.lock().expect("hop 状态锁中毒").index,
                hops: self.inner.lock().expect("hop 状态锁中毒").hops,
                interval_secs: self.inner.lock().expect("hop 状态锁中毒").interval_secs,
                closed: self.inner.lock().expect("hop 状态锁中毒").closed,
            }),
            tx: self.tx.clone(),
        }
    }
}

impl HopScheduler {
    /// 建调度器；`index` 从 0 起（等价参考 `NewUDPHopPacketConn(addr, 0, …)`）。
    pub fn new(spec: HopSpec, rng: Arc<dyn TransportRng>) -> Result<Self, HopError> {
        if spec.ports.is_empty() {
            return Err(HopError::NoPorts);
        }
        let (min, max) = normalize_interval(spec.interval_min, spec.interval_max)?;
        let spec = HopSpec {
            ports: spec.ports,
            interval_min: min,
            interval_max: max,
        };
        let interval_secs = draw_interval(&spec, &*rng);
        let (tx, _rx) = watch::channel(0u64);
        Ok(Self {
            spec,
            rng,
            inner: Mutex::new(Inner {
                index: 0,
                hops: 0,
                interval_secs,
                closed: false,
            }),
            tx,
        })
    }

    /// 订阅「已跳」通知（每跳一次 +1）。
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.tx.subscribe()
    }

    /// 端口列表。
    #[must_use]
    pub fn ports(&self) -> &[u16] {
        &self.spec.ports
    }

    /// 当前端口下标（对照 `addrIndex`）。
    #[must_use]
    pub fn index(&self) -> usize {
        self.inner.lock().expect("hop 状态锁中毒").index
    }

    /// 当前端口。
    #[must_use]
    pub fn current_port(&self) -> u16 {
        self.spec.ports[self.index()]
    }

    /// 当前这一跳的剩余等待时长（对照 `ticker` 的周期）。
    #[must_use]
    pub fn interval(&self) -> Duration {
        let secs = self.inner.lock().expect("hop 状态锁中毒").interval_secs;
        Duration::from_secs(secs.max(0) as u64)
    }

    /// 完成的跳数。
    #[must_use]
    pub fn hops(&self) -> u64 {
        self.inner.lock().expect("hop 状态锁中毒").hops
    }

    /// 执行一跳：随机选端口 + 重新抽间隔（对照 `hop()` 与 `hopLoop` 的
    /// `ticker.Reset`）。返回 `(新下标, 新端口, 本跳时长)`。
    /// 已关闭时返回 `None`。
    pub fn next_hop(&self) -> Option<(usize, u16, Duration)> {
        {
            let inner = self.inner.lock().expect("hop 状态锁中毒");
            if inner.closed {
                return None;
            }
        }
        let index = self.rng.gen_index(self.spec.ports.len());
        let interval_secs = draw_interval(&self.spec, &*self.rng);
        let hops = {
            let mut inner = self.inner.lock().expect("hop 状态锁中毒");
            inner.index = index;
            inner.interval_secs = interval_secs;
            inner.hops += 1;
            inner.hops
        };
        let _ = self.tx.send(hops);
        Some((
            index,
            self.spec.ports[index],
            Duration::from_secs(interval_secs.max(0) as u64),
        ))
    }

    /// 当前跳对应的远端地址：仅替换 `base` 的端口（对照 `addrs[addrIndex]`，
    /// 参考的 `UDPHopAddr` 保留同一 IP，只换端口）。
    #[must_use]
    pub fn current_dest(&self, base: &std::net::SocketAddr) -> std::net::SocketAddr {
        let mut addr = *base;
        addr.set_port(self.current_port());
        addr
    }

    /// 推进一跳并等待其间隔（真实时钟路径；测试用虚拟时钟）。
    pub async fn wait_hop(&self, timeout: Duration) -> bool {
        let some = tokio::time::timeout(timeout, async {
            let mut rx = self.subscribe();
            // 先跳一次再等通知：`wait_hop` 的调用者期望「推进一跳」。
            let _ = self.next_hop();
            let _ = rx.changed().await;
        })
        .await;
        some.is_ok()
    }

    /// 关闭调度器（对照 `Close`：`closeChan` 关掉后 `hopLoop` 退出）。
    pub fn close(&self) {
        self.inner.lock().expect("hop 状态锁中毒").closed = true;
    }

    /// 是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().expect("hop 状态锁中毒").closed
    }
}

/// `crypto.RandBetween(min, max)`：闭区间均匀取值。
fn draw_interval(spec: &HopSpec, rng: &dyn TransportRng) -> i64 {
    if spec.interval_min >= spec.interval_max {
        return spec.interval_min;
    }
    let span = (spec.interval_max - spec.interval_min).unsigned_abs() + 1;
    spec.interval_min + (rng.gen_u64(span) % span) as i64
}
