//! keepalive 任务：**周期性地发零长载荷的 keepalive 帧**。
//!
//! keepalive 的作用是**穿过 NAT 的空闲回收**：定期让报文流过，
//! 免得映射表被中间设备悄悄丢掉。
//!
//! ⚠️ **间隔由上层给**（[`KeepaliveConfig::interval`]）——本 crate **不写死**
//! 任何节奏常量（那是隧道装配卡的配置项）。
//!
//! ⚠️ **本卡不动 keepalive 的帧长**：契约要求 52B（20B 帧头 + 32B 载荷），
//! 而这里发的是 20B（零长载荷）。这是**另一张卡**（`wg-keepalive-sealed`）的
//! 范围，本卡**只做握手**，⛔ 不顺手改。

use std::time::Duration;

use lengsuo_link_core::frame::{Frame, FrameType};
use tokio::task::JoinHandle;

use super::error::UdpError;
use super::loop_::Cancel;
use super::socket::UdpEndpoint;

/// keepalive 的配置。**间隔由上层给**——本卡不写死任何节奏常量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveConfig {
    /// 发 keepalive 的间隔。`None` = **关闭** keepalive。
    pub interval: Option<Duration>,
}

/// keepalive 任务的结束方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepaliveOutcome {
    /// 上层取消。
    Cancelled,
    /// 端点出了问题（发送失败）。
    Failed(UdpError),
}

/// keepalive 任务句柄。
#[derive(Debug)]
pub struct KeepaliveHandle {
    task: JoinHandle<KeepaliveOutcome>,
    cancel: Cancel,
}

impl KeepaliveHandle {
    /// 主动结束 keepalive 任务并等它退出。
    ///
    /// ⚠️ 调用方必须自己加超时（与 `LoopHandle::stop` 同理）。
    pub async fn stop(self) -> KeepaliveOutcome {
        self.cancel.cancel();
        match self.task.await {
            Ok(outcome) => outcome,
            Err(err) => KeepaliveOutcome::Failed(UdpError::Socket {
                source: super::error::SocketError::new(std::io::Error::other(format!(
                    "keepalive 任务异常退出：{err}"
                ))),
            }),
        }
    }
}

/// 启动 keepalive 任务：周期性地发**零长载荷**的 keepalive 帧。
///
/// ⚠️ **间隔由上层给**（[`KeepaliveConfig::interval`]）——本卡**不写死**任何
/// 节奏常量（那是隧道装配卡的配置项）。`interval` 为 `None` 时**不启动**，
/// 返回 `None`。
///
/// # Errors
/// 本函数不返回 `Result`：间隔不合法（零）时视为配置错误，直接拒绝启动。
pub fn spawn_keepalive(
    endpoint: UdpEndpoint,
    config: KeepaliveConfig,
    cancel: Cancel,
) -> Option<KeepaliveHandle> {
    let interval = config.interval?;
    if interval.is_zero() {
        // 零间隔 = busy loop，绝不允许。
        return None;
    }
    let task = tokio::spawn(run_keepalive(endpoint, interval, cancel.clone()));
    Some(KeepaliveHandle { task, cancel })
}

/// keepalive 任务本体。
async fn run_keepalive(
    endpoint: UdpEndpoint,
    interval: Duration,
    cancel: Cancel,
) -> KeepaliveOutcome {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 第一次 tick 立刻触发；这里**跳过**它，让首个 keepalive 在一个间隔之后发。
    ticker.tick().await;

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                return KeepaliveOutcome::Cancelled;
            }
            _ = ticker.tick() => {
                // keepalive = **零长载荷**的帧。
                let frame = Frame::new(FrameType::Keepalive, 0, Vec::new());
                if let Err(err) = endpoint.send_frame(&frame).await {
                    return KeepaliveOutcome::Failed(err);
                }
            }
        }
    }
}
