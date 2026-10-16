//! Windows 侧会话后端：真实 wintun 会话与测试专用内存回环共用同一套最小接口。
//!
//! 为什么需要这层抽象：wintun 0.5.1 只有 `unsafe fn load*()` 能产出库句柄，本 crate
//! `#![forbid(unsafe_code)]`，因此**真实会话的创建必须由宿主加载 dll 后完成**；
//! 而本层自身的语义（会话生命周期、超时分类、缓冲不足、Drop 防重入、MTU 边界）
//! 需要能在不触碰系统的情况下被测试。二者用 [`Ring`] 接口统一：
//! - [`WintunRing`]：转发到 `wintun::Session`，是生产路径。
//! - [`LoopbackRing`]：进程内内存队列，同一会话自发自收，只用于测试，不创建适配器、
//!   不改系统状态。**它验证的是本层语义，不代表 wintun 真实收发。**
//!
//! 错误约定：`Ok(None)` 表示当前无报文（调用方按超时策略重试）；会话被撤回返回
//! [`Error::SessionEnded`]；队列满返回 [`Error::BufferInsufficient`]。

use super::{Error, Result, MAX_PACKET_BYTES};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use wintun::Session;

/// 会话后端的最小接口。
pub(crate) trait Ring: Send + Sync {
    /// 尝试取一个报文；`Ok(None)` 表示暂无报文。
    fn try_receive(&self) -> Result<Option<Vec<u8>>>;
    /// 发送一个报文，长度已由上层校验。
    fn send(&self, packet: &[u8]) -> Result<()>;
    /// 唤醒并结束会话；重复调用无副作用。
    fn shutdown(&self);
    /// 是否已停止。
    fn stopped(&self) -> bool;
}

/// 生产路径：转发到 wintun 会话。
pub(crate) struct WintunRing {
    session: Arc<Session>,
    stopped: AtomicBool,
}

impl WintunRing {
    pub(crate) fn new(session: Arc<Session>) -> Self {
        Self {
            session,
            stopped: AtomicBool::new(false),
        }
    }
}

impl Ring for WintunRing {
    fn try_receive(&self) -> Result<Option<Vec<u8>>> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::SessionEnded);
        }
        match super::windows::map_wintun(self.session.try_receive())? {
            Some(packet) => {
                // Packet 借用驱动环形缓冲内存，析构即归还；这里立刻拷贝成堆内存。
                let bytes = packet.bytes().to_vec();
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    fn send(&self, packet: &[u8]) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::SessionEnded);
        }
        let size = u16::try_from(packet.len()).map_err(|_| Error::InvalidPacket {
            value: packet.len(),
            max: MAX_PACKET_BYTES,
        })?;
        // wintun 要求每个分配的包都被发送，否则发送队列永久卡住。
        // 分配长度与写入长度同为 packet.len()，copy_from_slice 不会失败，
        // 因此本函数不存在「已分配未发送」的返回路径。
        let mut buffer = super::windows::map_wintun(self.session.allocate_send_packet(size))?;
        buffer.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(buffer);
        Ok(())
    }

    fn shutdown(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        // shutdown 只置位停止事件，失败由随后的会话释放兜住。
        let _ = self.session.shutdown();
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

/// 测试专用回环：同一会话内自发自收，不接触任何系统状态。
#[derive(Default)]
pub(crate) struct LoopbackRing {
    queue: Mutex<VecDeque<Vec<u8>>>,
    stopped: AtomicBool,
    /// 队列可暂存的报文条数上限，取自 ring 容量按最小报文长度折算。
    pending_limit: Mutex<usize>,
}

impl LoopbackRing {
    /// 按 ring 容量折算暂存上限：每报文至少 1 字节，因此条数上限即容量字节数，
    /// 再对拍到一个合理区间，避免测试里真的分配 64MB 的槽位向量。
    pub(crate) fn new(ring_capacity: u32) -> Self {
        let limit = usize::try_from(ring_capacity)
            .unwrap_or(usize::MAX)
            .clamp(1, 4096);
        Self {
            queue: Mutex::new(VecDeque::with_capacity(limit.min(64))),
            stopped: AtomicBool::new(false),
            pending_limit: Mutex::new(limit),
        }
    }

    /// 测试夹具：当前暂存的报文条数。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn pending(&self) -> usize {
        self.queue.lock().expect("回环队列锁 poisoned").len()
    }

    /// 测试夹具：注入一个报文，模拟驱动侧收到数据包。
    pub(crate) fn inject(&self, packet: Vec<u8>) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::SessionEnded);
        }
        let mut queue = self.queue.lock().expect("回环队列锁 poisoned");
        if queue.len() >= *self.pending_limit.lock().expect("上限锁 poisoned") {
            return Err(Error::BufferInsufficient);
        }
        queue.push_back(packet);
        Ok(())
    }
}

impl Ring for LoopbackRing {
    fn try_receive(&self) -> Result<Option<Vec<u8>>> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::SessionEnded);
        }
        Ok(self
            .queue
            .lock()
            .expect("回环队列锁 poisoned")
            .pop_front()
            .map(|packet| {
                debug_assert!(!packet.is_empty());
                packet
            }))
    }

    fn send(&self, packet: &[u8]) -> Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::SessionEnded);
        }
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(Error::InvalidPacket {
                value: packet.len(),
                max: MAX_PACKET_BYTES,
            });
        }
        let mut queue = self.queue.lock().expect("回环队列锁 poisoned");
        if queue.len() >= *self.pending_limit.lock().expect("上限锁 poisoned") {
            return Err(Error::BufferInsufficient);
        }
        // 回环语义：发出的报文立刻成为本会话的下一个可收报文。
        queue.push_back(packet.to_vec());
        Ok(())
    }

    fn shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
        self.queue.lock().expect("回环队列锁 poisoned").clear();
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

/// 回环报文的构造时间戳，仅用于诊断日志，不参与任何判定。
#[cfg(test)]
pub(crate) fn loopback_stamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_micros())
        .unwrap_or_else(|_| Instant::now().elapsed().as_micros())
}
