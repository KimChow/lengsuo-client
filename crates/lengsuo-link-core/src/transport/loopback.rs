//! 内存环回传输：**两个端点互连**的参考实现。
//!
//! 用途：证明「L2 封帧 → L1 搬运 → L2 解帧」这条路径**真的**走通
//! （对端拿到明文、链路上跑的是密文），而**不**依赖任何 socket。
//!
//! # 无 IO
//!
//! 纯内存队列（`Arc<Mutex<VecDeque<Vec<u8>>>>`）：⛔ 无 socket、⛔ 无文件、
//! ⛔ 无线程、⛔ 无计时器。两个端点靠 `Arc` 共享同一条队列。
//!
//! # 契约遵守
//!
//! - [`send`](Transport::send) 超长 ⇒ [`TransportError::TooLong`]（**不截断**）；
//! - [`recv`](Transport::recv) 超长 ⇒ [`TransportError::TooLong`]，
//!   且**丢弃**这一包（坏包留在队列里会永远卡住接收侧）；
//! - 空队列 ⇒ [`TransportError::WouldBlock`]（**不是**失败）。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::frame::MAX_FRAME_LEN;

use super::error::TransportError;
use super::trait_def::Transport;

/// 内存环回传输的一端。
///
/// 两个端点由 [`Loopback::pair`] 配对，共享同一条字节队列。
#[derive(Clone, Debug)]
pub struct Loopback {
    /// 与对端共享的字节队列。
    shared: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// 本端的准入上限（单帧字节数）。
    max_frame_len: usize,
}

impl Loopback {
    /// 造一对互连的环回端点。
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let shared = Arc::new(Mutex::new(VecDeque::new()));
        (
            Self {
                shared: Arc::clone(&shared),
                max_frame_len: MAX_FRAME_LEN,
            },
            Self {
                shared,
                max_frame_len: MAX_FRAME_LEN,
            },
        )
    }

    /// 收窄本端的准入上限（低于 [`MAX_FRAME_LEN`] 时用于模拟分片重组传输）。
    #[must_use]
    pub fn with_max_frame_len(mut self, limit: usize) -> Self {
        self.max_frame_len = limit.min(MAX_FRAME_LEN);
        self
    }

    /// 队列里还没被取走的字节数。
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.shared.lock().map(|queue| queue.len()).unwrap_or(0)
    }
}

impl Transport for Loopback {
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if bytes.len() > self.max_frame_len {
            return Err(TransportError::TooLong {
                actual: bytes.len(),
                limit: self.max_frame_len,
            });
        }
        let mut queue = self
            .shared
            .lock()
            .map_err(|_| TransportError::Internal("环回队列已 poison"))?;
        queue.push_back(bytes.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut queue = self
            .shared
            .lock()
            .map_err(|_| TransportError::Internal("环回队列已 poison"))?;
        let bytes = queue.pop_front().ok_or(TransportError::WouldBlock)?;
        if bytes.len() > self.max_frame_len {
            // 坏包丢弃：留在队列里会永远卡住接收侧。
            return Err(TransportError::TooLong {
                actual: bytes.len(),
                limit: self.max_frame_len,
            });
        }
        Ok(bytes)
    }

    fn max_frame_len(&self) -> usize {
        self.max_frame_len
    }
}
