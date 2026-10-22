//! Native Messaging **管道帧**编解码（宿主进程 ⇄ Chromium 之间的传输格式）。
//!
//! # 帧布局
//!
//! ```text
//! pipe_frame = length_prefix(4 字节) || payload(length_prefix 字节)
//! ```
//!
//! | 偏移 | 宽度 | 字段 | 语义 |
//! |---|---|---|---|
//! | 0 | 4 | `length_prefix` | u32，**本机字节序** = payload 字节数（不含这 4 字节） |
//! | 4 | .. | `payload` | JSON 文本（UTF-8） |
//!
//! ⛔ 长度前缀是**本机字节序**（native endian），**不是**网络字节序：
//! Chromium 的写侧用 `memcpy` 把 `uint32_t` 原样拷进缓冲区，
//! 读侧用 `*reinterpret_cast<const uint32_t*>` 原样读回
//! ⇒ 收发两侧同机同序。
//!
//! 字节真相：`chrome/browser/extensions/api/messaging/native_message_process_host.cc`
//! （写侧 `OnMessage`，读侧 `ProcessIncomingData`）。
//!
//! # 本模块只搬字节
//!
//! ⛔ 本模块**不解析载荷的 JSON 结构**：载荷是 JSON **文本**，
//! 业务消息帧（类型编号 / 回退语义）是上一层的事。
//!
//! # 分片
//!
//! 一次 `read` **不等于**一帧。本模块的 [`FrameDecoder`] 按 Chromium
//! `ProcessIncomingData` 的语义工作：把收到的字节**追加**进缓冲，
//! 然后**循环**切帧 —— 凑够一整帧才交付，不够就留着等下一次。
//!
//! # 上限
//!
//! 单帧载荷上限 1 MiB（见 [`MAX_FRAME_PAYLOAD_LEN`]）。

use crate::error::FrameError;

/// 管道帧帧头长度：4 字节长度前缀。
pub const FRAME_HEADER_LEN: usize = 4;

/// 单帧**载荷**上限：1 MiB。
///
/// 编码侧的依据是 Chromium 的 `kMaximumNativeMessageSize`
/// （`native_message_process_host.cc`）：超过它的消息会被 Chromium
/// 直接关掉通道 ⇒ 本卡写出去的消息必须 ≤ 1 MiB。
///
/// 解码侧的 1 MiB 是**本卡自设**（Chromium 的写侧不检查长度）：
/// 一来与编码侧对称，二来防止一个坏的长度头让本卡申请巨量内存。
pub const MAX_FRAME_PAYLOAD_LEN: usize = 1024 * 1024;

/// 把载荷装进管道帧：4 字节本机字节序长度前缀 + 载荷。
///
/// # Errors
/// 载荷超过 [`MAX_FRAME_PAYLOAD_LEN`] ⇒ `FrameError::PayloadTooLong`
/// （**不截断、不分帧**）。
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLong {
            declared: payload.len(),
            limit: MAX_FRAME_PAYLOAD_LEN,
        });
    }
    // 上限检查已保证 payload.len() <= 1 MiB ⇒ 转 u32 不会截断。
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 从字节流里切出**第一帧**：返回载荷与**已消费字节数**。
///
/// 长度纪律：只按帧头声明的长度切帧。
/// - 缓冲不足一整帧 ⇒ `FrameError::Incomplete`（**不返回部分数据**）。
/// - 缓冲多于一帧 ⇒ 正常返回第一帧（粘包是常态），多余字节留给调用方。
/// - 帧头声明的长度超限 ⇒ `FrameError::FrameTooLong`（**不截断、不巨量分配**）。
///
/// # Errors
/// - 缓冲不足一整帧 ⇒ `FrameError::Incomplete`。
/// - 帧头声明的长度超过上限 ⇒ `FrameError::FrameTooLong`。
pub fn decode_frame(buf: &[u8]) -> Result<(&[u8], usize), FrameError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(FrameError::Incomplete {
            needed: FRAME_HEADER_LEN,
            available: buf.len(),
        });
    }
    let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if u64::from(len) > MAX_FRAME_PAYLOAD_LEN as u64 {
        return Err(FrameError::FrameTooLong {
            declared: u64::from(len),
            limit: MAX_FRAME_PAYLOAD_LEN,
        });
    }
    let total = FRAME_HEADER_LEN + len as usize;
    if buf.len() < total {
        return Err(FrameError::Incomplete {
            needed: total,
            available: buf.len(),
        });
    }
    Ok((&buf[FRAME_HEADER_LEN..total], total))
}

/// 管道帧解码器：把收到的字节流切成完整帧。
///
/// 语义照 Chromium 的 `ProcessIncomingData`：收到的字节**追加**进缓冲，
/// 再**循环**切帧 —— 凑够一整帧才交付，不够就留着等下一次。
///
/// ⇒ 一次 [`feed`](Self::feed) 可能取出 **0 帧、1 帧或多帧**。
#[derive(Debug, Default)]
pub struct FrameDecoder {
    /// 还没切走的字节。
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// 新建一个空解码器。
    #[must_use]
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// 追加收到的字节，返回本次能切出的**全部**完整帧。
    ///
    /// # Errors
    /// - 帧头声明的长度超过上限 ⇒ `FrameError::FrameTooLong`
    ///   （**不截断、不巨量分配**；缓冲里的字节原样保留）。
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            match decode_frame(&self.buffer) {
                Ok((payload, consumed)) => {
                    frames.push(payload.to_vec());
                    self.buffer.drain(..consumed);
                }
                // 凑不够一整帧 ⇒ 等更多数据（不是错误）。
                Err(FrameError::Incomplete { .. }) => break,
                Err(other) => return Err(other),
            }
        }
        Ok(frames)
    }

    /// 缓冲里还没切走的字节数。
    ///
    /// 分片场景下 = 已收到但不足一整帧的部分。
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}
