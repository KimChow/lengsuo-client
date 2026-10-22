//! 消息帧编解码（契约 §5.2）。
//!
//! # 帧格式
//!
//! ```text
//! 偏移  宽度  字段      语义
//! 0     4    len       u32 **大端**（网络字节序）= payload 字节数
//! 4     1    type      u8
//! 5     3    reserved  u8×3，必须为 0
//! 8     ..   payload   len 字节
//! ```
//!
//! ⛔ **`len` 是 payload 字节数，不含帧头** ⇒ 整帧总长 = `8 + len`。
//!
//! # 失败即失败
//!
//! 解码只在这四种情况下返回错误，且**一律 fail-closed**：
//! - `len` 超过 1 MiB ⇒ **立刻失败**（不等数据、不截断、不读越界）；
//! - `reserved` 非 0；
//! - `type` 不在已知集合内；
//! - 帧头或载荷被截断。
//!
//! 解码器**只在缓冲至少 `8 + len` 字节时才成功返回**，否则报错；
//! 它从不「先截断到可用长度再解」，也从不「等更多数据」。
//!
//! # 无状态
//!
//! 本模块不持有任何状态：没有 socket、没有文件、没有线程。

use crate::error::FrameError;
use crate::message::MessageType;

/// 帧头固定长度：`len`(4) + `type`(1) + `reserved`(3)。
pub const FRAME_HEADER_LEN: usize = 8;

/// 保留位字段的宽度（3 字节，必须全为 0）。
pub const RESERVED_LEN: usize = 3;

/// 载荷长度上限：1 MiB。
///
/// 契约 §5.2 的约束是「`len` > 1 MiB ⇒ 解码失败」，
/// 因此**恰好 1 MiB 是合法的**（上限本身含在内）。
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;

/// 一帧的完整内容：消息类型 + 载荷。
///
/// `Debug` **只输出类型与载荷长度**，绝不输出载荷字节
/// （载荷可能承载凭据数据，长度之外的信息都可能泄漏业务内容）。
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    /// 消息类型（契约 §5.3 的编号）。
    pub frame_type: u8,
    /// 载荷字节（长度不超过 [`MAX_PAYLOAD_LEN`]）。
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("frame_type", &self.frame_type)
            .field("payload_len", &self.payload.len())
            // 故意不输出 payload。
            .finish_non_exhaustive()
    }
}

impl Frame {
    /// 构造一帧。
    #[must_use]
    pub fn new(frame_type: u8, payload: Vec<u8>) -> Self {
        Self {
            frame_type,
            payload,
        }
    }

    /// 编码成线上字节：8 字节帧头 + 载荷。
    ///
    /// # Errors
    /// - 载荷长度超过 [`MAX_PAYLOAD_LEN`] ⇒ `FrameError::PayloadTooLong`
    ///   （**不截断**）。
    /// - 消息类型未知 ⇒ `FrameError::UnknownMessageType`
    ///   （不产出「已知类型之外」的帧，避免对端误解）。
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLong {
                declared: self.payload.len() as u64,
                limit: MAX_PAYLOAD_LEN,
            });
        }
        if MessageType::from_u8(self.frame_type).is_none() {
            return Err(FrameError::UnknownMessageType {
                got: self.frame_type,
            });
        }
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        // len：大端 u32 = payload 字节数（不含帧头）。
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.push(self.frame_type);
        out.extend_from_slice(&[0u8; RESERVED_LEN]);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

/// 切分出一个帧：返回帧内容与**已消费的字节数**。
///
/// `consumed` 支持粘包：缓冲里可以有多帧连续排列，本函数只切出**第一帧**，
/// 调用方拿 `consumed` 推进自己的游标后继续切下一帧。
///
/// **长度纪律**：本函数**只按帧头声明的长度**切帧。
/// - 缓冲不足一帧 ⇒ `FrameError::TruncatedPayload`（**不返回部分数据**）。
/// - 缓冲多于一帧 ⇒ **正常返回第一帧**（粘包是常态，不是错误）。
/// - 需要「缓冲必须恰好一帧」时用 [`decode_exact`]。
///
/// # Errors
/// - 帧头字段非法（长度超限 / 保留位非 0 / 类型未知 / 帧头截断）⇒ 对应错误。
/// - 载荷比声明长度短 ⇒ `FrameError::TruncatedPayload`。
pub fn decode(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    let (frame, total) = parse(buf)?;
    Ok((frame, total))
}

/// 切分出**恰好一个**帧：缓冲里多一个字节都算错。
///
/// 与 [`decode`] 的区别：粘包场景请用 [`decode`]（它返回已消费字节数）。
///
/// # Errors
/// - 帧头字段非法 ⇒ 对应错误。
/// - 载荷比声明长度短 ⇒ `FrameError::TruncatedPayload`。
/// - 缓冲多于一个帧 ⇒ `FrameError::TrailingBytes`（**不按实际长度猜**）。
pub fn decode_exact(buf: &[u8]) -> Result<Frame, FrameError> {
    let (frame, total) = parse(buf)?;
    if buf.len() > total {
        return Err(FrameError::TrailingBytes {
            expected: total,
            actual: buf.len(),
        });
    }
    Ok(frame)
}

/// 解析帧头并切出载荷；成功时返回帧与**整帧长度**。
///
/// 校验顺序：**帧头截断 → len 超限 → reserved 非 0 → type 未知 → 载荷截断**。
/// 超限检查排在最前，保证「`len` 超限时立刻失败」——
/// 绝不等数据、绝不截断、绝不读越界。
fn parse(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(FrameError::TruncatedHeader {
            needed: FRAME_HEADER_LEN,
            available: buf.len(),
        });
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLong {
            declared: len as u64,
            limit: MAX_PAYLOAD_LEN,
        });
    }
    let reserved = [buf[5], buf[6], buf[7]];
    if reserved != [0u8; RESERVED_LEN] {
        return Err(FrameError::ReservedNotZero { got: reserved });
    }
    let frame_type = buf[4];
    if MessageType::from_u8(frame_type).is_none() {
        return Err(FrameError::UnknownMessageType { got: frame_type });
    }
    let total = FRAME_HEADER_LEN + len;
    if buf.len() < total {
        return Err(FrameError::TruncatedPayload {
            declared: len,
            available: buf.len() - FRAME_HEADER_LEN,
        });
    }
    Ok((
        Frame {
            frame_type,
            payload: buf[FRAME_HEADER_LEN..total].to_vec(),
        },
        total,
    ))
}
