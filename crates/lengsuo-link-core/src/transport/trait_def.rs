//! L1 的**字节搬运抽象**。
//!
//! 本模块只定义「把**已经封好**的字节交给底层 / 从底层取回一段字节」的契约。
//! ⛔ **它不认识明文**：搬运层只认字节，明文语义属于 L2 会话层。
//!
//! # 契约要点
//!
//! | 方法 | 入参 | 返回 | 语义 |
//! |---|---|---|---|
//! | [`Transport::send`] | **已封好的密文字节** | `()` | 交出去；失败 ⇒ 报错，**不得**吞掉 |
//! | [`Transport::recv`] | — | 一段收到的**字节** | 取回；暂时没数据 ⇒ [`TransportError::WouldBlock`] |
//!
//! - **同步、阻塞语义由调用方决定**：本 crate 不引入任何运行时
//!   （⛔ 无 tokio / 无线程 / 无计时器）。实现方可以用同步 socket，
//!   也可以在 FFI 侧把它适配成别的东西——**trait 本身不约束**。
//! - **不要求实现方提供明文语义**：实现方永远只看字节。
//! - **单帧长度上限**由搬运层把关：超过 [`crate::frame::MAX_FRAME_LEN`]
//!   的字节必须**明确报错**（[`TransportError::TooLong`]），
//!   ⛔ 不得静默截断、⛔ 不得当作合法帧往下传。
//!
//! # 错误
//!
//! 错误一律是 [`TransportError`]，带**稳定数字码 + 稳定字符串标签**
//! （见 [`crate::transport::ErrorCode`］）。⛔ **不得**拿 Rust `Debug` 文本当跨端契约。

use crate::frame::MAX_FRAME_LEN;

use super::error::TransportError;

/// 字节搬运抽象（L1 传输）。
///
/// 实现方负责**怎么把字节送到对端**（UDP / QUIC / TCP / 内存环回……），
/// 但**只搬字节**：既不加密，也不解密，更不认识明文。
///
/// # 契约（实现方必须遵守）
///
/// 1. [`send`](Transport::send) 的入参**必须是已经封好的密文字节**
///    （帧头 + AEAD 密文包）。实现方**不得**对其做任何再加工。
/// 2. [`recv`](Transport::recv) 返回**一段收到的字节**；实现方**不得**
///    猜测内容、不得过滤、不得把明文塞进来。
/// 3. 收到/要发的字节长度**不得超过** [`MAX_FRAME_LEN`]：
///    超限必须返回 [`TransportError::TooLong`]，
///    ⛔ **不得静默截断**、⛔ **不得当作合法帧往下传**。
/// 4. 暂时没有数据时返回 [`TransportError::WouldBlock`]——
///    这**不是**失败（会话仍然有效），调用方应当退避后重试。
/// 5. 链路不可用时返回 [`TransportError::Closed`] 或 [`TransportError::Io`]。
/// 6. **不得**在实现里吞掉错误、不得把失败改写成「成功」。
///
/// 错误码的稳定目录见 [`crate::transport::ErrorCode`]。
///
/// # 线程安全
///
/// 本 trait **不要求** `Send` / `Sync`：单端链路的搬运上下文通常由
/// 调用方独占持有。需要跨线程时由实现方自行包裹。
pub trait Transport {
    /// 送出一段**已封好的**字节。
    ///
    /// # Errors
    /// - 链路不可用 ⇒ [`TransportError::Closed`] / [`TransportError::Io`]。
    /// - 字节数超过 [`MAX_FRAME_LEN`] ⇒ [`TransportError::TooLong`]
    ///   （**写入前**拒绝，⛔ 不截断）。
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// 取回一段收到的字节。
    ///
    /// # Errors
    /// - 暂时没有数据 ⇒ [`TransportError::WouldBlock`]（**不是失败**）。
    /// - 链路不可用 ⇒ [`TransportError::Closed`] / [`TransportError::Io`]。
    /// - 收到的字节数超过 [`MAX_FRAME_LEN`] ⇒ [`TransportError::TooLong`]
    ///   （**不截断**、⛔ 不当作合法帧往下传）。
    fn recv(&mut self) -> Result<Vec<u8>, TransportError>;

    /// 本端看到的**最大**单帧字节数（搬运层的准入上限）。
    ///
    /// 默认取 [`MAX_FRAME_LEN`]；实现方（如分片重组的传输）可以给出更小的值。
    /// 接线层用它判断「这段字节是否值得交给会话层」。
    #[must_use]
    fn max_frame_len(&self) -> usize {
        MAX_FRAME_LEN
    }
}

/// 判断一段字节是否**可以**交给会话层。
///
/// 超过搬运层的准入上限 ⇒ 明确失败（⛔ 不截断、⛔ 不当合法帧往下传）。
///
/// # Errors
/// 超过 `limit` ⇒ [`TransportError::TooLong`]。
pub(crate) fn check_frame_len(actual: usize, limit: usize) -> Result<(), TransportError> {
    if actual > limit {
        return Err(TransportError::TooLong { actual, limit });
    }
    Ok(())
}
