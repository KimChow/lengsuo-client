//! 承载连接上那段 **VLESS 响应头**的消费（握手顺序的关键）。
//!
//! ## 事实：响应头是 1 字节 version ＋ 1 字节 addons 长度
//!
//! 参考 `proxy/vless/encoding/encoding.go:135` 的 `EncodeResponseHeader` 写的是
//! 「1 字节 version ＋ `EncodeHeaderAddons` 写的 1 字节 addons 长度（＋ 长度非 0
//! 时的 addons 载荷）」。
//!
//! 参考 `proxy/vless/encoding/addons.go:18` 的 `EncodeHeaderAddons` 只在
//! `Flow == XRV` 时写非 0 长度；而参考入站的响应固定用空 `Addons`
//! （`proxy/vless/inbound/inbound.go:546` 的 `responseAddons` 未设 `Flow`）
//! ⇒ **线上响应头恒为 2 字节 `00 00`**。
//!
//! ## 事实：响应头与 mux 帧流是同一条字节流
//!
//! 参考 `proxy/vless/inbound/inbound.go:618-634`：
//!
//! ```text
//! bufferWriter := buf.NewBufferedWriter(buf.NewWriter(connection))
//! encoding.EncodeResponseHeader(bufferWriter, request, responseAddons) // 写进缓冲
//! clientWriter := encoding.EncodeBodyAddons(bufferWriter, ...)
//! bufferWriter.SetFlushNext()   // ← 在响应头写完「之后」才设
//! ```
//!
//! 参考 `common/buf/writer.go` 的 `SetFlushNext()` 只让**下一次 Write** 触发 flush
//! （`if w.flushNext { w.buffered = false; return w.flushInternal() }`），而那次
//! Write 发生在 `SetFlushNext()` **之前** ⇒ **响应头滞留缓冲区**，要等**第一个
//! mux 数据帧写回**时才一起 flush。
//!
//! 参考自己的客户端为什么不死锁：`proxy/vless/outbound/outbound.go:321` 的
//! `postRequest` 里 `buf.Copy(clientReader, serverWriter, ...)` **持续**把 mux 帧流
//! 转发给服务器，服务器的响应头与 mux 数据**一起**回来；参考 mux 客户端
//! `common/mux/client.go:382` 的 `fetchOutput` 也**直接读帧流**，不单独读响应头。
//!
//! ⇒ **不能先阻塞等响应头再发帧**：那会让「我方等响应头」与「对端等第一个帧才
//! flush 响应头」互锁成死锁。
//!
//! 参考自己的客户端为什么不被这个顺序坑到：它的 `postRequest` 与 `getResponse`
//! 是**两个 goroutine**（`outbound.go:321`），`postRequest` 里
//! `buf.Copy(clientReader, serverWriter, ...)` **持续**转发 mux 帧流；
//! `getResponse`（`:384`）读响应头只是响应侧的一条路径。本仓的 `MuxWire` 是
//! **单线程**读侧，没有那个并发结构 ⇒ 必须自己保证「写侧先发帧」。
//!
//! 本模块的处置：响应头**只在读侧**消费一次（解第一帧之前），写侧从不等它。

use std::time::Duration;

use tokio::io::AsyncRead;

use super::Error;

/// 承载连接开头是否还挂着一段待消费的 VLESS 响应头。
///
/// `true` ⇒ 第一帧之前要先消费响应头；消费后立即置回 `false`（只消费一次）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct PendingResponseHeader {
    pending: bool,
}

impl PendingResponseHeader {
    /// 「没有响应头前缀」的承载连接（首字节即 mux 帧流）。
    pub(super) const fn none() -> Self {
        Self { pending: false }
    }

    /// 「开头有 VLESS 响应头」的承载连接。
    pub(super) const fn present() -> Self {
        Self { pending: true }
    }

    /// 是否还挂着待消费的响应头。
    pub(super) const fn is_pending(self) -> bool {
        self.pending
    }

    /// 消费掉响应头（读一次即失效）。
    ///
    /// 返回 `Err` 时响应头已被标记为「不再待消费」：参考在该处终止整条连接，
    /// 不再尝试复用这条承载连接（fail-closed）。
    pub(super) async fn consume<R: AsyncRead + Unpin>(
        &mut self,
        source: &mut R,
        deadline: Duration,
    ) -> Result<(), Error> {
        if !self.pending {
            return Ok(());
        }
        self.pending = false;
        // 参考 `DecodeResponseHeader`：version 必须等于请求 version（线上为 0），
        // addons 按长度字节消费；两者都由 `receive_response_header` 负责。
        // 该函数自带截止时间（`crate::stream::deadline` 判据 + 内部 `timeout`）。
        crate::stream::receive_response_header(source, deadline).await?;
        Ok(())
    }
}
