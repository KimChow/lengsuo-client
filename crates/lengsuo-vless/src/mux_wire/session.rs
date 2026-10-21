//! mux 承载连接上的**逻辑会话写侧句柄**（`MuxSession`）。
//!
//! ## 与参考的对应（Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//!
//! - [`MuxSession::write`] ≡ 参考 `common/mux/writer.go` 的
//!   `Writer.WriteMultiBuffer`：空载荷只发元数据帧（`writeMetaOnly`）；流式会话
//!   按 8 KiB 分片（`buf.SplitSize(mb, 8*1024)`）；分组（UDP）会话一帧一包
//!   （`buf.SplitFirst`）。
//! - [`MuxSession::close`] ≡ 参考 `Writer.Close`（写 `End` 帧；`hasError` 时带
//!   `OptionError`）＋ `common/mux/session.go` 的 `Session.Close` 末尾的
//!   `s.parent.Remove`。
//! - [`MuxSession::mark_error`] ≡ 参考 `fetchInput` 在拷贝失败时置
//!   `writer.hasError = true`。
//!
//! ## 并发写
//!
//! 多个句柄可并发写同一条承载连接：写半边由 `Arc<Mutex<..>>` 串行化，与参考里
//! `ClientWorker.link.Writer`（`pipe.Writer`，自带锁）语义一致。

use std::{sync::Arc, time::Duration};

use tokio::{io::AsyncWrite, sync::Mutex};

use crate::mux::worker::SessionWriter;

use super::{write_to, ClientState, Error};

/// 逻辑会话的写侧句柄。
///
/// 一个句柄对应承载连接上的一条 mux 会话（参考 `Session`）。多个句柄可并发写
/// 同一条承载连接：写半边由 `Arc<Mutex<..>>` 串行化，与参考里
/// `ClientWorker.link.Writer`（`pipe.Writer`，自带锁）语义一致。
pub struct MuxSession {
    id: u16,
    writer: SessionWriter,
    sink: Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    state: Arc<Mutex<ClientState>>,
}

impl std::fmt::Debug for MuxSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxSession")
            .field("id", &self.id)
            .field("has_error", &self.writer.has_error)
            .finish_non_exhaustive()
    }
}

impl MuxSession {
    /// 由承载连接构造一个会话句柄（仅供 [`super::MuxWire::open`] 调用）。
    pub(super) fn new(
        id: u16,
        writer: SessionWriter,
        sink: Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
        state: Arc<Mutex<ClientState>>,
    ) -> Self {
        Self {
            id,
            writer,
            sink,
            state,
        }
    }

    /// 会话 ID（参考 `Session.ID`）。
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// 标记本次会话以错误收尾：随后的 `End` 帧带 `OptionError`。
    ///
    /// 参考 `fetchInput` 在拷贝失败时置 `writer.hasError = true`。
    pub fn mark_error(&mut self) {
        self.writer.has_error = true;
    }

    /// 写数据（参考 `Writer.WriteMultiBuffer`）。
    ///
    /// - 空载荷 ⇒ 只发一个元数据帧（参考 `writeMetaOnly`）；
    /// - TCP 会话 ⇒ 按 8 KiB 分片，每片一帧（参考 `buf.SplitSize(mb, 8*1024)`）；
    /// - UDP 会话 ⇒ 一帧一包（参考 `buf.SplitFirst`）。
    ///
    /// 整段载荷先编码进内存再落盘（复用 `worker::SessionWriter::write_multi` 这一
    /// 既有原语），故调用方宜按 ≤ 8 KiB 分片调用。
    ///
    /// ⚠️ 本方法**不等** VLESS 响应头：mux 承载连接上响应头与帧流是同一条字节
    /// 流，响应头由读侧消费（见 [`super::MuxWire::new_over_vless`]）。
    pub async fn write(&mut self, payload: &[u8], deadline: Duration) -> Result<(), Error> {
        let mut wire = Vec::new();
        self.writer.write_multi(&mut wire, payload)?;
        write_to(self.sink.as_ref(), &wire, deadline).await
    }

    /// 结束会话：写 `End` 帧并把会话从会话表摘除。
    ///
    /// 参考 `Writer.Close`（写 `End` 帧；`has_error` 时带 `OptionError`）
    /// ＋ `Session.Close` 末尾的 `s.parent.Remove`。
    pub async fn close(mut self, deadline: Duration) -> Result<(), Error> {
        let mut wire = Vec::new();
        self.writer.close(&mut wire)?;
        write_to(self.sink.as_ref(), &wire, deadline).await?;
        self.state.lock().await.client.manager.remove(self.id);
        Ok(())
    }
}
