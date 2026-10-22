//! mux 承载连接（客户端侧出站原语）的读写实现。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）；行为逐字节等价。
//! 结构体本身与其文档示例留在 [`super`]，本模块只承载 `impl MuxWire`。

use std::{sync::Arc, time::Duration};

use ss_core::target::TargetAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
    time::timeout,
};

use crate::mux::frame::{decode_from_async, read_data_async, TargetNetwork};
use crate::mux::worker::{
    write_closing_end, Action, MuxClient, SessionState, SessionWriter, Strategy,
};

use super::handshake::PendingResponseHeader;
use super::session::MuxSession;
use super::{check_deadline, write_to, ClientState, Error, MuxFrame, MuxWire};

impl MuxWire {
    /// 把「已建立的字节流」包装成一条 mux 承载连接。
    ///
    /// `strategy` 对应参考 `ClientStrategy`（`MaxConcurrency` / `MaxConnection`）。
    ///
    /// ⚠️ 该入口假定承载连接上**没有** VLESS 响应头前缀（首字节即 mux 帧流）。
    /// 承载在 VLESS 连接上时必须用 [`MuxWire::new_over_vless`]。
    pub fn new<S>(stream: S, strategy: Strategy) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::build(stream, strategy, false)
    }

    /// 把「一条已发出 VLESS `command=Mux` 头的字节流」包装成 mux 承载连接。
    ///
    /// 参考的 VLESS 响应头与 mux 帧流是**同一条字节流**：承载连接开头先到的是
    /// 响应头（`00 00`），其后才是 mux 帧。本入口登记这段待消费的前缀，由
    /// [`MuxWire::next_inbound`] 在**解第一帧之前**消费掉。
    ///
    /// **写侧从不等响应头**：`open` / `write` 直接发 mux 帧，理由见模块头
    /// 「承载连接上的 VLESS 响应头」。
    pub fn new_over_vless<S>(stream: S, strategy: Strategy) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::build(stream, strategy, true)
    }

    /// 两种入口的共同构造。
    ///
    /// `over_vless` ⇒ 承载连接开头挂着一段待消费的 VLESS 响应头。
    fn build<S>(stream: S, strategy: Strategy, over_vless: bool) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (read, write) = tokio::io::split(stream);
        Self {
            sink: Arc::new(Mutex::new(Box::new(write))),
            source: Box::new(read),
            state: Arc::new(Mutex::new(ClientState {
                client: MuxClient::new(),
                strategy,
            })),
            pending_response_header: if over_vless {
                PendingResponseHeader::present()
            } else {
                PendingResponseHeader::none()
            },
        }
    }

    /// 打开一条逻辑会话：分配会话 ID、登记会话、写出首帧 `New`。
    ///
    /// `first` 是可选首包（参考 `writeFirstPayload`）；`None` 时只发一个不带
    /// 数据段的 `New` 帧（参考「首包超时 ⇒ `WriteMultiBuffer(空)`」）。
    pub async fn open(
        &mut self,
        target: (TargetAddr, TargetNetwork),
        first: Option<&[u8]>,
        deadline: Duration,
    ) -> Result<MuxSession, Error> {
        check_deadline(deadline)?;
        // 帧生成与会话登记在状态锁内完成，落到承载连接上的写发生在锁外。
        let (id, writer, wire) = {
            let mut state = self.state.lock().await;
            // 参考 `ClientWorker.Dispatch`：`sm.Allocate` 后登记会话。
            let strategy = state.strategy;
            let id = state.client.manager.allocate(&strategy)?;
            if !state.client.manager.add(
                id,
                SessionState {
                    target: target.clone(),
                },
            ) {
                return Err(Error::SessionTableClosed);
            }
            let mut writer = SessionWriter::request(id, target.clone(), target.1);
            let mut wire = Vec::new();
            match first {
                // 参考 `writeFirstPayload` 拿到首包 ⇒ 首帧带数据。
                Some(payload) => writer.write_multi(&mut wire, payload)?,
                // 参考 `writeFirstPayload` 超时 ⇒ 空 multi-buffer ⇒ 只发元数据。
                None => writer.write_meta_only(&mut wire)?,
            }
            (id, writer, wire)
        };
        write_to(self.sink.as_ref(), &wire, deadline).await?;
        Ok(MuxSession::new(
            id,
            writer,
            Arc::clone(&self.sink),
            Arc::clone(&self.state),
        ))
    }

    /// 读承载连接上的下一帧，并按参考 `ClientWorker.fetchOutput` 派发。
    ///
    /// 帧头不合法（未知 status/network、`metaLen > 512`、截断）时**直接返回
    /// 错误**：参考在该处 `return`，即终止整条承载连接。调用方必须把错误当作
    /// 「承载连接已终止」处理。
    ///
    /// 派发 `Action::SendEnd`（下行 `Keep` 帧未命中会话）时本方法**自动**写出
    /// 那帧 `End` 通知（参考 `handleStatusKeep` 里的 `closingWriter.Close()`）。
    ///
    /// ⚠️ 若承载连接是经 [`MuxWire::new_over_vless`] 建立的，本方法在解第一帧
    /// **之前**先消费那段 VLESS 响应头（见模块头「承载连接上的 VLESS 响应头」）。
    pub async fn next_inbound(&mut self, deadline: Duration) -> Result<MuxFrame, Error> {
        check_deadline(deadline)?;
        // 承载连接开头的那段 VLESS 响应头：只在**读侧**消费一次。
        // 写侧从不等它 ⇒ 与参考「首个 mux 帧才 flush 响应头」的顺序不会互锁。
        self.pending_response_header
            .consume(&mut self.source, deadline)
            .await?;
        let meta = timeout(deadline, decode_from_async(&mut self.source, false))
            .await
            .map_err(|_| Error::Timeout)??;
        // 参考的四个 handle* 分支在有 OptionData 时都会消费数据段
        // （`buf.Copy(NewStreamReader(reader), buf.Discard)` 或读给会话），
        // 因此**必须**先消费数据段再派发，否则承载连接会错位。
        let stream = self.session_is_stream(meta.session_id).await;
        let data = if meta.has_data() {
            Some(
                timeout(deadline, read_data_async(&mut self.source, stream))
                    .await
                    .map_err(|_| Error::Timeout)??,
            )
        } else {
            None
        };
        let (action, closing) = {
            let mut state = self.state.lock().await;
            let action = state.client.handle(&meta, data)?;
            // 参考 `handleStatusEnd` → `s.Close(false)`：会话从会话表摘除。
            if let Action::CloseSession { id } = action {
                state.client.manager.remove(id);
            }
            let closing = matches!(action, Action::SendEnd { .. });
            (action, closing)
        };
        if closing {
            // 参考 `handleStatusKeep` 未命中会话 ⇒ 回一个 `End` 帧通知对端关闭。
            let mut wire = Vec::new();
            write_closing_end(&mut wire, meta.session_id, TargetNetwork::Tcp)?;
            write_to(self.sink.as_ref(), &wire, deadline).await?;
        }
        Ok(MuxFrame { meta, action })
    }

    /// 通知对端关闭某条会话（参考 `handleStatusKeep` 未命中会话时回的 `End` 帧）。
    ///
    /// [`MuxWire::next_inbound`] 已在派发 `Action::SendEnd` 时自动做过一次；
    /// 本方法供上层需要主动收尾时使用。
    pub async fn send_end(&self, id: u16, deadline: Duration) -> Result<(), Error> {
        check_deadline(deadline)?;
        let mut wire = Vec::new();
        write_closing_end(&mut wire, id, TargetNetwork::Tcp)?;
        write_to(self.sink.as_ref(), &wire, deadline).await
    }

    /// 关闭承载连接的写方向（参考 `ClientWorker.Close` →
    /// `common.Interrupt(m.link.Writer)`）。
    ///
    /// 关闭后对端读到 EOF；本仓的读半边仍可继续读，直到对端也关闭。
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), Error> {
        check_deadline(deadline)?;
        let mut sink = self.sink.lock().await;
        timeout(deadline, sink.shutdown())
            .await
            .map_err(|_| Error::Timeout)??;
        Ok(())
    }

    /// 会话结束后从会话表摘除（参考 `Session.Close` 末尾的 `s.parent.Remove`）。
    pub async fn forget(&self, id: u16) {
        self.state.lock().await.client.manager.remove(id);
    }

    /// 某条会话的目标地址（上层据此把下行数据路由回对应的上游连接）。
    pub async fn session_target(&self, id: u16) -> Option<(TargetAddr, TargetNetwork)> {
        self.state
            .lock()
            .await
            .client
            .manager
            .get(id)
            .map(|session| session.target.clone())
    }

    /// 当前活跃会话数（参考 `SessionManager.Size`）。
    pub async fn active_sessions(&self) -> usize {
        self.state.lock().await.client.manager.size()
    }

    /// 累计分配过的会话数（参考 `SessionManager.Count`）。
    pub async fn total_sessions(&self) -> u16 {
        self.state.lock().await.client.manager.count()
    }

    /// 会话的数据方向是否按流式读（参考 `Session.NewReader`：
    /// `transferType == Stream` ⇒ `NewStreamReader`，否则 `NewPacketReader`）。
    /// 未知会话按流式处理，与参考丢弃路径（`NewStreamReader`）一致。
    async fn session_is_stream(&self, id: u16) -> bool {
        let state = self.state.lock().await;
        state
            .client
            .manager
            .get(id)
            .is_none_or(|session| session.target.1 == TargetNetwork::Tcp)
    }
}
