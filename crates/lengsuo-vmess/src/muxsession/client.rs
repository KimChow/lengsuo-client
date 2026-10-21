//! 客户端方向的 Mux 会话状态机（参考 `common/mux/client.go` 的
//! `ClientWorker.fetchOutput`）。
//!
//! 语义来源：参考 `common/mux/client.go`，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::collections::BTreeMap;

use crate::muxframe::{FrameError, FrameMetadata, SessionStatus, OPTION_ERROR};

use super::server::ServerSession;
use super::sink::StreamSink;
use super::table::{SessionState, SessionStrategy, SessionTable};

/// 客户端方向的会话状态机（`ClientWorker.fetchOutput`）。
pub struct ClientSession {
    table: SessionTable,
    sinks: BTreeMap<u16, Box<dyn StreamSink>>,
}

impl ClientSession {
    #[must_use]
    pub fn new(strategy: SessionStrategy) -> Self {
        ClientSession {
            table: SessionTable::new(strategy),
            sinks: BTreeMap::new(),
        }
    }

    /// 客户端本地发起一个会话（`sm.Allocate(&strategy)`）。
    pub fn open(
        &mut self,
        network: crate::muxframe::TargetNetwork,
        target: ss_core::target::TargetAddr,
    ) -> Option<SessionState> {
        self.table.allocate(network, target)
    }

    /// 注册本地会话的下行通道。
    pub fn attach(&mut self, id: u16, sink: Box<dyn StreamSink>) {
        self.sinks.insert(id, sink);
    }

    /// 会话表只读访问。
    #[must_use]
    pub const fn table(&self) -> &SessionTable {
        &self.table
    }

    /// 处理对端来的一个帧（`handleStatusNew/Keep/KeepAlive/End`）。
    pub fn handle_frame(
        &mut self,
        meta: &FrameMetadata,
        payload: Option<&[u8]>,
    ) -> Result<(), FrameError> {
        match meta.status {
            SessionStatus::KeepAlive => Ok(()),
            // 参考 `handleStatueKeepAlive` / `handleStatusNew`：OptionData 时读完丢弃。
            SessionStatus::New => Ok(()),
            SessionStatus::End => {
                self.close_session(meta.session_id);
                Ok(())
            }
            SessionStatus::Keep => {
                if !meta.has_data() {
                    return Ok(());
                }
                if self.table.get(meta.session_id).is_none() {
                    // 参考：未知会话 → 回一个 End(带错误标志) 帧通知对端关闭。
                    self.missing_session_end(meta.session_id);
                    return Ok(());
                }
                if let Some(data) = payload {
                    if let Some(sink) = self.sinks.get_mut(&meta.session_id) {
                        if sink.write(data).is_err() {
                            self.close_session(meta.session_id);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// 未知会话时服务端/客户端回发的 `NewResponseWriter(...).Close()` 帧。
    /// 参考里 `hasError` 默认 false（`NewResponseWriter` 不置位），故 option = 0。
    #[must_use]
    pub fn closing_end_frame(session_id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        ServerSession::encode_frame(&mut out, session_id, SessionStatus::End, 0, None)
            .expect("End 帧恒可编码");
        out
    }

    fn missing_session_end(&mut self, id: u16) {
        self.sinks.remove(&id);
    }

    fn close_session(&mut self, id: u16) {
        if self.table.get(id).is_some() {
            if let Some(sink) = self.sinks.get_mut(&id) {
                let _ = sink.close_remote();
            }
        }
        self.sinks.remove(&id);
        self.table.remove(id);
    }

    /// 本端结束一个会话并返回要写出的 End 帧（`writer.Close()`）。
    pub fn close_local(&mut self, id: u16, had_error: bool) -> Vec<u8> {
        let option = if had_error { OPTION_ERROR } else { 0 };
        let frame = {
            let mut out = Vec::new();
            ServerSession::encode_frame(&mut out, id, SessionStatus::End, option, None)
                .expect("End 帧恒可编码");
            out
        };
        self.table.remove(id);
        if let Some(mut sink) = self.sinks.remove(&id) {
            let _ = sink.close_local();
        }
        frame
    }

    /// 会话表关闭。
    pub fn shutdown(&mut self) {
        for (_, mut sink) in std::mem::take(&mut self.sinks) {
            let _ = sink.close_local();
        }
        self.table.close();
    }
}
