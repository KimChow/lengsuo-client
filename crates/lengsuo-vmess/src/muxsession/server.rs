//! 服务端方向的 Mux 会话状态机（参考 `common/mux/server.go` 的
//! `ServerWorker` 的三个 handle 函数 + `run`）。
//!
//! 语义来源：参考 `common/mux/server.go`，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::collections::BTreeMap;

use crate::muxframe::{encode_data_into, FrameError, FrameMetadata, SessionStatus};

use super::sink::{StreamSink, TargetDialer};
use super::table::{SessionState, SessionStrategy, SessionTable};

/// 服务端方向的会话状态机（`ServerWorker` 的三个 handle 函数 + `run`）。
pub struct ServerSession {
    table: SessionTable,
    sinks: BTreeMap<u16, Box<dyn StreamSink>>,
}

impl ServerSession {
    #[must_use]
    pub fn new(strategy: SessionStrategy) -> Self {
        ServerSession {
            table: SessionTable::new(strategy),
            sinks: BTreeMap::new(),
        }
    }

    /// 会话表只读访问（测试断言用）。
    #[must_use]
    pub const fn table(&self) -> &SessionTable {
        &self.table
    }

    /// 处理一个帧（不含数据段）：`handleFrame` 的状态分派。
    ///
    /// `Data` 帧的数据段由调用方先按 `meta.has_data()` 读出并作为 `payload`
    /// 传入——这样本层保持无 I/O（除元数据解析）。
    pub fn handle_frame<D: TargetDialer>(
        &mut self,
        meta: &FrameMetadata,
        payload: Option<&[u8]>,
        dialer: &mut D,
    ) -> Result<(), FrameError> {
        match meta.status {
            SessionStatus::KeepAlive => {
                // 参考 handleStatusKeepAlive：OptionData 时把整条 chunked 流读空丢弃。
                Ok(())
            }
            SessionStatus::End => {
                // handleStatusEnd：找到即关闭；带数据则读完丢弃（本层丢弃 payload）。
                self.close_session(meta.session_id);
                Ok(())
            }
            SessionStatus::New => self.handle_new(meta, payload, dialer),
            SessionStatus::Keep => self.handle_keep(meta, payload),
        }
    }

    fn handle_new<D: TargetDialer>(
        &mut self,
        meta: &FrameMetadata,
        payload: Option<&[u8]>,
        dialer: &mut D,
    ) -> Result<(), FrameError> {
        let Some((target, network)) = meta.target.clone() else {
            // 参考：Heartbeat/padding 之外的 New 必带地址；无地址即解析失败。
            return Err(FrameError::Address);
        };
        let sink = dialer
            .dial(&target, network)
            .map_err(|_| FrameError::Address)?;
        self.sinks.insert(meta.session_id, sink);
        self.table.add(SessionState {
            id: meta.session_id,
            network,
            target: Some(target),
            remote_closed: false,
            local_closed: false,
            new_sent: true,
        });
        // 参考在 `go handle(...)` 之后，若 New 帧带数据则把该帧数据写进会话。
        if let Some(data) = payload {
            self.write_to_session(meta.session_id, data);
        }
        Ok(())
    }

    fn handle_keep(
        &mut self,
        meta: &FrameMetadata,
        payload: Option<&[u8]>,
    ) -> Result<(), FrameError> {
        if !meta.has_data() {
            return Ok(());
        }
        if self.table.get(meta.session_id).is_none() {
            // 参考：未知会话 → `NewResponseWriter(...).Close()`（End 帧）后丢弃。
            self.missing_session_end(meta.session_id);
            return Ok(());
        }
        if let Some(data) = payload {
            self.write_to_session(meta.session_id, data);
        }
        Ok(())
    }

    fn write_to_session(&mut self, id: u16, payload: &[u8]) {
        if let Some(sink) = self.sinks.get_mut(&id) {
            if sink.write(payload).is_err() {
                // 参考 `buf.IsWriteError(err)`：关该会话并继续丢弃后续数据。
                self.close_session(id);
            }
        }
    }

    fn missing_session_end(&mut self, id: u16) {
        if let Some(sink) = self.sinks.get_mut(&id) {
            let _ = sink.close_local();
        }
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

    /// 会话表关闭（`run` 退出时的清理）。
    pub fn shutdown(&mut self) {
        for (_, mut sink) in std::mem::take(&mut self.sinks) {
            let _ = sink.close_local();
        }
        self.table.close();
    }

    /// 输出侧（服务端 → 客户端）封装一帧并追加到 `out`。
    ///
    /// `payload == None` 等价参考 `writeMetaOnly()`（`mb.IsEmpty()` 时只写元数据，
    /// 不发数据段）；`Some(bytes)` 即 `writeMetaWithFrame`。
    pub fn encode_frame(
        out: &mut Vec<u8>,
        session_id: u16,
        status: SessionStatus,
        option: u8,
        payload: Option<&[u8]>,
    ) -> Result<(), FrameError> {
        let meta = FrameMetadata {
            session_id,
            status,
            option,
            target: None,
            source: None,
            local: None,
        };
        meta.encode_into(out)?;
        if let Some(data) = payload {
            encode_data_into(out, data)?;
        }
        Ok(())
    }
}
