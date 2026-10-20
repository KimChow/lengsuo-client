//! Mux 会话状态机（对照 Xray `common/mux/{session,client,server}.go`
//! 固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 本模块对齐的是**帧语义与会话管理**，不是参考的 goroutine/buf.Pipe 结构：
//!
//! - `SessionManager` → [`SessionTable`]：`(id → state)`，`Allocate` 自增 id 分配、
//!   `Add`/`Remove`/`Get`、`Close` 全清；
//! - 客户端 `ClientWorker` 的 `fetchOutput` 状态分派 →
//!   [`ClientSession::handle_frame`]（New/Keep/KeepAlive/End 各自语义）；
//! - 客户端 `fetchInput` 的首包 `writeFirstPayload` →
//!   [`StreamSender::send_new`]（`SendFlow` 空闲时发 New 帧，随后 Keep 帧）；
//! - 服务端 `ServerWorker.handleStatusNew/handleStatusKeep/handleStatusEnd` →
//!   [`ServerSession::handle_frame`]（本层不含 dispatcher，改由调用方注入
//!   「建立目标流」的回调 [`TargetDialer`]）。
//!
//! 本层只做**同步**状态机 + 字节流编解码：网络收发由调用方驱动（见
//! `tests/xray_mux.rs` 的夹具），符合本 crate「原语层不做网络」的定位。

use std::collections::BTreeMap;
use std::io::Read;

use ss_core::target::TargetAddr;

use crate::muxframe::{
    decode_address_port, encode_address_port, encode_data_into, read_data, FrameError,
    FrameMetadata, SessionStatus, TargetNetwork, OPTION_DATA, OPTION_ERROR,
};

/// 会话表上限语义（参考 `SessionManager`）：`MaxConcurrency` 限并发会话数，
/// `MaxConnection` 限本连接累计会话数，0 表示不限。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStrategy {
    pub max_concurrency: u32,
    pub max_connection: u32,
}

/// 一个 mux 会话的本地状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub id: u16,
    pub network: TargetNetwork,
    pub target: Option<TargetAddr>,
    /// 输出侧（对端 → 本端）是否已结束。
    pub remote_closed: bool,
    /// 输入侧（本端 → 对端）是否已结束。
    pub local_closed: bool,
    /// 是否已发出过 New 帧（之后一律 Keep）。
    pub new_sent: bool,
}

/// `SessionManager`：id 分配与会话登记。
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: BTreeMap<u16, SessionState>,
    count: u16,
    closed: bool,
    strategy: SessionStrategy,
}

impl SessionTable {
    /// `NewSessionManager` + 策略（参考 `Allocate` 读 `ClientStrategy`）。
    #[must_use]
    pub fn new(strategy: SessionStrategy) -> Self {
        SessionTable {
            sessions: BTreeMap::new(),
            count: 0,
            closed: false,
            strategy,
        }
    }

    /// 当前并发会话数（`Size()`）。
    #[must_use]
    pub fn size(&self) -> usize {
        self.sessions.len()
    }

    /// 累计分配过的会话数（`Count()`）。
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// 是否已关闭。
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// `Allocate`：分配新 id（`m.count++` 后取 `ID = count`，**从 1 开始**）。
    /// 超限或已关闭返回 `None`。
    pub fn allocate(&mut self, network: TargetNetwork, target: TargetAddr) -> Option<SessionState> {
        if self.closed {
            return None;
        }
        if self.strategy.max_concurrency > 0
            && self.sessions.len() >= self.strategy.max_concurrency as usize
        {
            return None;
        }
        if self.strategy.max_connection > 0 && self.count >= self.strategy.max_connection as u16 {
            return None;
        }
        self.count = self.count.wrapping_add(1);
        let state = SessionState {
            id: self.count,
            network,
            target: Some(target),
            remote_closed: false,
            local_closed: false,
            new_sent: false,
        };
        self.sessions.insert(state.id, state.clone());
        Some(state)
    }

    /// `Add`：按对端指定的 id 登记（服务端方向 `Session{ID: meta.SessionID}`）。
    pub fn add(&mut self, state: SessionState) -> bool {
        if self.closed {
            return false;
        }
        self.count = self.count.wrapping_add(1);
        self.sessions.insert(state.id, state);
        true
    }

    /// `Remove`。
    pub fn remove(&mut self, id: u16) {
        self.sessions.remove(&id);
    }

    /// `Get`。
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&SessionState> {
        self.sessions.get(&id)
    }

    /// `Get` 的可变版。
    pub fn get_mut(&mut self, id: u16) -> Option<&mut SessionState> {
        self.sessions.get_mut(&id)
    }

    /// 已登记的会话 id（升序）。
    pub fn ids(&self) -> Vec<u16> {
        self.sessions.keys().copied().collect()
    }

    /// `Close`：全部会话标记关闭并清表。
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.sessions.clear();
    }

    /// `CloseIfNoSessionAndIdle`：无会话且计数未变时置关闭。
    pub fn close_if_idle(&mut self, check_size: usize, check_count: u16) -> bool {
        if self.closed {
            return true;
        }
        if !self.sessions.is_empty() || check_size != 0 || check_count != self.count {
            return false;
        }
        self.closed = true;
        true
    }
}

/// 子流的逻辑方向：本端读（远端写）与本端写（远端读）。
///
/// 参考里这对读写是两个 `buf.Pipe` 端点；本层把它们显式交给调用方，
/// 由调用方接真实网络或内存通道。
pub trait StreamSink {
    /// 把下行载荷交给本端消费者（`s.output`）。
    fn write(&mut self, payload: &[u8]) -> Result<(), String>;
    /// 对端结束该会话（`s.Close(false)` / `s.output` 关闭）。
    fn close_remote(&mut self) -> Result<(), String>;
    /// 本端结束该会话（收到 End 帧，或本地关闭）。
    fn close_local(&mut self) -> Result<(), String>;
}

/// 空实现：只做记账、不转发（用于纯状态机测试）。
#[derive(Debug, Default)]
pub struct DiscardSink;

impl StreamSink for DiscardSink {
    fn write(&mut self, _payload: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn close_remote(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn close_local(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// 会话建立的回调（服务端方向）：由调用方按目标地址拨号并给出下行通道。
///
/// 对齐参考 `w.dispatcher.Dispatch(ctx, meta.Target)`；本层不实现 dispatcher。
pub trait TargetDialer {
    /// `Dispatch` 失败即放弃该会话（参考 `failed to dispatch request.`）。
    fn dial(
        &mut self,
        target: &TargetAddr,
        network: TargetNetwork,
    ) -> Result<Box<dyn StreamSink>, String>;
    /// 帧级致命错误时的兜底（参考 `closingWriter.Close()` / 断整条 mux 连接）。
    fn abort_all(&mut self) -> Result<(), String>;
}

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
    pub fn open(&mut self, network: TargetNetwork, target: TargetAddr) -> Option<SessionState> {
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

/// 输入侧封装器（`fetchInput` + `Writer`）：把本端字节流切成会话帧。
///
/// 关键语义对齐参考：**New 帧只在「本会话还没有任何输出」时出现**
/// （`getNextFrameMeta` 的 `followup` 标志），首包为空即 `writeMetaOnly`。
pub struct StreamSender {
    pub id: u16,
    pub network: TargetNetwork,
    pub target: TargetAddr,
    /// 已发出过 New（对端可能已建立会话）。
    pub new_sent: bool,
}

impl StreamSender {
    #[must_use]
    pub fn new(id: u16, network: TargetNetwork, target: TargetAddr) -> Self {
        StreamSender {
            id,
            network,
            target,
            new_sent: false,
        }
    }

    /// `writeFirstPayload`：`payload == None` 表示 100ms 内没有首包
    /// （参考 `ErrNotTimeoutReader` / `ErrReadTimeout`）→ 只发 New 元数据帧。
    ///
    /// 参考 `writeMetaOnly`（`writer.go:62-69`）走 `getNextFrameMeta()`，
    /// 其 `Option` 为 0：**元数据帧不得带 `OptionData`**，否则对端会把下一帧
    /// 的长度字段误当作本帧数据长度读走（本卡实跑证据：Xray 报
    /// `unknown status: 108`）。
    ///
    /// `Some(bytes)` 对 Stream 按 8KiB 切分，且**每片各自成帧**
    /// （`WriteMultiBuffer` → 每片一次 `writeData`：首片 New，其余 Keep）；
    /// 对 UDP（Packet）一次调用即一个数据报、一帧。
    pub fn send_new(
        &mut self,
        out: &mut Vec<u8>,
        payload: Option<&[u8]>,
    ) -> Result<(), FrameError> {
        let pieces = payload.map_or_else(Vec::new, |bytes| self.frame_payloads(bytes));
        let meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::New,
            option: if pieces.is_empty() { 0 } else { OPTION_DATA },
            target: Some((self.target.clone(), self.network)),
            source: None,
            local: None,
        };
        meta.encode_into(out)?;
        self.new_sent = true;
        if let Some(first) = pieces.first().copied() {
            encode_data_into(out, first)?;
            for piece in &pieces[1..] {
                self.write_keep_data(out, piece)?;
            }
        }
        Ok(())
    }

    /// `writeData`：后续数据一律 Keep 帧（`getNextFrameMeta` 的 followup 分支）。
    pub fn send_keep(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FrameError> {
        if !self.new_sent {
            return self.send_new(out, Some(payload));
        }
        for piece in self.frame_payloads(payload) {
            self.write_keep_data(out, piece)?;
        }
        Ok(())
    }

    /// 空 `WriteMultiBuffer`：只发元数据，不发数据段（`writeMetaOnly`，Option=0）。
    pub fn send_keep_meta_only(&mut self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::Keep,
            option: 0,
            target: None,
            source: None,
            local: None,
        };
        meta.encode_into(out)
    }

    /// `Writer.Close()`：`SessionStatusEnd`（出错时带 `OptionError`）。
    pub fn send_end(&mut self, out: &mut Vec<u8>, had_error: bool) -> Result<(), FrameError> {
        let option = if had_error { OPTION_ERROR } else { 0 };
        ServerSession::encode_frame(out, self.id, SessionStatus::End, option, None)
    }

    /// 参考 `Writer.WriteMultiBuffer` 的分片：Stream 用
    /// `buf.SplitSize(mb, 8*1024)`（每片一帧），Packet 用 `SplitFirst`
    /// （每次一个数据报、一帧）。
    fn frame_payloads<'a>(&self, payload: &'a [u8]) -> Vec<&'a [u8]> {
        if payload.is_empty() {
            Vec::new()
        } else if self.network == TargetNetwork::Udp {
            vec![payload]
        } else {
            payload
                .chunks(crate::muxframe::SESSION_CHUNK_SIZE)
                .collect()
        }
    }

    /// 一个 Keep 元数据 + 单段数据的完整帧。
    fn write_keep_data(&self, out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FrameError> {
        let meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::Keep,
            option: OPTION_DATA,
            target: None,
            source: None,
            local: None,
        };
        meta.encode_into(out)?;
        encode_data_into(out, payload)
    }
}

/// 读端帧迭代器（`ClientWorker.fetchOutput` / `ServerWorker.run` 的读循环）。
///
/// 每帧返回 `(meta, payload)`：`payload` 为 `Some` 表示该帧后跟数据段
/// （长度由帧内 `BE16` 给出），否则为 `None`。`stream` 决定数据段长度上限
/// （会话 transferType：stream=8192、packet=8192）。
pub struct FrameReader<R: Read> {
    reader: R,
    read_source_and_local: bool,
}

impl<R: Read> FrameReader<R> {
    #[must_use]
    pub fn new(reader: R, read_source_and_local: bool) -> Self {
        FrameReader {
            reader,
            read_source_and_local,
        }
    }

    /// 读一个帧（元数据 + 可选数据段）。
    pub fn next_frame(&mut self) -> Result<(FrameMetadata, Option<Vec<u8>>), FrameError> {
        let meta = FrameMetadata::decode_from(&mut self.reader, self.read_source_and_local)?;
        let payload = if meta.has_data() {
            Some(read_data(&mut self.reader, true)?)
        } else {
            None
        };
        Ok((meta, payload))
    }
}

/// 便捷：把「元数据 + 载荷」编成一条完整帧（New/Keep 带数据时用）。
pub fn encode_frame_with_payload(
    session_id: u16,
    status: SessionStatus,
    option: u8,
    target: Option<(&TargetAddr, TargetNetwork)>,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>, FrameError> {
    let meta = FrameMetadata {
        session_id,
        status,
        option,
        target: target.map(|(addr, network)| (addr.clone(), network)),
        source: None,
        local: None,
    };
    let mut out = Vec::new();
    meta.encode_into(&mut out)?;
    if let Some(data) = payload {
        encode_data_into(&mut out, data)?;
    }
    Ok(out)
}

/// 供调用方复用的地址段辅助（与 [`crate::server::decode`] 的 PortThenAddress 同构，
/// 但本层必须独立实现以对齐 `protocol.PortThenAddress` 的字节推进语义）。
pub fn address_port_len(addr: &TargetAddr) -> usize {
    let mut sink = Vec::new();
    encode_address_port(&mut sink, addr).expect("地址可编码");
    sink.len()
}

/// 反向：从字节流直接读一个地址段（含端口），供调用方解析自定义扩展。
pub fn read_address_port(bytes: &[u8]) -> Result<(TargetAddr, usize), FrameError> {
    decode_address_port(bytes)
}
