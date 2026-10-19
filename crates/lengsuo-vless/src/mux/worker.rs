//! 通用多会话 Mux 工作端（对照 Xray `common/mux/{session,client,server,writer,reader}.go`，
//! 固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 本层是**纯逻辑**转写：不持有 socket，输入输出由调用方以 [`AsyncRead`]/[`AsyncWrite`]
//! 注入（参考用 `buf.Reader`/`buf.Writer` 与 `transport.Link`）。会话的上游/下游
//! 数据面（`buf.Copy`）由调用方驱动，本层只负责帧状态机与会话表，因为参考的
//! `transport.Link` 语义（pipe + 中断）与 Rust 侧 relay 需要一一对应而非「等价」。
//!
//! 逐条对齐参考的语义：
//! - `SessionManager::Allocate`：`MaxConcurrency` 按**活跃会话数**、`MaxConnection`
//!   按**累计会话数**限制；`count` 为单调递增的会话 ID 分配器（从 1 起）；
//! - `CloseIfNoSessionAndIdle`：仅当无活跃会话、`checkSize==0` 且 `count` 未变时关闭；
//! - 客户端 `fetchOutput`：KeepAlive/New 只丢数据，Keep/End 按会话表处理，**未知状态
//!   终止整条 Mux 连接**（参考直接 `return`）；
//! - 服务端 `handleStatusNew`：`GlobalID` 非空分支在本卡不实现（XUDP 跨连接恢复
//!   不在范围，见报告「偏离清单」）；会话建立失败即返回错误（会断开整条 Mux 连接）；
//! - 两端 `handleStatusKeep`：会话不存在时回一个 `End` 帧通知对端关闭，并继续丢弃
//!   后续数据；写入下游失败（`buf.IsWriteError`）时关闭该会话并丢弃余下数据；
//! - `Writer`：首帧 `New`、后续 `Keep`、`Close` 发 `End`（`has_error` 时置
//!   `OptionError`）；`transferType==Stream` 时按 8192 分片，Packet 时一帧一包。

use std::collections::HashMap;
use std::io::Write;

use crate::mux::frame::{
    encode_data_into, FrameError, FrameMetadata, SessionStatus, TargetNetwork, OPTION_ERROR,
    STREAM_CHUNK_SIZE,
};
use ss_core::target::TargetAddr;

/// 会话 ID 分配与查询（`SessionManager`）。
///
/// 与参考一致：`count` 单调递增用于下发 ID，**不复用**已关闭会话的 ID；
/// `size` 为当前活跃会话数。
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<u16, SessionState>,
    count: u16,
    closed: bool,
}

/// 会话表里的静态信息（参考 `Session` 中与网络无关的部分）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    /// 目标地址与网络。
    pub target: (TargetAddr, TargetNetwork),
}

/// 客户端/服务端策略（参考 `ClientStrategy`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Strategy {
    /// 单条 Mux 连接上的最大**活跃**会话数；0 表示不限制。
    pub max_concurrency: u32,
    /// 单条 Mux 连接上的最大**累计**会话数；0 表示不限制。
    pub max_connection: u32,
}

/// 分配失败的原因（参考 `Allocate` 返回 `nil`）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocateError {
    /// 会话表已关闭。
    #[error("mux session manager closed")]
    Closed,
    /// 活跃会话数达到 `MaxConcurrency`。
    #[error("mux session concurrency limit reached")]
    ConcurrencyLimit,
    /// 累计会话数达到 `MaxConnection`。
    #[error("mux session connection limit reached")]
    ConnectionLimit,
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `Closed()`。
    #[must_use]
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// `Size()`：活跃会话数。
    #[must_use]
    pub fn size(&self) -> usize {
        self.sessions.len()
    }

    /// `Count()`：累计分配过的会话数。
    #[must_use]
    pub fn count(&self) -> u16 {
        self.count
    }

    /// `Allocate`：分配一个新的会话 ID。
    ///
    /// 参考在 `closed || (MaxConcurrency>0 && len>=MaxConcurrency) ||
    /// (MaxConnection>0 && count>=MaxConnection)` 时返回 `nil`。
    pub fn allocate(&mut self, strategy: &Strategy) -> Result<u16, AllocateError> {
        if self.closed {
            return Err(AllocateError::Closed);
        }
        if strategy.max_concurrency > 0 && self.sessions.len() >= strategy.max_concurrency as usize
        {
            return Err(AllocateError::ConcurrencyLimit);
        }
        if strategy.max_connection > 0 && self.count >= strategy.max_connection as u16 {
            return Err(AllocateError::ConnectionLimit);
        }
        // 参考 `m.count++` 后取 `ID: m.count`；u16 回绕在 65535 时不被参考处理，
        // 本层同样照抄（不额外校验），但用 wrapping 避免 debug 构建 panic。
        self.count = self.count.wrapping_add(1);
        Ok(self.count)
    }

    /// `Add`：把（已分配 ID 的）会话登记进表；表已关闭时返回 false 并且**不**登记。
    pub fn add(&mut self, id: u16, state: SessionState) -> bool {
        if self.closed {
            return false;
        }
        self.sessions.insert(id, state);
        true
    }

    /// `Remove`。
    pub fn remove(&mut self, id: u16) {
        if self.closed {
            return;
        }
        self.sessions.remove(&id);
    }

    /// `Get`。
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&SessionState> {
        if self.closed {
            return None;
        }
        self.sessions.get(&id)
    }

    /// `CloseIfNoSessionAndIdle`：无活跃会话且 `count` 与观察点一致时才关闭。
    pub fn close_if_no_session_and_idle(&mut self, check_size: usize, check_count: u16) -> bool {
        if self.closed {
            return true;
        }
        if !self.sessions.is_empty() || check_size != 0 || check_count != self.count {
            return false;
        }
        self.closed = true;
        self.sessions.clear();
        true
    }

    /// `Close`。
    pub fn close(&mut self) {
        self.closed = true;
        self.sessions.clear();
    }
}

/// 会话方向的数据写入端（`Writer`），负责按会话状态生成帧。
///
/// 参考的 `NewWriter`（请求侧）与 `NewResponseWriter`（响应侧）分别对应
/// [`SessionWriter::request`] 与 [`SessionWriter::response`]。
#[derive(Debug)]
pub struct SessionWriter {
    /// 目标地址（`FrameMetadata.Target`）；响应侧保持 `None`（参考里为零值）。
    dest: Option<(TargetAddr, TargetNetwork)>,
    /// 会话数据方向是否按分组（UDP）语义走，决定是否写「续帧目标地址」。
    packet: bool,
    id: u16,
    followup: bool,
    pub has_error: bool,
    stream: bool,
}

impl SessionWriter {
    /// `NewWriter`：请求侧，首帧 `New`（带目标地址），后续 `Keep`。
    #[must_use]
    pub fn request(id: u16, dest: (TargetAddr, TargetNetwork), network: TargetNetwork) -> Self {
        Self {
            id,
            dest: Some(dest),
            packet: network == TargetNetwork::Udp,
            followup: false,
            has_error: false,
            stream: network == TargetNetwork::Tcp,
        }
    }

    /// `NewResponseWriter`：响应侧，无目标地址，首帧即 `Keep`。
    #[must_use]
    pub fn response(id: u16, network: TargetNetwork) -> Self {
        Self {
            id,
            // 参考的 response writer `dest` 为零值（`net.Destination{}`）：响应方向
            // 不写目标地址，仅在分组会话续帧时写 `b.UDP`（本层无 GlobalID，见模块头）。
            dest: None,
            packet: network == TargetNetwork::Udp,
            followup: true,
            has_error: false,
            stream: network == TargetNetwork::Tcp,
        }
    }

    /// `getNextFrameMeta`。
    fn next_meta(&mut self) -> FrameMetadata {
        let status = if self.followup {
            SessionStatus::Keep
        } else {
            self.followup = true;
            SessionStatus::New
        };
        // 参考 `getNextFrameMeta` 只区分 followup，UDP 状态由其自身的 `followup`
        // 构造器参数决定；本层让 `udp_continuation` 仅在**续帧**上生效，
        // 避免把 `New` 帧的地址段误当成续帧分支（`New` 分支本就写地址）。
        let udp_continuation = self.followup && self.packet;
        FrameMetadata {
            session_id: self.id,
            status,
            option: 0,
            target: self.dest.clone(),
            source: None,
            local: None,
            // 参考 `b.UDP != nil`：分组会话的续帧也写目标地址。
            udp_continuation,
        }
    }

    /// 构造本会话的下一个帧头（含 `OptionData` 时由调用方置位）。
    ///
    /// 与 [`SessionWriter::write_data`] 同源，供需要自行拼帧的 tokio 调用方使用
    /// （例如把 `Keep` 帧连同数据一次写出）。
    #[must_use]
    pub fn next_keep(&mut self) -> FrameMetadata {
        let mut meta = self.next_meta();
        meta.option |= crate::mux::frame::OPTION_DATA;
        meta
    }

    /// `writeMetaOnly`：只发一个元数据帧（无数据段），用于空载荷/首包欺骗窗口。
    pub fn write_meta_only<W: Write>(&mut self, out: &mut W) -> Result<(), FrameError> {
        let meta = self.next_meta();
        let mut wire = Vec::new();
        meta.encode_into(&mut wire)?;
        write_all(out, &wire)
    }

    /// `writeData`：`OptionData` 置位 + `BE16 长度 || 数据`。
    pub fn write_data<W: Write>(&mut self, out: &mut W, payload: &[u8]) -> Result<(), FrameError> {
        let mut meta = self.next_meta();
        meta.option |= crate::mux::frame::OPTION_DATA;
        let mut wire = Vec::new();
        meta.encode_into(&mut wire)?;
        encode_data_into(&mut wire, payload)?;
        write_all(out, &wire)
    }

    /// `WriteMultiBuffer`：空载荷 => 只发元数据；`Stream` 按 8192 分片，
    /// 分组（Packet）侧由调用方保证「一帧一包」。
    pub fn write_multi<W: Write>(&mut self, out: &mut W, payload: &[u8]) -> Result<(), FrameError> {
        if payload.is_empty() {
            return self.write_meta_only(out);
        }
        if self.stream {
            for chunk in payload.chunks(STREAM_CHUNK_SIZE) {
                self.write_data(out, chunk)?;
            }
            Ok(())
        } else {
            self.write_data(out, payload)
        }
    }

    /// `Close`：发 `End` 帧。
    pub fn close<W: Write>(&mut self, out: &mut W) -> Result<(), FrameError> {
        let mut meta = FrameMetadata {
            session_id: self.id,
            status: SessionStatus::End,
            option: 0,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        };
        if self.has_error {
            meta.option |= OPTION_ERROR;
        }
        let mut wire = Vec::new();
        meta.encode_into(&mut wire)?;
        write_all(out, &wire)
    }
}

/// `NewResponseWriter(...).Close()`：会话不存在时通知对端关闭。
pub fn write_closing_end<W: Write>(
    out: &mut W,
    id: u16,
    network: TargetNetwork,
) -> Result<(), FrameError> {
    SessionWriter::response(id, network).close(out)
}

/// 参考 `buf.IsWriteError`：下游已关闭/断管，属于「本会话可独立失败」的写入错误。
#[must_use]
pub fn is_write_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// 帧处理后的下一步动作，交调用方执行（数据面归调用方，见模块头）。
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// 无动作。
    None,
    /// 把该会话的后续数据写入其下游；`payload` 为本帧数据段。
    Deliver {
        id: u16,
        payload: Vec<u8>,
        new: bool,
    },
    /// 关闭该会话（对端 End、或本端下发失败）。
    CloseSession { id: u16 },
    /// 通知对端关闭会话（`Keep` 未命中会话时回 `End`）。
    SendEnd { id: u16 },
}

/// 客户端状态机（`ClientWorker.fetchOutput`）。`handleStatusNew` 在客户端侧只丢弃
/// 数据（下行 New 帧不承载新会话，服务端从不主动开新会话）。
#[derive(Debug, Default)]
pub struct MuxClient {
    pub manager: SessionManager,
}

impl MuxClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 处理一个已解码帧头 + 其数据段（`data` 为 `OptionData` 时读出的数据）。
    ///
    /// 返回 `Err` 表示**终止整条 Mux 连接**（未知状态；参考 `default` 分支
    /// `errors.LogError` 后 `return`）。
    pub fn handle(
        &mut self,
        meta: &FrameMetadata,
        data: Option<Vec<u8>>,
    ) -> Result<Action, FrameError> {
        match meta.status {
            SessionStatus::KeepAlive | SessionStatus::New => {
                // 参考 handleStatueKeepAlive/handleStatusNew：置位 OptionData 则丢弃。
                Ok(Action::None)
            }
            SessionStatus::Keep => {
                let Some(data) = data else {
                    return Ok(Action::None);
                };
                if self.manager.get(meta.session_id).is_none() {
                    return Ok(Action::SendEnd {
                        id: meta.session_id,
                    });
                }
                Ok(Action::Deliver {
                    id: meta.session_id,
                    payload: data,
                    new: false,
                })
            }
            SessionStatus::End => {
                if self.manager.get(meta.session_id).is_some() {
                    return Ok(Action::CloseSession {
                        id: meta.session_id,
                    });
                }
                Ok(Action::None)
            }
        }
    }
}

/// 服务端状态机（`ServerWorker.handleFrame`）。
#[derive(Debug, Default)]
pub struct MuxServer {
    pub manager: SessionManager,
    /// 允许的目标网络（`session.AllowedNetworkFromContext`）；`None` 表示不限制。
    pub allowed_network: Option<TargetNetwork>,
}

impl MuxServer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `handleStatusNew` 的会话登记部分：校验网络、登记会话。
    ///
    /// 返回需要**断开整条 Mux 连接**的错误时，调用方必须终止连接（参考在
    /// `handleStatusNew` 里直接返回 error，`run` 随即退出）。
    pub fn handle_new(&mut self, meta: &FrameMetadata) -> Result<u16, FrameError> {
        let Some((_target, network)) = meta.target.as_ref() else {
            // 参考对 `New` 帧必然解析出 Target；缺失即协议错误。
            return Err(FrameError::ShortMeta { got: 0 });
        };
        if let Some(allowed) = self.allowed_network {
            if *network != allowed {
                // 参考：`unexpected network`，会断开整条 Mux 连接。
                return Err(FrameError::UnknownNetwork {
                    network: network.to_byte(),
                });
            }
        }
        if self.manager.get(meta.session_id).is_some() {
            // 参考在 `SessionManager.Add` 里直接覆盖；此处保持同样的宽松语义，
            // 由调用方决定是否先关闭旧会话（服务端侧目标相同，覆盖等价）。
            self.manager.remove(meta.session_id);
        }
        let state = SessionState {
            target: meta.target.clone().expect("上面已校验存在"),
        };
        if !self.manager.add(meta.session_id, state) {
            // 参考 `failed to add new session`。
            return Err(FrameError::MetaTooLong);
        }
        Ok(meta.session_id)
    }

    /// 处理一个已解码帧头（非 `New` 分支；`New` 走 [`MuxServer::handle_new`]）。
    pub fn handle(
        &mut self,
        meta: &FrameMetadata,
        data: Option<Vec<u8>>,
    ) -> Result<Action, FrameError> {
        match meta.status {
            SessionStatus::KeepAlive => Ok(Action::None),
            SessionStatus::Keep => {
                let Some(data) = data else {
                    return Ok(Action::None);
                };
                if self.manager.get(meta.session_id).is_none() {
                    return Ok(Action::SendEnd {
                        id: meta.session_id,
                    });
                }
                Ok(Action::Deliver {
                    id: meta.session_id,
                    payload: data,
                    new: false,
                })
            }
            SessionStatus::End => {
                if self.manager.get(meta.session_id).is_some() {
                    return Ok(Action::CloseSession {
                        id: meta.session_id,
                    });
                }
                Ok(Action::None)
            }
            SessionStatus::New => Ok(Action::None),
        }
    }
}

fn write_all<W: Write>(out: &mut W, bytes: &[u8]) -> Result<(), FrameError> {
    out.write_all(bytes)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))
}
