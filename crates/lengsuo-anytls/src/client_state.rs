//! AnyTLS v2 客户端出站会话状态机：纯内存检查，不含 TLS、认证、网络与 I/O。
//! 基线 anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50
//! `docs/protocol.md` 与 `proxy/session/session.go` 客户端分支；
//! 参考只用于核对语义，本文件不复制其实现。
//! 职责：服务器帧方向、ServerSettings 协商、自配 Stream ID 生命周期、
//! SYNACK 就绪标记、迟到帧归类、心跳关联值透传与 Alert 终止。
//! 不含：SYNACK 超时与隧道恢复、心跳定时、padding 方案解析与重写、
//! 空闲会话复用池、认证、UDP-over-TCP 与任何参考互通。
use crate::frame::{Command, Frame};
use std::collections::{BTreeMap, HashSet};

/// ServerSettings 文本字节上限；参考实现无显式上限，此处为防御性自设上限。
const MAX_SETTINGS_BYTES: usize = 4096;

/// 状态机产出的事件，调用方据此驱动写出与代理业务。
/// 事件不携带应用载荷或错误文本：字节始终由调用方持有的原 `Frame` 提供。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// 已读出但不影响状态：Waste、活跃就绪流上的空数据帧、
    /// 指向本端已关闭流的迟到帧、重复的成功 SYNACK、心跳回复。
    Ignore,
    /// 活跃且已就绪流上的非空数据，载荷仍在原帧中。
    Data(u32),
    /// 版本 2 下该流收到成功 SYNACK，此后可收发数据。
    Ready(u32),
    /// 该流收到带错误文本的 SYNACK，状态机已将其移除；文本仍在原帧中。
    Rejected(u32),
    /// 服务器 FIN 关闭了该活跃流并已移除。
    Closed(u32),
    /// 已采纳 ServerSettings，`version` 为协商出的对端版本。
    Settings { version: u8 },
    /// 服务器请求更新 padding 方案；方案解析与生效不在本模块。
    PaddingUpdate,
    /// 服务器心跳请求，`u32` 是需原样回传的关联值，不是浏览器环境标识。
    Heartbeat(u32),
    /// 服务器 Alert，文本在原帧中；会话随即终止。
    Alert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    #[error("会话配置非法")]
    InvalidConfig,
    #[error("会话已因非法远端帧失效，必须丢弃连接")]
    Poisoned,
    #[error("会话已终止，不接受后续帧或新流")]
    Terminated,
    #[error("尚未标记客户端 Settings 已发送")]
    SettingsNotSent,
    #[error("客户端 Settings 只标记一次")]
    SettingsAlreadySent,
    #[error("活跃流已达上限，未分配流编号")]
    StreamLimitReached,
    #[error("流编号空间已耗尽")]
    StreamIdExhausted,
    #[error("流引用非法：{0}")]
    InvalidStream(&'static str),
    #[error("远端帧 {0:?} 早于客户端 Settings")]
    RemoteBeforeSettings(Command),
    #[error("服务端不得发送客户端方向帧 {0:?}")]
    ClientToServer(Command),
    #[error("版本 1 不使用该帧：{0}")]
    InvalidVersion(&'static str),
    #[error("ServerSettings 非法：{0}")]
    InvalidSettings(&'static str),
}

/// 服务器帧引用的流位置。ID 由本客户端连续分配，因此
/// `0 < id <= 已分配上限` 而不在活跃表中，唯一含义是“该流已被本端关闭”。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    /// 活跃流，`acked` 表示是否已收到成功 SYNACK。
    Active { acked: bool },
    /// 本端已关闭的流：迟到帧静默忽略，不影响其他流。
    Closed,
    /// 编号为零或从未分配：协议违规。
    Invalid(&'static str),
}

/// 单个（假定已认证的）TLS 连接的客户端会话状态。
/// 首个非法远端帧使状态失效，之后 `accept`/`open_stream`/`close_stream` 全部拒绝；
/// 本地 API 参数错误只返回错误，不破坏既有流。
pub struct ClientState {
    max_streams: usize,
    settings_sent: bool,
    server_settings_seen: bool,
    /// 版本协商：默认 1，直到 ServerSettings 升级为 2。
    peer_version: u8,
    /// 已分配的最大流编号；新流编号必须严格为它加一。
    last_allocated: u32,
    /// 活跃流编号 -> 是否已收到成功 SYNACK。不保存任何载荷。
    streams: BTreeMap<u32, bool>,
    poisoned: bool,
    terminated: bool,
}

impl ClientState {
    pub fn new(max_streams: usize) -> Result<Self, ClientError> {
        if max_streams == 0 {
            return Err(ClientError::InvalidConfig);
        }
        Ok(Self {
            max_streams,
            settings_sent: false,
            server_settings_seen: false,
            peer_version: 1,
            last_allocated: 0,
            streams: BTreeMap::new(),
            poisoned: false,
            terminated: false,
        })
    }

    pub fn peer_version(&self) -> u8 {
        self.peer_version
    }

    /// 是否已调用 `mark_settings_sent`，即会话是否可承载非 Waste 帧。
    pub fn settings_sent(&self) -> bool {
        self.settings_sent
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn is_active(&self, stream_id: u32) -> bool {
        self.streams.contains_key(&stream_id)
    }

    /// 流是否可收发数据：版本 1 活跃即就绪；版本 2 必须收到成功 SYNACK。
    /// 不存在的流永远不就绪。
    pub fn is_ready(&self, stream_id: u32) -> bool {
        match self.streams.get(&stream_id) {
            Some(acked) => self.peer_version != 2 || *acked,
            None => false,
        }
    }

    /// 通知状态机客户端 Settings 已写出。只能调用一次；重复调用是本地错误，
    /// 不改变任何已有流状态。
    pub fn mark_settings_sent(&mut self) -> Result<(), ClientError> {
        self.usable()?;
        if self.settings_sent {
            return Err(ClientError::SettingsAlreadySent);
        }
        self.settings_sent = true;
        Ok(())
    }

    /// 分配并登记一条新流。先检查容量再 `checked_add`，因此容量或编号空间不足
    /// 都不消耗编号；编号从 1 开始严格连续，且永不复用。
    pub fn open_stream(&mut self) -> Result<u32, ClientError> {
        self.usable()?;
        if !self.settings_sent {
            return Err(ClientError::SettingsNotSent);
        }
        if self.streams.len() >= self.max_streams {
            return Err(ClientError::StreamLimitReached);
        }
        let id = self
            .last_allocated
            .checked_add(1)
            .ok_or(ClientError::StreamIdExhausted)?;
        self.last_allocated = id;
        self.streams.insert(id, false);
        Ok(id)
    }

    /// 关闭本端流并释放容量。编号不回收、不复用。
    /// `Rejected` 事件已由状态机移除该流，调用方无需再次关闭。
    pub fn close_stream(&mut self, stream_id: u32) -> Result<(), ClientError> {
        self.usable()?;
        match self.locate(stream_id) {
            Location::Active { .. } => {
                self.streams.remove(&stream_id);
                Ok(())
            }
            Location::Closed => Err(ClientError::InvalidStream("流已关闭")),
            Location::Invalid(reason) => Err(ClientError::InvalidStream(reason)),
        }
    }

    /// 接收一个服务器帧。校验全部通过后一次性提交变更；
    /// 远端协议违规会失效整个状态（fail-closed），调用方须随后关闭连接。
    pub fn accept(&mut self, frame: &Frame) -> Result<Event, ClientError> {
        self.usable()?;
        match self.apply(frame) {
            Ok(event) => Ok(event),
            Err(err) => {
                self.poisoned = true;
                Err(err)
            }
        }
    }

    fn apply(&mut self, frame: &Frame) -> Result<Event, ClientError> {
        // Waste 是双向填充：任意流编号与任意长度都只作丢弃，任何时候都允许。
        if frame.command == Command::Waste {
            return Ok(Event::Ignore);
        }
        // 参考实现把 cmdSettings 缓冲在会话起点，收到其他服务器帧前必然已发出。
        if !self.settings_sent {
            return Err(ClientError::RemoteBeforeSettings(frame.command));
        }
        self.server_frame(frame)
    }

    fn server_frame(&mut self, frame: &Frame) -> Result<Event, ClientError> {
        match frame.command {
            // 由 `apply` 提前返回，保留此分支只为命令穷尽。
            Command::Waste => Ok(Event::Ignore),
            Command::ServerSettings => self.server_settings(frame),
            Command::SynAck => self.syn_ack(frame),
            Command::Push => self.push(frame),
            Command::Fin => self.fin(frame),
            Command::UpdatePadding => self.update_padding(frame),
            Command::HeartRequest => {
                self.heartbeat(Command::HeartRequest, frame)?;
                Ok(Event::Heartbeat(frame.stream_id))
            }
            // 心跳回复不构成完整的链路健康验证，只作静默丢弃。
            Command::HeartResponse => {
                self.heartbeat(Command::HeartResponse, frame)?;
                Ok(Event::Ignore)
            }
            Command::Alert => {
                self.terminated = true;
                Ok(Event::Alert)
            }
            // Syn/Settings 是客户端方向帧：服务端发送即协议违规，其载荷与流编号不再解释。
            // 若客户端 Settings 尚未发出，前面的 Settings 门禁已先一步拒绝。
            Command::Syn | Command::Settings => Err(ClientError::ClientToServer(frame.command)),
        }
    }

    fn server_settings(&mut self, frame: &Frame) -> Result<Event, ClientError> {
        if self.server_settings_seen {
            return Err(ClientError::InvalidSettings("只接收一次"));
        }
        if frame.stream_id != 0 {
            return Err(ClientError::InvalidSettings("stream id 非零"));
        }
        let version = parse_server_settings(&frame.data)?;
        self.server_settings_seen = true;
        self.peer_version = version;
        Ok(Event::Settings { version })
    }

    fn syn_ack(&mut self, frame: &Frame) -> Result<Event, ClientError> {
        self.version2("SYNACK")?;
        match self.locate(frame.stream_id) {
            Location::Active { acked } => {
                if frame.data.is_empty() {
                    if acked {
                        // 重复成功 SYNACK：不改状态，交由上层继续使用该流。
                        return Ok(Event::Ignore);
                    }
                    self.streams.insert(frame.stream_id, true);
                    Ok(Event::Ready(frame.stream_id))
                } else {
                    // 带错误文本：只删除这一条流，其余流与会话保持有效。
                    self.streams.remove(&frame.stream_id);
                    Ok(Event::Rejected(frame.stream_id))
                }
            }
            Location::Closed => Ok(Event::Ignore),
            Location::Invalid(reason) => Err(ClientError::InvalidStream(reason)),
        }
    }

    fn push(&mut self, frame: &Frame) -> Result<Event, ClientError> {
        match self.locate(frame.stream_id) {
            Location::Active { acked } => {
                if self.peer_version == 2 && !acked {
                    return Err(ClientError::InvalidStream("数据早于 SYNACK"));
                }
                if frame.data.is_empty() {
                    Ok(Event::Ignore)
                } else {
                    Ok(Event::Data(frame.stream_id))
                }
            }
            Location::Closed => Ok(Event::Ignore),
            Location::Invalid(reason) => Err(ClientError::InvalidStream(reason)),
        }
    }

    fn fin(&mut self, frame: &Frame) -> Result<Event, ClientError> {
        if !frame.data.is_empty() {
            return Err(ClientError::InvalidStream("FIN 携带数据"));
        }
        match self.locate(frame.stream_id) {
            Location::Active { .. } => {
                self.streams.remove(&frame.stream_id);
                Ok(Event::Closed(frame.stream_id))
            }
            Location::Closed => Ok(Event::Ignore),
            Location::Invalid(reason) => Err(ClientError::InvalidStream(reason)),
        }
    }

    fn update_padding(&self, frame: &Frame) -> Result<Event, ClientError> {
        if frame.stream_id != 0 {
            return Err(ClientError::InvalidStream("padding 更新流编号非零"));
        }
        Ok(Event::PaddingUpdate)
    }

    /// 心跳只在已知版本 2 启用且无数据；任意 u32 关联值都是合法的，
    /// 它既不是流编号，也不用于映射浏览器环境。
    fn heartbeat(&self, command: Command, frame: &Frame) -> Result<(), ClientError> {
        self.version2(match command {
            Command::HeartRequest => "心跳请求",
            _ => "心跳回复",
        })?;
        if !frame.data.is_empty() {
            return Err(ClientError::InvalidVersion("心跳携带数据"));
        }
        Ok(())
    }

    fn version2(&self, what: &'static str) -> Result<(), ClientError> {
        if self.peer_version == 2 {
            Ok(())
        } else {
            Err(ClientError::InvalidVersion(what))
        }
    }

    fn locate(&self, stream_id: u32) -> Location {
        if stream_id == 0 {
            return Location::Invalid("流编号为零");
        }
        if let Some(acked) = self.streams.get(&stream_id) {
            return Location::Active { acked: *acked };
        }
        if stream_id <= self.last_allocated {
            return Location::Closed;
        }
        Location::Invalid("引用从未创建的流")
    }

    fn usable(&self) -> Result<(), ClientError> {
        if self.poisoned {
            return Err(ClientError::Poisoned);
        }
        if self.terminated {
            return Err(ClientError::Terminated);
        }
        Ok(())
    }
}

/// 解析 ServerSettings：UTF-8 文本、每行 `key=value`、禁止重复键、
/// 必须包含 `v`（1 或 2）。未知键允许并忽略，以便第三方服务端扩展。
/// 参考实现对缺失或不可解析的 `v` 宽容地停留在版本 1，本实现显式拒绝，
/// 避免把协商失败静默降级为更弱的协议行为。
fn parse_server_settings(data: &[u8]) -> Result<u8, ClientError> {
    if data.len() > MAX_SETTINGS_BYTES {
        return Err(ClientError::InvalidSettings("文本超出上限"));
    }
    let text = std::str::from_utf8(data).map_err(|_| ClientError::InvalidSettings("非 UTF-8"))?;
    let mut keys = HashSet::new();
    let mut version = None;
    for line in text.split('\n') {
        let (key, value) = line
            .split_once('=')
            .ok_or(ClientError::InvalidSettings("行缺少等号"))?;
        if key.is_empty() {
            return Err(ClientError::InvalidSettings("键为空"));
        }
        if !keys.insert(key) {
            return Err(ClientError::InvalidSettings("键重复"));
        }
        if key == "v" {
            if value != "1" && value != "2" {
                return Err(ClientError::InvalidSettings("版本非 1 或 2"));
            }
            version = Some(value);
        }
    }
    let version = version.ok_or(ClientError::InvalidSettings("缺少 v"))?;
    Ok(if version == "2" { 2 } else { 1 })
}
