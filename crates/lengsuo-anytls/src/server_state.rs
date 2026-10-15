//! AnyTLS v2 服务端入站会话状态机：纯内存检查，不含 TLS、认证与网络。
//! 基线 anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50 `docs/protocol.md`。
//! 只负责帧方向、Settings 协商、Stream ID 单调性与活跃流集合；
//! 不含 SYNACK 发送、心跳计时、padding 方案更新、空闲复用池与 UDP-over-TCP。
use crate::frame::{Command, Frame};
use std::collections::{BTreeSet, HashSet};

/// Settings 文本字节上限；参考实现无显式上限，此处固定防御性上限。
const MAX_SETTINGS_BYTES: usize = 4096;

/// 状态机产出的事件，调用方据此驱动写出与代理业务。
/// 事件不携带应用载荷：`Data` 的字节由调用方持有的原 `Frame` 提供。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// 已接收并采纳客户端 Settings，`version` 为协商出的对端版本。
    Settings { version: u8 },
    /// 客户端打开新流。
    Open(u32),
    /// 某活跃流上的数据，载荷仍在原帧中。
    Data(u32),
    /// 某活跃流已关闭并从活跃集合移除。
    Close(u32),
    /// 客户端心跳请求，上层应回复 HeartResponse。
    Heartbeat(u32),
    /// 静默丢弃的填充：Waste 帧或客户端 HeartResponse。
    Padding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    #[error("会话配置非法")]
    InvalidConfig,
    #[error("会话已因非法帧失效，必须丢弃连接")]
    Poisoned,
    #[error("收到 Settings 之前仅容忍 Waste 帧")]
    SettingsExpected,
    #[error("Settings 非法：{0}")]
    InvalidSettings(&'static str),
    #[error("流状态非法：{0}")]
    InvalidStream(&'static str),
    #[error("版本 1 禁用该帧：{0}")]
    InvalidVersion(&'static str),
    #[error("客户端不得发送服务端方向帧 {0:?}")]
    ServerToClient(Command),
}

/// 单个已认证 TLS 连接的服务端会话循环状态。
/// 首个非法帧使状态失效，之后所有 `accept` 一律拒绝；连接关闭必须丢弃本对象。
pub struct ServerState {
    max_streams: usize,
    peer_version: Option<u8>,
    max_syn_id: u32,
    active: BTreeSet<u32>,
    poisoned: bool,
}

impl ServerState {
    pub fn new(max_streams: usize) -> Result<Self, StateError> {
        if max_streams == 0 {
            return Err(StateError::InvalidConfig);
        }
        Ok(Self {
            max_streams,
            peer_version: None,
            max_syn_id: 0,
            active: BTreeSet::new(),
            poisoned: false,
        })
    }

    /// 协商出的对端版本；未收到 Settings 时为 `None`。
    pub fn peer_version(&self) -> Option<u8> {
        self.peer_version
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 接收一个客户端帧。校验全部通过后一次性提交状态变更，失败不留下半成品；
    /// 任何失败都会把状态标记为失效（fail-closed），调用方须随后关闭连接。
    pub fn accept(&mut self, frame: &Frame) -> Result<Event, StateError> {
        if self.poisoned {
            return Err(StateError::Poisoned);
        }
        match self.apply(frame) {
            Ok(event) => Ok(event),
            Err(err) => {
                self.poisoned = true;
                Err(err)
            }
        }
    }

    fn apply(&mut self, frame: &Frame) -> Result<Event, StateError> {
        match frame.command {
            // Waste 任意方向、任意流编号与数据长度都只作填充丢弃。
            Command::Waste => Ok(Event::Padding),
            Command::Settings => {
                if self.peer_version.is_some() {
                    return Err(StateError::InvalidSettings("只接收一次"));
                }
                if frame.stream_id != 0 {
                    return Err(StateError::InvalidSettings("stream id 非零"));
                }
                let version = parse_settings(&frame.data)?;
                self.peer_version = Some(version);
                Ok(Event::Settings { version })
            }
            Command::Syn => {
                self.started()?;
                if !frame.data.is_empty() {
                    return Err(StateError::InvalidStream("SYN 携带数据"));
                }
                if frame.stream_id == 0 {
                    return Err(StateError::InvalidStream("SYN 流编号为零"));
                }
                if frame.stream_id <= self.max_syn_id {
                    return Err(StateError::InvalidStream("SYN 流编号未严格递增"));
                }
                if self.active.len() >= self.max_streams {
                    return Err(StateError::InvalidStream("活跃流已达上限"));
                }
                self.max_syn_id = frame.stream_id;
                self.active.insert(frame.stream_id);
                Ok(Event::Open(frame.stream_id))
            }
            Command::Push => {
                self.started()?;
                self.require_active(frame.stream_id)?;
                Ok(Event::Data(frame.stream_id))
            }
            Command::Fin => {
                self.started()?;
                if !frame.data.is_empty() {
                    return Err(StateError::InvalidStream("FIN 携带数据"));
                }
                self.require_active(frame.stream_id)?;
                self.active.remove(&frame.stream_id);
                Ok(Event::Close(frame.stream_id))
            }
            Command::HeartRequest => {
                self.version2(Command::HeartRequest, frame)?;
                Ok(Event::Heartbeat(frame.stream_id))
            }
            Command::HeartResponse => {
                self.version2(Command::HeartResponse, frame)?;
                Ok(Event::Padding)
            }
            // 服务端方向帧由客户端发送即协议违规，与是否已收 Settings 无关。
            Command::Alert | Command::UpdatePadding | Command::SynAck | Command::ServerSettings => {
                Err(StateError::ServerToClient(frame.command))
            }
        }
    }

    fn started(&self) -> Result<(), StateError> {
        if self.peer_version.is_some() {
            Ok(())
        } else {
            Err(StateError::SettingsExpected)
        }
    }

    fn require_active(&self, stream_id: u32) -> Result<(), StateError> {
        if self.active.contains(&stream_id) {
            Ok(())
        } else {
            Err(StateError::InvalidStream("引用不存在的流"))
        }
    }

    /// 心跳只在版本 2 启用且无数据；stream id 是需要原样回传的关联值。
    fn version2(&self, command: Command, frame: &Frame) -> Result<(), StateError> {
        self.started()?;
        if self.peer_version != Some(2) {
            return Err(StateError::InvalidVersion(match command {
                Command::HeartRequest => "心跳请求",
                _ => "心跳回复",
            }));
        }
        if !frame.data.is_empty() {
            return Err(StateError::InvalidVersion("心跳携带数据"));
        }
        Ok(())
    }
}

/// 解析客户端 Settings：UTF-8 文本、每行 `key=value`、禁止重复键、
/// 必须包含 `v`（1 或 2）、非空 `client`、32 位小写十六进制 `padding-md5`。
/// 未知键允许并忽略，以便第三方客户端扩展。
fn parse_settings(data: &[u8]) -> Result<u8, StateError> {
    if data.len() > MAX_SETTINGS_BYTES {
        return Err(StateError::InvalidSettings("文本超出上限"));
    }
    let text = std::str::from_utf8(data).map_err(|_| StateError::InvalidSettings("非 UTF-8"))?;
    let mut keys = HashSet::new();
    let mut version = None;
    let mut client_ok = false;
    let mut padding_ok = false;
    for line in text.split('\n') {
        let (key, value) = line
            .split_once('=')
            .ok_or(StateError::InvalidSettings("行缺少等号"))?;
        if key.is_empty() {
            return Err(StateError::InvalidSettings("键为空"));
        }
        if !keys.insert(key) {
            return Err(StateError::InvalidSettings("键重复"));
        }
        match key {
            "v" => {
                if value != "1" && value != "2" {
                    return Err(StateError::InvalidSettings("版本非 1 或 2"));
                }
                version = Some(value);
            }
            "client" => {
                if value.is_empty() {
                    return Err(StateError::InvalidSettings("client 为空"));
                }
                client_ok = true;
            }
            "padding-md5" => {
                if !is_md5_hex(value) {
                    return Err(StateError::InvalidSettings("padding-md5 非法"));
                }
                padding_ok = true;
            }
            _ => {}
        }
    }
    let version = version.ok_or(StateError::InvalidSettings("缺少 v"))?;
    if !client_ok {
        return Err(StateError::InvalidSettings("缺少 client"));
    }
    if !padding_ok {
        return Err(StateError::InvalidSettings("缺少 padding-md5"));
    }
    Ok(if version == "2" { 2 } else { 1 })
}

fn is_md5_hex(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
