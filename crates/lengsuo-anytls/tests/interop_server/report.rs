//! 服务端方向互通的会话统计与失败分类。
use lengsuo_anytls::frame::{Command, Frame};

/// 会话结束原因；成功结束（对端干净关闭）时不产生 `Failure`。
#[derive(Debug)]
pub enum Failure {
    /// 认证摘要不匹配：连接立即丢弃，无明文回退。
    Authentication,
    /// TLS 握手失败：明文/非法 ClientHello 一律拒绝，不进入会话层。
    Handshake(String),
    /// 协议违规（状态机失效或帧非法）。
    Protocol(String),
    /// 传输层、超时或写出失败。
    Transport(String),
}

/// 会话统计，供测试断言；不含任何载荷或凭据。
#[derive(Debug, Default)]
pub struct Report {
    pub streams_opened: Vec<u32>,
    pub streams_closed: Vec<u32>,
    pub peer_version: Option<u8>,
    /// 服务端方向告警帧数（本组装只在缺 Settings 时发一条）。
    pub alerts_sent: usize,
    /// 静默丢弃的填充帧数（Waste 与心跳回复）。
    pub waste_frames: usize,
    pub bytes_to_target: usize,
    pub bytes_to_client: usize,
    /// 本端发出的 SYNACK 帧数（含带错误文本的失败回报）。
    pub syn_acks_sent: usize,
}

pub fn protocol(message: String) -> Failure {
    Failure::Protocol(message)
}

pub fn transport(message: String) -> Failure {
    Failure::Transport(message)
}

pub fn control(command: Command, stream_id: u32) -> Frame {
    Frame {
        command,
        stream_id,
        data: Vec::new(),
    }
}
