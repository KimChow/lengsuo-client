//! 服务端会话循环：对齐参考 `proxy/session/session.go::recvLoop` 的**服务端分支**与
//! `cmd/server/handleTcpConnection` 的认证时序，以及 `cmd/server/outbound_tcp.go` 的
//! 出站 TCP 转发。
//!
//! 时序（逐条对应参考）：
//! 1. `Credential::verify`：SHA256 口令 + BE16 padding 长度 + padding。失败即丢弃连接。
//! 2. Settings 必须是首个非 Waste 帧；收到后若客户端 `v>=2`，回 `cmdServerSettings`；
//!    若 `padding-md5` 与本地方案不符，回 `cmdUpdatePaddingScheme`（携带本地方案原文）。
//! 3. SYN 建立流；首帧 PUSH 的前缀是 SOCKS5 目标地址，解析后拨号（TCP）。
//! 4. SYNACK 只在 v2 且只汇报一次；失败带错误文本（参考 `HandshakeSuccess/Failure`）。
//! 5. 实时数据 PUSH → 目标；FIN → 本地关流；HeartRequest → 原样回 HeartResponse。
//!
//! 未实现（与 `docs/anytls-status.md` 的「未覆盖」一致）：空闲复用池、主动心跳计时、
//! UDP-over-TCP（v2）、认证失败时的明文 fallback（参考为空实现 = 断连）。
use super::sink::Sink;
use super::streams::Stream;
use crate::auth::Credential;
use crate::frame::{Command, Frame};
use crate::padding::PaddingScheme;
use crate::server_state::{Event, ServerState, StateError};
use crate::Error;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// 一个握手完成的 TLS 连接的服务端会话。
pub struct Session<S: AsyncRead + AsyncWrite + Unpin> {
    stream: S,
    password: Vec<u8>,
    padding: PaddingScheme,
    wait: Duration,
    max_streams: usize,
}

/// 会话结束的统计（只用于测试与诊断，不含载荷）。
#[derive(Debug, Default)]
pub struct SessionStats {
    pub streams_opened: usize,
    pub streams_closed: usize,
    pub peer_version: Option<u8>,
    pub syn_acks_sent: usize,
    pub heartbeats: usize,
    pub bytes_to_target: usize,
    pub bytes_to_client: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Session<S> {
    /// 构造会话；`max_streams` 为 0 或等待时长为 0 都会失败（配置非法）。
    pub fn new(
        stream: S,
        password: &[u8],
        padding: PaddingScheme,
        max_streams: usize,
        wait: Duration,
    ) -> Result<Self, Error> {
        if wait.is_zero() || ServerState::new(max_streams).is_err() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            stream,
            password: password.to_vec(),
            padding,
            wait,
            max_streams,
        })
    }

    /// 跑完整条会话：认证 → 帧循环 → 收尾。返回 `Ok(汇总)` 表示会话正常收尾
    /// （对端干净关闭或本地读到 EOF）；协议违规/传输错误返回 `Err`，调用方必须
    /// 丢弃底层连接。
    pub async fn run(mut self) -> Result<SessionStats, Error> {
        Credential::new(&self.password)
            .verify(&mut self.stream, super::PADDING_LIMIT, self.wait)
            .await?;
        // 认证之后读写分离：`Sink` 同时持有读半与写半，共用一把锁串行化。
        // 这里把 `self` 拆开，避免 `&mut self.stream` 与后续 `self.serve` 的双重借用。
        let Self {
            stream,
            padding,
            wait,
            max_streams,
            ..
        } = self;
        let (read, write) = tokio::io::split(stream);
        let sink = Sink::new(read, write, padding.clone(), wait);
        serve(sink, padding, max_streams).await
    }
}

/// 认证之后的帧循环（自由函数，便于把流的所有权交给 `Sink`）。
async fn serve(
    sink: Sink,
    padding: PaddingScheme,
    max_streams: usize,
) -> Result<SessionStats, Error> {
    let mut state = ServerState::new(max_streams).map_err(|_| Error::Invalid)?;
    let mut streams: HashMap<u32, Stream> = HashMap::new();
    let mut stats = SessionStats::default();
    loop {
        let frame = match sink.read(u16::MAX).await {
            Ok(frame) => frame,
            // 对端干净关闭（EOF / close_notify）：正常收尾。
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                finish(&mut streams, &mut stats);
                return Ok(stats);
            }
            Err(err) => return Err(err),
        };
        dispatch(&sink, &mut state, &mut streams, &mut stats, &padding, frame).await?;
    }
}

/// 处理一帧；返回 `Err` 表示会话应以失败结束。
async fn dispatch(
    sink: &Sink,
    state: &mut ServerState,
    streams: &mut HashMap<u32, Stream>,
    stats: &mut SessionStats,
    padding: &PaddingScheme,
    frame: Frame,
) -> Result<(), Error> {
    match state.accept(&frame) {
        Ok(Event::Settings { version }) => {
            stats.peer_version = Some(version);
            // 参考：客户端 padding-md5 与本地方案不符时回本地方案原文。
            // Settings 是 StringMap 文本，直接看是否含本地方案的 md5。
            if !contains(&frame.data, padding.md5().as_bytes()) {
                let raw = padding.raw().to_vec();
                sink.control_data(Command::UpdatePadding, 0, &raw).await?;
            }
            if version >= 2 {
                sink.control_data(Command::ServerSettings, 0, b"v=2")
                    .await?;
            }
            Ok(())
        }
        Ok(Event::Open(id)) => {
            streams.insert(id, Stream::pending());
            stats.streams_opened += 1;
            Ok(())
        }
        Ok(Event::Data(id)) => {
            let Some(entry) = streams.get_mut(&id) else {
                return Err(Error::Invalid);
            };
            let version = stats.peer_version.unwrap_or(1);
            relay(entry, id, &frame.data, version, sink).await
        }
        Ok(Event::Close(id)) => {
            if let Some(entry) = streams.get_mut(&id) {
                entry.close_local();
            }
            stats.streams_closed += 1;
            Ok(())
        }
        Ok(Event::Heartbeat(id)) => {
            sink.control(Command::HeartResponse, id).await?;
            stats.heartbeats += 1;
            Ok(())
        }
        Ok(Event::Padding) => Ok(()),
        Err(StateError::SettingsExpected) => {
            // 参考：Settings 之前收到流帧，回 Alert 文本并结束会话。
            sink.control_data(Command::Alert, 0, b"client did not send its settings")
                .await?;
            Err(Error::Invalid)
        }
        Err(_) => Err(Error::Invalid),
    }
}

/// 数据帧：未建连时先解析目标地址（可跨帧），再拨号并转发剩余载荷。
async fn relay(
    entry: &mut Stream,
    sid: u32,
    data: &[u8],
    version: u8,
    sink: &Sink,
) -> Result<(), Error> {
    if entry.sender_ready() {
        entry.write_to_target(data);
        return Ok(());
    }
    entry.push_pending(data);
    let Some(endpoint) = entry.take_endpoint()? else {
        return Ok(());
    };
    entry.connect(sid, endpoint, version, sink).await?;
    entry.flush_pending();
    Ok(())
}

/// 收尾：关闭出站通道，汇总统计（回程任务已把已读字节写入 Sink）。
fn finish(streams: &mut HashMap<u32, Stream>, stats: &mut SessionStats) {
    for entry in streams.values_mut() {
        entry.close_local();
        stats.bytes_to_target += entry.flags.to_target.swap(0, Ordering::Relaxed);
        stats.bytes_to_client += entry.flags.to_client.swap(0, Ordering::Relaxed);
    }
}

/// 无额外依赖的子串查找（本地方案 md5 是固定 32 字节 ASCII）。
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
