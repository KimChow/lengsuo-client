//! 本仓 AnyTLS 服务端组装（仅供互通测试使用）：
//! TLS 承载（tls.rs，tokio-rustls TlsAcceptor）+ `server_state::ServerState` 状态机
//! 以及 `frame::Frame` 编解码；字节进出与写出通道在 pumps.rs，统计在 report.rs。
//! 语义基线 anytls-go fd6167a：认证（SHA256 口令 + padding0）→ Settings/ServerSettings →
//! 逐流解析 SOCKS 目标地址 → 出站连接 → 空载荷 SYNACK → 双向中继 → FIN。
//! 不含 padding 方案下发、空闲复用池、主动心跳计时与 UDP-over-TCP。
use crate::pumps::{self, drain_writer, feed_target, Flags, Session};
use crate::report::{protocol, transport, Failure, Report};
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    server_state::{Event, ServerState, StateError},
    Error,
};
use ss_core::target::TargetAddr;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// 认证 padding0 上限：参考默认方案只用 30 字节，此处留防御余量。
const PADDING_LIMIT: u16 = 4096;
/// 入站帧数据上限：线格式以两字节编码，此处全量容忍对端分包与填充。
const READ_LIMIT: u16 = u16::MAX;
/// 单会话活跃流上限（本端自设）。
const MAX_STREAMS: usize = 16;
/// Alert 文本上限；只写固定说明，不含对端字节。
const ALERT_LIMIT: usize = 200;
/// 出站连接失败时回报给客户端的固定错误文本（SYNACK 载荷）。
const CONNECT_FAILED: &[u8] = b"lengsuo-anytls: target connect failed";

/// 目标地址必须是非零端口的回环 IPv4，其余一律拒绝（不发起出站）。
fn loopback_endpoint(addr: &TargetAddr) -> Result<SocketAddr, Failure> {
    match addr {
        TargetAddr::V4(octets, port) => {
            if octets.first() != Some(&127) || *port == 0 {
                return Err(protocol("目标不是回环 IPv4".to_owned()));
            }
            Ok(SocketAddr::from((std::net::Ipv4Addr::from(*octets), *port)))
        }
        other => Err(protocol(format!("目标地址不受支持：{other:?}"))),
    }
}

/// 从缓存前缀里取目标地址；不足则原样保留并返回 `None` 等下一帧。
fn parse_target(entry: &mut Entry) -> Result<Option<SocketAddr>, Failure> {
    let (addr, used) = match TargetAddr::decode(&entry.pending) {
        Ok(pair) => pair,
        Err(ss_core::Error::TooShort { .. }) => return Ok(None),
        Err(err) => return Err(protocol(format!("目标地址非法：{err}"))),
    };
    let endpoint = loopback_endpoint(&addr)?;
    entry.pending.drain(..used);
    Ok(Some(endpoint))
}

/// 单流的会话侧记录。
#[derive(Default)]
struct Entry {
    /// 尚未解析出完整目标地址时缓存的字节。
    pending: Vec<u8>,
    /// 转发给目标的通道发送端；`None` 表示未建连或已关闭。
    sender: Option<UnboundedSender<Vec<u8>>>,
    flags: Arc<Flags>,
    /// 出站连接已失败：后续数据一律丢弃。
    failed: bool,
}

/// 会话循环的全部可变状态。
struct Loop {
    session: Session,
    state: ServerState,
    streams: HashMap<u32, Entry>,
    pumps: Vec<JoinHandle<()>>,
    opened: Vec<u32>,
    closed: Vec<u32>,
    version: Option<u8>,
    waste: usize,
    alerts: usize,
    syn_acks: usize,
    bytes_to_target: usize,
}

impl Loop {
    fn new(frames: UnboundedSender<Vec<u8>>, wait: Duration) -> Result<Self, Failure> {
        Ok(Self {
            session: Session { frames, wait },
            state: ServerState::new(MAX_STREAMS).map_err(|err| protocol(err.to_string()))?,
            streams: HashMap::new(),
            pumps: Vec::new(),
            opened: Vec::new(),
            closed: Vec::new(),
            version: None,
            waste: 0,
            alerts: 0,
            syn_acks: 0,
            bytes_to_target: 0,
        })
    }

    /// 出站连接目标并回报 SYNACK；失败时按 v2 语义回带错误文本的 SYNACK。
    async fn connect_target(&mut self, sid: u32, endpoint: SocketAddr) -> Result<(), Failure> {
        let wait = self.session.wait;
        let entry = self
            .streams
            .get_mut(&sid)
            .ok_or_else(|| protocol(format!("流 {sid} 未登记")))?;
        let target = match timeout(wait, TcpStream::connect(endpoint)).await {
            Ok(Ok(socket)) => socket,
            Ok(Err(_)) => {
                entry.failed = true;
                let frame = Frame {
                    command: Command::SynAck,
                    stream_id: sid,
                    data: CONNECT_FAILED.to_vec(),
                };
                self.session.send(&frame)?;
                self.syn_acks += 1;
                return Ok(());
            }
            Err(_) => return Err(transport("出站连接超时".to_owned())),
        };
        let (read, write) = target.into_split();
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        entry.sender = Some(tx);
        let flags = Arc::clone(&entry.flags);
        let session = self.session.clone();
        self.pumps.push(tokio::spawn(feed_target(write, rx, wait)));
        self.pumps.push(tokio::spawn(pumps::collect_target(
            sid, read, session, flags, wait,
        )));
        self.session
            .send(&crate::report::control(Command::SynAck, sid))?;
        self.syn_acks += 1;
        Ok(())
    }

    /// 数据帧：未建连时先解析目标地址（可跨帧），再转发剩余载荷。
    async fn relay(&mut self, sid: u32, data: &[u8]) -> Result<usize, Failure> {
        let entry = self
            .streams
            .get_mut(&sid)
            .ok_or_else(|| protocol(format!("流 {sid} 未登记")))?;
        if entry.failed {
            return Ok(0);
        }
        let payload: Vec<u8> = if entry.sender.is_some() {
            data.to_vec()
        } else {
            entry.pending.extend_from_slice(data);
            let endpoint = match parse_target(entry)? {
                Some(endpoint) => endpoint,
                None => return Ok(0),
            };
            self.connect_target(sid, endpoint).await?;
            let entry = self
                .streams
                .get_mut(&sid)
                .ok_or_else(|| protocol(format!("流 {sid} 未登记")))?;
            std::mem::take(&mut entry.pending)
        };
        if payload.is_empty() {
            return Ok(0);
        }
        let written = payload.len();
        let sender = self
            .streams
            .get(&sid)
            .ok_or_else(|| protocol("流未登记".to_owned()))?
            .sender
            .as_ref()
            .ok_or_else(|| protocol("出站通道缺失".to_owned()))?;
        sender
            .send(payload)
            .map_err(|_| transport("出站通道已关闭".to_owned()))?;
        self.bytes_to_target += written;
        Ok(written)
    }

    /// 客户端 FIN：关闭出站通道并标记已收 FIN，回程任务不再补发 FIN。
    fn close_stream(&mut self, sid: u32) {
        if let Some(entry) = self.streams.get_mut(&sid) {
            entry.sender = None;
            entry.flags.client_fin.store(true, Ordering::Relaxed);
        }
    }

    /// 发送 Alert 并终止会话；文本只含固定说明。
    fn alert(&mut self, reason: &str) {
        let mut text = format!("lengsuo-anytls server: {reason}").into_bytes();
        text.truncate(ALERT_LIMIT);
        let frame = Frame {
            command: Command::Alert,
            stream_id: 0,
            data: text,
        };
        if self.session.send(&frame).is_ok() {
            self.alerts += 1;
        }
    }

    /// 处理一帧；返回 `Err` 表示会话循环应立即结束（原因已记录）。
    async fn handle(&mut self, frame: Frame) -> Result<(), Failure> {
        let sid = frame.stream_id;
        match self.state.accept(&frame) {
            Ok(Event::Settings { version }) => {
                self.version = Some(version);
                if version == 2 {
                    // 参考服务端：客户端上报 v>=2 时立即回 cmdServerSettings。
                    let settings = Frame {
                        command: Command::ServerSettings,
                        stream_id: 0,
                        data: b"v=2".to_vec(),
                    };
                    return self.session.send(&settings);
                }
                Ok(())
            }
            Ok(Event::Open(id)) => {
                self.opened.push(id);
                self.streams.insert(id, Entry::default());
                Ok(())
            }
            Ok(Event::Data(id)) => {
                self.relay(id, &frame.data).await?;
                Ok(())
            }
            Ok(Event::Heartbeat(id)) => self
                .session
                .send(&crate::report::control(Command::HeartResponse, id)),
            Ok(Event::Close(id)) => {
                self.closed.push(id);
                self.close_stream(id);
                Ok(())
            }
            Ok(Event::Padding) => {
                self.waste += 1;
                let _ = sid;
                Ok(())
            }
            Err(StateError::SettingsExpected) => {
                // 参考服务端：Settings 之前收到 cmdSYN 必须拒绝此次会话。
                self.alert("client did not send its settings");
                Err(protocol("Settings 之前收到流帧".to_owned()))
            }
            Err(err) => Err(protocol(format!("状态机拒绝：{err}"))),
        }
    }

    /// 收尾：关出站通道 → 等回程任务 → 关写出通道 → 等写出任务。
    async fn finish(mut self) -> Report {
        for entry in self.streams.values_mut() {
            entry.sender = None;
        }
        let wait = self.session.wait;
        for handle in self.pumps.drain(..) {
            let _ = timeout(wait, handle).await;
        }
        let mut bytes_to_client = 0usize;
        for entry in self.streams.values() {
            bytes_to_client += entry.flags.bytes_out.swap(0, Ordering::Relaxed);
        }
        drop(self.session);
        Report {
            streams_opened: std::mem::take(&mut self.opened),
            streams_closed: std::mem::take(&mut self.closed),
            peer_version: self.version,
            alerts_sent: self.alerts,
            waste_frames: self.waste,
            bytes_to_target: self.bytes_to_target,
            bytes_to_client,
            syn_acks_sent: self.syn_acks,
        }
    }
}

/// 跑完一条已握手 TLS 连接的服务端会话，返回统计与结束原因。
///
/// `stream` 只需同时实现 AsyncRead/AsyncWrite：互通测试传入 tokio-rustls
/// 服务端流（tls::handshake 的结果）。认证失败立刻丢弃，无明文回退。
pub async fn serve<S>(stream: S, password: &[u8], wait: Duration) -> (Report, Result<(), Failure>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = stream;
    if let Err(err) = Credential::new(password)
        .verify(&mut stream, PADDING_LIMIT, wait)
        .await
    {
        let failure = match err {
            Error::Authentication => Failure::Authentication,
            other => transport(format!("认证读取失败：{other}")),
        };
        return (Report::default(), Err(failure));
    }
    let (mut reader, writer) = tokio::io::split(stream);
    let (frames, queue) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(drain_writer(writer, queue, wait));
    let mut loop_state = match Loop::new(frames.clone(), wait) {
        Ok(state) => state,
        Err(err) => {
            drop(frames);
            let _ = timeout(wait, writer_task).await;
            return (Report::default(), Err(err));
        }
    };
    let mut failure: Option<Failure> = None;
    loop {
        let frame = match Frame::read(&mut reader, READ_LIMIT, wait).await {
            Ok(frame) => frame,
            // 对端干净关闭（EOF/close_notify）：会话正常结束。
            Err(Error::Io(err)) if err.kind() == ErrorKind::UnexpectedEof => break,
            Err(err) => {
                failure = Some(transport(format!("读帧失败：{err}")));
                break;
            }
        };
        if let Err(err) = loop_state.handle(frame).await {
            failure = Some(err);
            break;
        }
    }
    drop(reader);
    let report = loop_state.finish().await;
    drop(frames);
    if timeout(wait, writer_task).await.is_err() {
        failure = failure.or(Some(transport("写出任务未退出".to_owned())));
    }
    (report, failure.map_or(Ok(()), Err))
}
