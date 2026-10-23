//! 用户态监听：把一个完整的真实 IP 报文喂给状态机，并构造回包。
//!
//! `feed` 的处理链严格照 `app/dispatcher/default.go` 的分发口径对应：
//! ① 校验（`checksum::verify`，其内部先做 `packet::inspect`，两者都 fail-closed）
//! → ② 方向判定 → ③ 会话表命中或新建 → ④ `Connection::advance`
//! → ⑤ 用 `segment::build` 构造 IP 头 + TCP 段的回包。
//!
//! 会话键用现网 [`SessionTable`]：**入站键**为（对端 → 本端），正是 `inspect` 解出的
//! 五元组；回包直接把键的源/目的对调，不另建反向会话。容量与 TTL 由 [`Config`]
//! 参数化，满时拒绝新会话且**不驱逐**既有（`SessionTable` 已是该语义）。
//!
//! 丢弃与事件落在 [`ListenerStats`] 的独立计数格里，无需日志即可判断丢包原因分布。
//!
//! 明确不做：不打开设备、不路由、不重组分片、不做拥塞控制、不做主动 connect。
//! 逐条差异见文件末尾「偏离清单」。

use std::net::IpAddr;

use crate::checksum;
use crate::mtu::{self, Direction};
use crate::packet::{PacketInfo, Transport};
use crate::session::{Clock, OpenError, SessionKey, SessionTable};

use super::ip;
use super::segment::{self, Flags};
use super::state::{Config as ConnConfig, Connection, DiscardReason, Outcome, State};

/// 本端 IP 头部构造与状态机的静态配置。
#[derive(Debug, Clone)]
pub struct Config {
    /// 连接级参数（窗口/重排槽/ISN 种子）。
    pub connection: ConnConfig,
    /// 会话表容量：满时拒绝新会话且不驱逐既有。
    pub session_capacity: usize,
    /// 会话表 TTL（毫秒）：过期由 `feed` 传入的 `clock` 驱动。
    pub session_ttl: Clock,
    /// 本地接口 MTU：用于 `mtu::decide` 做入站过大判定。低于协议族下限时该报文的
    /// 过大判定按拒绝处理（计入 `oversize`），不 panic。
    pub interface_mtu: u16,
    /// 首次建连时 ISN 种子的起始值；每建一条新连接递增，避免同一对端复用同一 ISN。
    pub iss_seed_start: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            connection: ConnConfig::default(),
            session_capacity: 1024,
            session_ttl: 60_000,
            interface_mtu: 1500,
            iss_seed_start: 0,
        }
    }
}

/// `feed` 的失败原因。所有拒绝路径都走这里，绝不 panic。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 传输层校验和或头部解析失败（fail-closed，逐字保留原错误）。
    #[error("入站报文校验失败：{0}")]
    Checksum(#[from] checksum::Error),
    /// 报文不是 TCP：本监听只处理 TCP（UDP 由上层其它模块处理）。
    #[error("非 TCP 报文，本监听不处理")]
    NotTcp,
    /// 会话表已满，拒绝新会话且不驱逐既有。
    #[error("会话表已满，拒绝新会话：{0}")]
    SessionFull(usize),
    /// 回包长度超出 IP 头部可表达的范围。
    #[error("回包长度非法：{0}")]
    ReplyLength(usize),
}

/// 一次 `feed` 的完整结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feed {
    /// 要写回设备的完整 IP 报文（IP 头 + TCP 段），可能为零到多条。
    pub replies: Vec<Vec<u8>>,
    /// 按序到达、应交给上层读端的应用载荷（可能为空）。
    pub delivered: Vec<u8>,
    /// 状态机对本次段的动作口径，供上层观察（`None`/`Discard` 也可能伴随回包）。
    pub outcome: FeedOutcome,
}

/// 对外的动作归类；与 [`Outcome`] 同构但不暴露内部序号字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedOutcome {
    /// 产生了需要回送的段（握手 / ACK / RST / FIN）。
    Replied,
    /// 交付了应用载荷。
    Delivered,
    /// 无动作。
    None,
    /// 丢弃，附原因。
    Discarded(DiscardReason),
}

/// 丢弃与事件计数。每格独立，不合并统计口径。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListenerStats {
    /// 校验/解析失败被 fail-closed 丢弃的报文数。
    pub malformed: u64,
    /// 非 TCP 报文数。
    pub non_tcp: u64,
    /// 因会话表满被拒绝的新会话数。
    pub session_rejected: u64,
    /// 收到的 SYN（新建会话尝试）总数。
    pub syn_received: u64,
    /// 完成三次握手、进入 `Established` 的连接数。
    pub established: u64,
    /// 经 `mtu::decide` 判定为过大而被拒的入站报文数。
    pub oversize: u64,
    /// 状态机判定为 `Discard` 的段数（按 [`DiscardReason`] 分布另见 `discarded`）。
    pub discarded: u64,
    /// 因 RST 终止的连接数。
    pub reset: u64,
    /// 收到对端 FIN、进入 `CloseWait` 的连接数。
    pub peer_fin: u64,
    /// 应用载荷交付字节总数。
    pub delivered_bytes: u64,
}

/// 会话表里保存的单条连接及其回包所需的地址信息。
struct Session {
    connection: Connection,
    /// 本端地址（回包的源），即入站报文的目的地址。
    local: IpAddr,
    /// 对端地址（回包的目的），即入站报文的源地址。
    peer: IpAddr,
    /// 本端端口。
    local_port: u16,
    /// 对端端口。
    peer_port: u16,
}

/// 把一条会话与待发段编成完整 IP 回包。地址方向相对入站报文对调。
fn reply(session: &Session, s: &super::state::SendSegment) -> Result<Vec<u8>, Error> {
    ip::reply(
        session.local,
        session.peer,
        session.local_port,
        session.peer_port,
        s,
    )
}

/// 用户态 TCP 监听器。**不打开设备**：报文由上层设备接入部分喂入、回包由其取走。
pub struct TcpListener {
    config: Config,
    sessions: SessionTable<Session>,
    stats: ListenerStats,
    /// 下一条新连接的 ISN 种子，建连时递增。
    next_iss: u32,
}

impl TcpListener {
    /// 按配置建立监听器。会话表容量/TTL 立即生效；连接级参数在每次建连时复制。
    pub fn new(config: Config) -> Self {
        let capacity = config.session_capacity;
        let ttl = config.session_ttl;
        let next_iss = config.iss_seed_start;
        Self {
            config,
            sessions: SessionTable::new(capacity, ttl),
            stats: ListenerStats::default(),
            next_iss,
        }
    }

    pub fn stats(&self) -> ListenerStats {
        self.stats
    }

    /// 当前占用会话条目数（含未回收的已过期条目）。
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// 显式回收所有过期会话（由上层按其时钟周期调用）。
    pub fn gc(&mut self, clock: Clock) -> usize {
        self.sessions.gc(clock).len()
    }

    /// 主动关闭一条连接的本端写端（发 FIN）。`key` 为入站五元组键；不存在则无动作。
    pub fn close(&mut self, key: SessionKey, clock: Clock) -> Result<Vec<Vec<u8>>, Error> {
        let Some(session) = self.sessions.get(key, clock) else {
            return Ok(Vec::new());
        };
        match session.connection.close() {
            Outcome::SendSegment(s) => Ok(vec![reply(session, &s)?]),

            _ => Ok(Vec::new()),
        }
    }

    /// 在一条已建立的连接上发送应用载荷，返回要写回设备的 IP 报文。
    ///
    /// 仅供上层读/写流（[`super::stream`]）调用：按 clamp 后的有效 MSS 分段——有效
    /// MSS 由 [`Config::interface_mtu`] 经 [`mtu::MssClamp`] 按 `key` 目的地址的协议族
    /// 换算（IPv4 用 `mss_for_v4`，IPv6 用 `mss_for_v6`）。每段都带 ACK，**仅末段**追加
    /// PSH；段序号按前面各段长度递增。
    ///
    /// fail-closed：MSS 换算失败、会话不存在（或已终结）或任一段构造失败时**整次返回
    /// 空**，不产出半成品，也不推进 `snd_nxt`。不做拥塞控制、不做重传、不改窗口语义。
    pub fn send(&mut self, key: SessionKey, payload: &[u8], clock: Clock) -> Vec<Vec<u8>> {
        if payload.is_empty() {
            return Vec::new();
        }
        let interface_mtu = self.config.interface_mtu;
        let Some(session) = self.sessions.get(key, clock) else {
            return Vec::new();
        };
        // MSS 换算失败（接口 MTU 低于协议族下限）时 fail-closed：不发送、不推进序号。
        let Ok(clamp) = mtu::MssClamp::new(interface_mtu) else {
            return Vec::new();
        };
        let mss = if key.destination().is_ipv4() {
            clamp.mss_for_v4()
        } else {
            clamp.mss_for_v6()
        };
        let Ok(mss) = mss else {
            return Vec::new();
        };
        let mss = usize::from(mss);
        // 先构造全部段，再统一提交：任一段 `reply` 失败则整次返回空，`snd_nxt` 不变。
        let ack = session.connection.rcv_nxt();
        // 通告的是**本端**接收窗口（与状态机 ack 段同一口径），不是对端窗口。
        let window = session.connection.advertised_window();
        let mut seq = session.connection.snd_nxt();
        let mut chunks = payload.chunks(mss).peekable();
        let mut packets = Vec::with_capacity(payload.len().div_ceil(mss));
        while let Some(chunk) = chunks.next() {
            // 只有最后一段置 PSH；其余段仅确认。
            let flags = if chunks.peek().is_some() {
                Flags::ACK
            } else {
                Flags::ACK | Flags::PSH
            };
            let s = super::state::SendSegment {
                seq,
                ack,
                flags,
                window,
                payload: chunk.to_vec(),
            };
            match reply(session, &s) {
                Ok(packet) => packets.push(packet),
                Err(_) => return Vec::new(),
            }
            seq = seq.wrapping_add(chunk.len() as u32);
        }
        // 发送端序号推进：载荷字节数全部消耗（仅在全部段构造成功后）。
        session.connection.advance_snd(payload.len() as u32);
        packets
    }

    /// 吃一个**完整 IP 报文**（真实设备喂进来的原字节），返回要写回设备的报文与载荷。
    ///
    /// 处理链见模块头注释；任何一步失败都 fail-closed，不产生半成品回包。
    pub fn feed(&mut self, ip_packet: &[u8], clock: Clock) -> Result<Feed, Error> {
        // ① 校验：checksum::verify 内部先 inspect，二者都 fail-closed。
        let info = match checksum::verify(ip_packet) {
            Ok(info) => info,
            Err(err) => {
                self.stats.malformed += 1;
                return Err(Error::Checksum(err));
            }
        };
        if info.protocol != Transport::Tcp {
            self.stats.non_tcp += 1;
            return Err(Error::NotTcp);
        }
        // ② 方向判定：本监听只处理**入站**（对端 → 本端）。用 mtu::decide 做过大判定，
        //    过大的入站报文不得回报 PMTUD（Ingress），这里直接拒收。
        match mtu::decide_from(ip_packet, self.config.interface_mtu, Direction::Ingress) {
            Ok(decision) if decision.is_send() => {}
            Ok(_) => {
                self.stats.oversize += 1;
                return Ok(Feed::rejected());
            }
            Err(_) => {
                // 接口 MTU 低于协议族下限、或长度非法：按拒绝处理，不 panic、不回错。
                self.stats.oversize += 1;
                return Ok(Feed::rejected());
            }
        }
        // 定位 **TCP 段起始**（含 TCP 头部）。注意 `info.payload_offset` 是**应用载荷**
        // 偏移（已越过 TCP 头部），`segment::parse` 需要的是段首，因此这里另算 IP 头部长度。
        let Some(segment_bytes) = ip::tcp_segment_start(ip_packet, info.payload_offset)
            .and_then(|start| ip_packet.get(start..))
        else {
            self.stats.malformed += 1;
            return Ok(Feed::rejected());
        };
        let Ok(seg) = segment::parse(segment_bytes) else {
            self.stats.malformed += 1;
            return Ok(Feed::rejected());
        };
        self.dispatch(info, &seg, clock)
    }

    /// ③ 会话命中/新建 → ④ `advance` → ⑤ 构造回包。
    fn dispatch(
        &mut self,
        info: PacketInfo,
        seg: &segment::Segment<'_>,
        clock: Clock,
    ) -> Result<Feed, Error> {
        let key = SessionKey::from_info(info);
        if seg.flags.has_syn() && !seg.flags.has_ack() {
            self.stats.syn_received += 1;
        }
        if self.sessions.peek(key, clock).is_none() {
            self.open_session(info, key, clock)?;
        }
        let Some(session) = self.sessions.get(key, clock) else {
            // 极端情形：刚建好的会话在同一次调用内已过期（TTL=0）。按丢弃处理。
            self.stats.discarded += 1;
            return Ok(Feed::rejected());
        };
        let before = (
            session.connection.state(),
            session.connection.discarded_segments(),
        );
        let status = session.connection.advance(seg, clock);
        let after = (
            session.connection.state(),
            session.connection.discarded_segments(),
        );
        let mut feed = Feed {
            replies: Vec::new(),
            delivered: Vec::new(),
            outcome: FeedOutcome::None,
        };
        match status {
            Outcome::SendSegment(s) => {
                feed.outcome = FeedOutcome::Replied;
                feed.replies.push(reply(session, &s)?);
            }
            Outcome::Deliver(bytes) => {
                feed.outcome = FeedOutcome::Delivered;
                self.stats.delivered_bytes += bytes.len() as u64;
                feed.delivered = bytes;
            }
            Outcome::Discard(reason) => {
                feed.outcome = FeedOutcome::Discarded(reason);
                self.stats.discarded += 1;
            }
            Outcome::None => feed.outcome = FeedOutcome::None,
        }
        // 事件计数：按状态迁移记一次，而非按段记。
        if matches!(before.0, State::SynReceived) && matches!(after.0, State::Established) {
            self.stats.established += 1;
        }
        if matches!(before.0, State::Established | State::SynReceived)
            && matches!(after.0, State::CloseWait)
        {
            self.stats.peer_fin += 1;
        }
        if !matches!(before.0, State::Closed) && matches!(after.0, State::Closed) {
            self.stats.reset += 1;
        }
        // 连接进入 Closed 且状态机已终结：释放会话，避免占着容量。
        if session.connection.is_closed() {
            self.sessions.close(key);
        }
        Ok(feed)
    }

    /// 新建会话：分配 ISN 种子、`listen()`，容量满则拒绝且不驱逐既有。
    fn open_session(
        &mut self,
        info: PacketInfo,
        key: SessionKey,
        clock: Clock,
    ) -> Result<(), Error> {
        let seed = self.next_iss;
        self.next_iss = self.next_iss.wrapping_add(1);
        let mut connection = Connection::new(self.config.connection);
        connection.set_iss_seed(seed);
        connection.listen();
        let session = Session {
            connection,
            local: info.destination,
            peer: info.source,
            local_port: info.destination_port,
            peer_port: info.source_port,
        };
        match self.sessions.open(key, session, clock) {
            Ok(_) => Ok(()),
            Err(OpenError::Capacity { capacity, .. }) => {
                self.stats.session_rejected += 1;
                Err(Error::SessionFull(capacity))
            }
        }
    }
}

impl Feed {
    /// 无回包、无载荷的拒绝结果（校验失败与过大判定共用）。
    fn rejected() -> Self {
        Self {
            replies: Vec::new(),
            delivered: Vec::new(),
            outcome: FeedOutcome::None,
        }
    }
}

// ---- 与参考实现 / RFC 9293 的有意差异 ----
//
// 1. 只处理**入站**（对端 → 本端）方向。`feed` 的名字即口径：设备喂进来的报文按
//    「来自链路」处理；主动 connect 方向本卡不实现（见 stream.rs 与 docs）。
// 2. IPv4 回包固定 IHL=5，不发选项、不复制入站选项；入站带选项的报文仍可被
//    `packet::inspect` 接受并正常处理。
// 3. 回包只做一层 `mtu::decide` 的**入站**过大判定；回包自身的出站过大不在此处二次
//    判定（本层不持有链路 MTU 的发送语义）。分片由上层决定，本层不重组入站分片。
// 4. 会话表按**入站五元组**建键，回包靠地址对调，不建第二条反向会话——与参考实现
//    「一个 Link 承载双向」不同，这里双向共用同一条 `Connection`。
// 5. 连接进入 `Closed`（RST 或最终 ACK）即释放会话条目，不保留 TIME-WAIT 占位。
// 6. `SessionTable` 只在被访问的键上做过期回收；批量回收要靠上层周期调用 [`TcpListener::gc`]。
