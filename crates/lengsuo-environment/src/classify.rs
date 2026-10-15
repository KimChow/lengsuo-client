//! 报文 -> 环境归属的分类核心，供浏览器 TUN 分流层在放行任何字节之前调用。
//!
//! 权威来源分工：环境 -> 出口设备仍由既有 [`Router`] 持有，本模块只借用它，
//! 不复制路由状态，也不改动它的任何行为；本模块新增的是「五元组 -> 环境」
//! 的会话归属，以及 DNS 端口语义。
//!
//! 安全底线（全部 fail-closed，不存在「放行直连」的第三种出口）：
//! - 没有任何归属登记的流一律 [`DenyReason::NoAttribution`]。环境身份来自可信
//!   入口的显式登记（`register`），绝不从地址、端口或域名猜测。
//! - 环境被撤销、换绑或出口设备离线后，新流被拒，存量会话在判定时一并清除，
//!   与 `runtime::Runtime` 现有「租约不再有效就中止在途连接」的策略一致。
//! - DNS（UDP 端口 53）只能走该环境绑定的出口设备，请求其他出口即拒绝；
//!   DNS 响应只会交付给发起查询的那个环境（会话键绑定 + 显式收件方校验）。

use crate::flow::{traffic_kind, Attribution, Direction, FlowKey, Timestamp, TrafficKind};
use crate::router::{DeviceId, EnvironmentId, Lease, Router, RouterError};
use crate::session::{Session, SessionError, SessionTable};
use lengsuo_tun::packet::PacketInfo;
use std::time::Duration;

/// 分类与出口授权的全部拒绝原因。调用方必须丢弃报文并记录原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    /// 该五元组从未被任何环境登记：默认拒绝，绝不静默直连。
    #[error("流 {0:?} 没有环境归属，默认拒绝")]
    NoAttribution(FlowKey),
    /// 登记过但会话已到期，需要可信入口重新登记。
    #[error("流 {0:?} 的会话已到期")]
    SessionExpired(FlowKey),
    /// 会话登记的代次落后于当前权威绑定（换设备或重绑）。
    #[error("流 {0:?} 的会话代次 {1} 已过期，当前权威代次为 {2}")]
    StaleSession(FlowKey, u64, u64),
    /// 归属环境已无任何绑定（被撤销或从未绑定）。
    #[error("环境 {0:?} 没有出口绑定")]
    UnknownEnvironment(EnvironmentId),
    /// 归属环境的出口设备离线。
    #[error("出口设备 {0:?} 离线")]
    DeviceOffline(DeviceId),
    /// 会话表容量必须大于零。
    #[error("会话表容量必须大于零")]
    InvalidCapacity,
    /// 会话表已满：拒绝新会话，且不驱逐任何既有会话。
    #[error("会话表已满，拒绝新会话")]
    SessionFull,
    /// 该五元组已被另一个环境占用（跨环境抢占）。
    #[error("流 {0:?} 已被环境 {1:?} 占用")]
    SessionOccupied(FlowKey, EnvironmentId),
    /// DNS 被要求走非授权出口。
    #[error("环境 {0:?} 的 DNS 只能走出口 {1:?}，拒绝 {2:?}")]
    DnsEgressDenied(EnvironmentId, DeviceId, DeviceId),
    /// 非 DNS 流被要求走非授权出口。
    #[error("环境 {0:?} 只能走出口 {1:?}，拒绝 {2:?}")]
    EgressDenied(EnvironmentId, DeviceId, DeviceId),
    /// 响应要交付给并非发起方的环境。
    #[error("DNS 响应由环境 {1:?} 发起，拒绝交付给 {2:?}")]
    DnsResponseNotInitiator(FlowKey, EnvironmentId, EnvironmentId),
    /// 时间算术溢出，无法确定会话寿命。
    #[error("会话时间计算溢出")]
    Clock,
    /// 路由核心的其他拒绝分支，原样上抛，不做二次解释。
    #[error("路由状态拒绝：{0}")]
    Router(#[from] RouterError),
}

/// 一条被判定通过的流：归属环境 + 唯一授权出口 + 代次 + 流量语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub key: FlowKey,
    pub direction: Direction,
    pub kind: TrafficKind,
    pub attribution: Attribution,
}

impl Decision {
    /// 该流唯一授权的出口设备；任何出口拨号都必须等于它。
    pub fn egress(&self) -> DeviceId {
        self.attribution.device
    }

    /// DNS 语义只由端口判定，载荷不被解析也不被信任。
    pub fn is_dns(&self) -> bool {
        matches!(self.kind, TrafficKind::DnsQuery | TrafficKind::DnsResponse)
    }
}

/// 分类器 = 会话归属表 + 借用的权威路由（按调用传入，不持有）。
pub struct Classifier {
    sessions: SessionTable,
}

impl Classifier {
    /// `idle_ttl` 是可续期存活期，`hard_ttl` 是首次登记起算的绝对上限。
    pub fn new(
        capacity: usize,
        idle_ttl: Duration,
        hard_ttl: Duration,
    ) -> Result<Self, DenyReason> {
        Ok(Self {
            sessions: SessionTable::new(capacity, idle_ttl, hard_ttl)
                .map_err(|_| DenyReason::InvalidCapacity)?,
        })
    }

    /// 可信入口登记一条出站流：环境身份来自已认证的入口，而非报文本身。
    ///
    /// 先向权威路由解析该环境，成功才占用会话槽位；绑定缺失或设备离线时
    /// 返回对应拒绝，且不留下任何状态。
    pub fn register(
        &mut self,
        router: &Router,
        info: &PacketInfo,
        environment: EnvironmentId,
        now: Timestamp,
    ) -> Result<Decision, DenyReason> {
        let key = FlowKey::from_packet(info, Direction::Egress);
        self.prepare(router, key, environment, now)
    }

    /// 登记归一化键并给出判决。`register` 的键由报文元数据推导，此入口便于
    /// 上层（已自行完成解析）直接复用同一套 fail-closed 检查。
    pub fn open(
        &mut self,
        router: &Router,
        key: FlowKey,
        environment: EnvironmentId,
        now: Timestamp,
    ) -> Result<Decision, DenyReason> {
        self.prepare(router, key, environment, now)
    }

    /// 判定一个报文能否放行、该走哪台出口。
    ///
    /// 命中时只续期会话寿命，绝不为未知归属的流创建条目；一旦归属环境的
    /// 权威状态已失效（撤销、换绑、离线），存量条目在拒绝的同时被清除，
    /// 与运行时中止在途连接的语义一致。
    pub fn classify(
        &mut self,
        router: &Router,
        info: &PacketInfo,
        direction: Direction,
        now: Timestamp,
    ) -> Result<Decision, DenyReason> {
        self.classify_key(
            router,
            FlowKey::from_packet(info, direction),
            direction,
            now,
        )
    }

    /// [`Classifier::classify`] 的显式键版本。
    pub fn classify_key(
        &mut self,
        router: &Router,
        key: FlowKey,
        direction: Direction,
        now: Timestamp,
    ) -> Result<Decision, DenyReason> {
        let session = match self.sessions.get(key, now) {
            Some(session) => session,
            None => {
                return Err(if self.sessions.expired(key, now) {
                    self.sessions.remove(key);
                    DenyReason::SessionExpired(key)
                } else {
                    DenyReason::NoAttribution(key)
                })
            }
        };
        let lease = match router.resolve(session.environment) {
            Ok(lease) => lease,
            Err(error) => {
                // 撤销/离线：新流与存量会话一并拒绝并清除（对齐 Runtime 策略）。
                self.sessions.remove(key);
                return Err(deny_router(error));
            }
        };
        if lease.epoch != session.epoch {
            self.sessions.remove(key);
            return Err(DenyReason::StaleSession(key, session.epoch, lease.epoch));
        }
        let session = self
            .sessions
            .refresh(key, now)
            .and_then(|(_, opened)| opened.ok())
            .ok_or(DenyReason::SessionExpired(key))?;
        decide(&key, direction, &lease, &session)
    }

    /// 校验出口设备是否是该判决授权的出口。DNS 给出专门的拒绝原因。
    pub fn authorize(&self, decision: Decision, requested: DeviceId) -> Result<(), DenyReason> {
        if decision.egress() == requested {
            return Ok(());
        }
        let environment = decision.attribution.environment;
        Err(if decision.is_dns() {
            DenyReason::DnsEgressDenied(environment, decision.egress(), requested)
        } else {
            DenyReason::EgressDenied(environment, decision.egress(), requested)
        })
    }

    /// DNS 响应只能交付给发起查询的环境；收件方不符即拒绝。
    ///
    /// 走与入站判定完全相同的会话键绑定：响应必须命中发起方登记过的那条会话，
    /// 因此环境身份取自会话表而不是响应方声明，收件方只用于比对。
    pub fn deliver_dns_response(
        &mut self,
        router: &Router,
        key: FlowKey,
        recipient: EnvironmentId,
        now: Timestamp,
    ) -> Result<Decision, DenyReason> {
        let initiator = self
            .sessions
            .get(key, now)
            .ok_or(DenyReason::NoAttribution(key))?
            .environment;
        if initiator != recipient {
            return Err(DenyReason::DnsResponseNotInitiator(
                key, initiator, recipient,
            ));
        }
        let decision = self.classify_key(router, key, Direction::Ingress, now)?;
        if decision.kind != TrafficKind::DnsResponse {
            return Err(DenyReason::NoAttribution(key));
        }
        Ok(decision)
    }

    /// 撤销某环境的全部会话。撤销后其新流一律被拒绝。
    pub fn revoke(&mut self, environment: EnvironmentId) -> usize {
        self.sessions.revoke(environment)
    }

    /// 清除所有已失效会话（到期、绑定被撤销、设备离线或代次已更新）。
    /// 上层在路由状态变更后周期调用，返回清除条数。
    pub fn prune(&mut self, router: &Router, now: Timestamp) -> usize {
        self.sessions.reap(now);
        let stale: Vec<FlowKey> = self
            .sessions
            .iter()
            .filter(|(_, session)| match router.resolve(session.environment) {
                Ok(lease) => lease.epoch != session.epoch,
                Err(_) => true,
            })
            .map(|(key, _)| *key)
            .collect();
        for key in &stale {
            self.sessions.remove(*key);
        }
        stale.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn session_of(&self, key: FlowKey, now: Timestamp) -> Option<Session> {
        self.sessions.get(key, now)
    }

    fn prepare(
        &mut self,
        router: &Router,
        key: FlowKey,
        environment: EnvironmentId,
        now: Timestamp,
    ) -> Result<Decision, DenyReason> {
        let lease = router.resolve(environment).map_err(deny_router)?;
        let session = self
            .sessions
            .open(key, lease.environment, lease.epoch, now)
            .map_err(deny_session)?;
        decide(&key, Direction::Egress, &lease, &session)
    }
}

/// DNS 与非 DNS 走同一套出口绑定检查：出口设备取自权威 lease，
/// 因此非授权出口只能在 [`Classifier::authorize`] 处被拒。
fn decide(
    key: &FlowKey,
    direction: Direction,
    lease: &Lease,
    session: &Session,
) -> Result<Decision, DenyReason> {
    Ok(Decision {
        key: *key,
        direction,
        kind: traffic_kind(key, direction),
        attribution: Attribution {
            environment: lease.environment,
            device: lease.device,
            epoch: session.epoch,
        },
    })
}

fn deny_router(error: RouterError) -> DenyReason {
    match error {
        RouterError::UnknownEnvironment(environment) => DenyReason::UnknownEnvironment(environment),
        RouterError::DeviceOffline(device) => DenyReason::DeviceOffline(device),
        other => DenyReason::Router(other),
    }
}

fn deny_session(error: SessionError) -> DenyReason {
    match error {
        SessionError::Full => DenyReason::SessionFull,
        SessionError::Occupied { key, holder } => DenyReason::SessionOccupied(key, holder),
        SessionError::Clock => DenyReason::Clock,
        SessionError::InvalidCapacity => DenyReason::InvalidCapacity,
    }
}
