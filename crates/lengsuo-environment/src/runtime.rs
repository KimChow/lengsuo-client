//! 可信入口的连接生命周期：每条流绑定租约，撤销时中止在途中继。
//! 不从 IP 包猜测环境，不接管系统流量；平台入口必须先完成身份认证。
use crate::{Binding, DeviceId, EnvironmentId, Lease, Router, RouterError};
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    time::timeout,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("路由状态拒绝：{0}")]
    Router(#[from] RouterError),
    #[error("连接容量必须大于零")]
    InvalidCapacity,
    #[error("连接容量耗尽")]
    Capacity,
    #[error("连接序号耗尽")]
    Exhausted,
    #[error("连接租约已撤销")]
    Revoked,
    #[error("连接总存活时间超过限制")]
    Timeout,
    #[error("连接总存活时间必须大于零")]
    InvalidLifetime,
    #[error("中继失败：{0}")]
    Io(#[from] std::io::Error),
}

pub struct Runtime {
    router: Router,
    flows: BTreeMap<u64, (Lease, watch::Sender<bool>)>,
    sequence: u64,
    capacity: usize,
}
impl Runtime {
    pub fn new(capacity: usize) -> Result<Self, Error> {
        if capacity == 0 {
            return Err(Error::InvalidCapacity);
        }
        Ok(Self {
            router: Router::new()?,
            flows: BTreeMap::new(),
            sequence: 0,
            capacity,
        })
    }
    pub fn bind(&mut self, environment: EnvironmentId, device: DeviceId) -> Result<Lease, Error> {
        let lease = self.router.bind(environment, device)?;
        self.revoke_invalid();
        Ok(lease)
    }
    pub fn set_online(&mut self, device: DeviceId, online: bool) {
        self.router.set_online(device, online);
        self.revoke_invalid();
    }
    pub fn remove(&mut self, environment: EnvironmentId) -> Option<Binding> {
        let removed = self.router.remove(environment);
        self.revoke_invalid();
        removed
    }
    pub fn resolve(&self, environment: EnvironmentId) -> Result<Lease, Error> {
        Ok(self.router.resolve(environment)?)
    }
    /// 只允许可信入口取得的内部租约；不能把用户提交的字段当作已认证身份。
    pub fn register(&mut self, lease: Lease) -> Result<Flow, Error> {
        self.router.validate(lease)?;
        self.flows
            .retain(|_, (_, sender)| sender.receiver_count() != 0);
        if self.flows.len() >= self.capacity {
            return Err(Error::Capacity);
        }
        let id = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let (sender, receiver) = watch::channel(false);
        self.flows.insert(id, (lease, sender));
        self.sequence = id;
        Ok(Flow { lease, receiver })
    }
    fn revoke_invalid(&mut self) {
        self.flows.retain(|_, (lease, sender)| {
            if self.router.validate(*lease).is_err() {
                sender.send_replace(true);
                false
            } else {
                sender.receiver_count() != 0
            }
        });
    }
}

/// 绑定一条在途连接，不可复制；Runtime 被销毁也按撤销处理。
pub struct Flow {
    lease: Lease,
    receiver: watch::Receiver<bool>,
}
impl Flow {
    pub fn lease(&self) -> Lease {
        self.lease
    }
    pub fn is_revoked(&self) -> bool {
        *self.receiver.borrow() || self.receiver.has_changed().is_err()
    }
    pub async fn revoked(&mut self) {
        if self.is_revoked() {
            return;
        }
        let _ = self.receiver.changed().await;
    }
    /// 消耗并拥有两端流。撤销、超时或错误均丢弃两端，不静默直连。
    /// max_lifetime 是整条连接的总时限；不是空闲超时。
    pub async fn relay<A, B>(
        mut self,
        mut ingress: A,
        mut egress: B,
        max_lifetime: Duration,
    ) -> Result<(u64, u64), Error>
    where
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if max_lifetime.is_zero() {
            return Err(Error::InvalidLifetime);
        }
        if self.is_revoked() {
            return Err(Error::Revoked);
        }
        tokio::select! {
            biased;
            _=self.revoked()=>Err(Error::Revoked),
            result=timeout(max_lifetime,tokio::io::copy_bidirectional(&mut ingress,&mut egress))=>{
                Ok(result.map_err(|_|Error::Timeout)??)
            }
        }
    }
}
