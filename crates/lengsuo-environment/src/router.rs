use std::collections::BTreeMap;
use std::fmt;

/// 浏览器环境身份。仅用作路由键，与域名无关。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvironmentId(pub u64);

/// 出口设备身份。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u64);

/// 权威绑定：环境身份当前占用哪台设备以及哪个代次。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// 当前承接该环境的出口设备。
    pub device: DeviceId,
    /// 绑定代次；每次成功绑定分配新的、全局严格递增的值。
    pub epoch: u64,
}

/// 交给上层使用的凭据式快照。epoch 不匹配即视为过期。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// 路由器实例的随机命名空间；不是授权密钥，租约仅供可信运行时内部使用。
    pub instance: [u8; 16],
    /// 所属环境身份。
    pub environment: EnvironmentId,
    /// 授权使用的出口设备。
    pub device: DeviceId,
    /// 签发时的绑定代次。
    pub epoch: u64,
}

/// 路由核心的失败原因。所有分支都是 fail-closed：调用方不得回退到默认出口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterError {
    /// 该环境身份没有任何绑定。
    UnknownEnvironment(EnvironmentId),
    /// 该设备从未上报状态，或当前处于离线状态。
    DeviceOffline(DeviceId),
    /// lease 的 epoch 或设备与当前权威绑定不一致（已被切换、重绑或撤销）。
    StaleLease(Lease),
    /// epoch 计数器已到上界，无法再分配严格递增的代次。
    EpochExhausted,
    /// 无法取得系统随机数，不创建可能复用旧命名空间的路由器。
    EntropyUnavailable,
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::UnknownEnvironment(env) => {
                write!(f, "环境 {env:?} 没有出口绑定")
            }
            RouterError::DeviceOffline(device) => write!(f, "设备 {device:?} 离线"),
            RouterError::StaleLease(lease) => write!(f, "lease 已失效: {lease:?}"),
            RouterError::EpochExhausted => write!(f, "绑定代次已耗尽"),
            RouterError::EntropyUnavailable => write!(f, "无法创建路由实例命名空间"),
        }
    }
}

impl std::error::Error for RouterError {}

/// 环境到出口设备的权威路由表。
///
/// 单线程所有权模型：状态由出口运行时的所有者持有，不含锁与异步原语。
#[derive(Debug)]
pub struct Router {
    instance: [u8; 16],
    bindings: BTreeMap<EnvironmentId, Binding>,
    online: BTreeMap<DeviceId, bool>,
    next_epoch: u64,
}

impl Router {
    /// 新建空路由表；此时没有任何设备，所有设备默认离线。
    pub fn new() -> Result<Self, RouterError> {
        let mut instance = [0; 16];
        getrandom::getrandom(&mut instance).map_err(|_| RouterError::EntropyUnavailable)?;
        Ok(Self {
            instance,
            bindings: BTreeMap::new(),
            online: BTreeMap::new(),
            next_epoch: 0,
        })
    }

    /// 把环境绑定到指定设备并签发 lease。
    ///
    /// 目标设备必须已显式上线；否则返回 [`RouterError::DeviceOffline`]
    /// 且完全不改动既有绑定、不消耗代次。成功时旧绑定被替换，旧 lease 立即失效。
    pub fn bind(
        &mut self,
        environment: EnvironmentId,
        device: DeviceId,
    ) -> Result<Lease, RouterError> {
        if !self.is_online(device) {
            return Err(RouterError::DeviceOffline(device));
        }
        let epoch = self
            .next_epoch
            .checked_add(1)
            .ok_or(RouterError::EpochExhausted)?;
        self.next_epoch = epoch;
        self.bindings.insert(environment, Binding { device, epoch });
        Ok(Lease {
            instance: self.instance,
            environment,
            device,
            epoch,
        })
    }

    /// 上报设备在线状态。
    ///
    /// 置为离线时，该设备名下全部绑定立即失效并被移除；重新上线不会恢复它们，
    /// 必须由上层显式重新 [`Router::bind`]。返回本次失效的绑定数量。
    pub fn set_online(&mut self, device: DeviceId, online: bool) -> usize {
        self.online.insert(device, online);
        if online {
            return 0;
        }
        let stale: Vec<EnvironmentId> = self
            .bindings
            .iter()
            .filter(|(_, binding)| binding.device == device)
            .map(|(environment, _)| *environment)
            .collect();
        let count = stale.len();
        for environment in stale {
            self.bindings.remove(&environment);
        }
        count
    }

    /// 撤销环境绑定。幂等：没有绑定时返回 `None`，被移除时返回旧绑定。
    ///
    /// 已分配过的代次永不复用，因此同 id 重建一定拿到更大的 epoch。
    pub fn remove(&mut self, environment: EnvironmentId) -> Option<Binding> {
        self.bindings.remove(&environment)
    }

    /// 按环境身份解析当前可用出口。
    ///
    /// 注意入参不含域名：域名不参与身份判定，只做无映射与离线的 fail-closed 检查。
    pub fn resolve(&self, environment: EnvironmentId) -> Result<Lease, RouterError> {
        let binding = self
            .bindings
            .get(&environment)
            .ok_or(RouterError::UnknownEnvironment(environment))?;
        if !self.is_online(binding.device) {
            return Err(RouterError::DeviceOffline(binding.device));
        }
        Ok(Lease {
            instance: self.instance,
            environment,
            device: binding.device,
            epoch: binding.epoch,
        })
    }

    /// 校验上层持有的 lease 是否仍然代表当前权威状态且设备在线。
    pub fn validate(&self, lease: Lease) -> Result<(), RouterError> {
        match self.bindings.get(&lease.environment) {
            None => Err(RouterError::UnknownEnvironment(lease.environment)),
            Some(binding) => {
                if lease.instance != self.instance
                    || binding.device != lease.device
                    || binding.epoch != lease.epoch
                {
                    return Err(RouterError::StaleLease(lease));
                }
                if !self.is_online(lease.device) {
                    return Err(RouterError::DeviceOffline(lease.device));
                }
                Ok(())
            }
        }
    }

    /// 设备是否已显式上报在线；未知设备视为离线。
    pub fn is_online(&self, device: DeviceId) -> bool {
        self.online.get(&device).copied().unwrap_or(false)
    }

    /// 当前绑定总数（测试与诊断用）。
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// 查看环境的当前绑定，不检查在线状态。
    pub fn binding_of(&self, environment: EnvironmentId) -> Option<Binding> {
        self.bindings.get(&environment).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: EnvironmentId = EnvironmentId(7);
    const DEV: DeviceId = DeviceId(70);

    /// 代次上界必须拒绝分配，且不留下任何副作用。
    #[test]
    fn epoch_exhaustion_is_rejected_without_mutating_state() {
        let mut router = Router {
            instance: [0; 16],
            bindings: BTreeMap::new(),
            online: BTreeMap::from([(DEV, true)]),
            next_epoch: u64::MAX,
        };
        assert_eq!(router.bind(ENV, DEV), Err(RouterError::EpochExhausted));
        assert_eq!(router.next_epoch, u64::MAX);
        assert!(router.bindings.is_empty());
        assert!(matches!(
            router.resolve(ENV),
            Err(RouterError::UnknownEnvironment(ENV))
        ));
    }

    /// 权威绑定指向离线设备属于内部不变量的防御分支：resolve/validate 都必须拒绝。
    #[test]
    fn resolve_and_validate_reject_offline_bound_device() {
        let router = Router {
            instance: [0; 16],
            bindings: BTreeMap::from([(
                ENV,
                Binding {
                    device: DEV,
                    epoch: 1,
                },
            )]),
            online: BTreeMap::from([(DEV, false)]),
            next_epoch: 1,
        };
        let lease = Lease {
            instance: [0; 16],
            environment: ENV,
            device: DEV,
            epoch: 1,
        };
        assert_eq!(router.resolve(ENV), Err(RouterError::DeviceOffline(DEV)));
        assert_eq!(router.validate(lease), Err(RouterError::DeviceOffline(DEV)));
    }

    /// 正常路径的最小闭环：上线、绑定、解析、校验。
    #[test]
    fn bind_resolve_validate_roundtrip() {
        let mut router = Router::new().unwrap();
        router.set_online(DEV, true);
        let lease = router.bind(ENV, DEV).expect("绑定应成功");
        assert_eq!(lease.epoch, 1);
        assert_eq!(router.resolve(ENV), Ok(lease));
        assert!(router.validate(lease).is_ok());
        assert_eq!(router.binding_count(), 1);
    }
}
