//! 权威绑定来源：环境身份、设备身份、租约与归因。

/// 环境身份。与 `lengsuo-environment::EnvironmentId` 同构；本 crate 不反向依赖它。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvironmentId(pub u64);

/// 出口设备身份。与 `lengsuo-environment::DeviceId` 同构。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u64);

/// 权威租约：与 `lengsuo-environment::Lease` 同构（含路由器实例命名空间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub instance: [u8; 16],
    pub environment: EnvironmentId,
    pub device: DeviceId,
    pub epoch: u64,
}

/// 分类器给出的环境归因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribution {
    pub environment: EnvironmentId,
    pub device: DeviceId,
    pub epoch: u64,
}

/// 权威绑定来源的拒绝原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// 该环境没有任何绑定。
    #[error("环境 {0:?} 没有出口绑定")]
    UnknownEnvironment(EnvironmentId),
    /// 环境已绑定，但承接它的设备离线。
    #[error("出口设备 {0:?} 离线")]
    DeviceOffline(DeviceId),
    /// 租约已失效（实例、设备或代次与当前权威状态不一致）。
    #[error("租约已失效")]
    StaleLease,
    /// 其它权威拒绝，原因不明时同样拒绝。
    #[error("权威状态拒绝")]
    Rejected,
}

/// 命中的绑定标识（审计用）：只含环境、设备与代次，**不含**任何凭据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingId {
    pub environment: EnvironmentId,
    pub device: DeviceId,
    pub epoch: u64,
}

/// 权威绑定来源：由环境路由核心（如 `lengsuo-environment::Router`）实现。
///
/// 实现方的错误描述**不得**包含口令、密钥或完整配置。
pub trait BindingAuthority {
    /// 解析环境当前的权威租约：环境无绑定或设备离线 ⇒ `Err`。
    fn resolve(&self, environment: EnvironmentId) -> Result<Lease, AuthorityError>;

    /// 校验租约是否仍代表当前权威状态（实例、设备、代次一致且设备在线）。
    fn validate(&self, lease: Lease) -> Result<(), AuthorityError>;
}
