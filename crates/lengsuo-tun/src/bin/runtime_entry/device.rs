//! 设备抽象、类型化错误与非 Linux 平台的显式不支持桩。
//!
//! 设备在本入口里承担两件事：**收包**与**写回**。收包复用既有的
//! [`lengsuo_tun::ingress::PacketSource`] 抽象（超时与错误分开），写回由本模块的
//! [`TunDevice`] 承载——这样设备替身只需实现两个小 trait，测试就能整套替换。
//!
//! 平台口径：
//! - Linux：真实 TUN 设备（见 [`super::linux`]，本卡唯一含 `unsafe` 的模块）。
//! - 其它平台：[`open_device`] **显式**返回 [`DeviceError::Unsupported`]，
//!   **不返回空设备、不静默成功**；[`UnsupportedDevice`] 的收发同样显式报错。

use std::time::Duration;

use lengsuo_tun::ingress::{PacketSource, Receipt};

#[cfg(target_os = "linux")]
use super::linux::LinuxTunDevice;

/// 设备层失败原因。全部显式：不静默降级、不假装成功。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceError {
    /// 系统调用失败。`op` 是稳定的操作名，`code` 是 errno（负值）。
    #[error("设备 {op} 失败：errno {code}")]
    Syscall { op: &'static str, code: i32 },
    /// 当前平台没有设备实现。
    #[error("平台不支持：{platform} 没有 TUN 设备实现")]
    Unsupported { platform: &'static str },
    /// 设备读写层的其它失败（详情由本层生成，不含任何凭据）。
    #[error("设备读写失败：{detail}")]
    Io { detail: String },
    /// 设备已关闭。
    #[error("设备已关闭")]
    Closed,
}

/// 设备写回能力：把一个完整 IP 报文交回链路。
///
/// 只定义写回；收包在 [`PacketSource`]。两者拆开是为了让「只写」或「只读」的
/// 替身也能复用同一套运行时接线。
pub trait TunDevice {
    /// 写回一个完整 IP 报文。失败表示该报文**没有**送出。
    fn send(&mut self, packet: &[u8]) -> Result<(), DeviceError>;
}

/// 非 Linux 平台的设备桩：收发**一律显式报错**，不静默 no-op。
#[derive(Debug, Clone)]
pub struct UnsupportedDevice {
    name: String,
}

impl UnsupportedDevice {
    /// 建立一个不支持平台上的设备桩。名字被如实保留，便于日志定位。
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// 设备名。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TunDevice for UnsupportedDevice {
    fn send(&mut self, _packet: &[u8]) -> Result<(), DeviceError> {
        Err(DeviceError::Unsupported {
            platform: current_platform(),
        })
    }
}

impl PacketSource for UnsupportedDevice {
    type Error = DeviceError;

    fn receive(&mut self, _timeout: Duration) -> Result<Receipt, Self::Error> {
        Err(DeviceError::Unsupported {
            platform: current_platform(),
        })
    }
}

/// 当前平台的设备实现。Linux 上是真实 TUN，其它平台是显式不支持的桩。
#[derive(Debug)]
pub enum PlatformDevice {
    /// Linux 上的真实 TUN 设备。
    #[cfg(target_os = "linux")]
    Linux(LinuxTunDevice),
    /// 其它平台：显式不支持。
    Unsupported(UnsupportedDevice),
}

impl PlatformDevice {
    /// 设备名。
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(device) => device.name(),
            Self::Unsupported(device) => device.name(),
        }
    }

    /// 本设备的 MTU（Linux 上取实际生效值，其它平台无设备故为 `None`）。
    #[must_use]
    pub fn mtu(&self) -> Option<u16> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(device) => Some(device.mtu()),
            Self::Unsupported(_) => None,
        }
    }

    /// 从**内核**读回接口的当前状态（MTU + 是否已 UP）。
    ///
    /// 只有内核认账的值才算「生效」；本地字段只是复述，不是证据。其它平台没有
    /// 设备可问，显式返回 `None`。
    #[cfg(target_os = "linux")]
    pub fn query_state(&self) -> Result<super::linux::InterfaceState, DeviceError> {
        match self {
            Self::Linux(device) => device.query_state(),
            Self::Unsupported(_) => Err(DeviceError::Unsupported {
                platform: current_platform(),
            }),
        }
    }
}

impl TunDevice for PlatformDevice {
    fn send(&mut self, packet: &[u8]) -> Result<(), DeviceError> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(device) => device.send(packet),
            Self::Unsupported(device) => device.send(packet),
        }
    }
}

impl PacketSource for PlatformDevice {
    type Error = DeviceError;

    fn receive(&mut self, timeout: Duration) -> Result<Receipt, Self::Error> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Linux(device) => device.receive(timeout),
            Self::Unsupported(device) => device.receive(timeout),
        }
    }
}

/// 打开平台设备。
///
/// Linux：经 `/dev/net/tun` 的 `TUNSETIFF` ioctl 挂载真实接口（实现见
/// [`super::linux`]），失败时返回类型化的 [`DeviceError`]。
/// 其它平台：**显式**返回 [`DeviceError::Unsupported`]，绝不返回空设备。
pub fn open_device(config: &super::config::RuntimeConfig) -> Result<PlatformDevice, DeviceError> {
    #[cfg(target_os = "linux")]
    {
        let device = super::linux::open(&config.device_name, config.mtu)?;
        Ok(PlatformDevice::Linux(device))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(DeviceError::Unsupported {
            platform: current_platform(),
        })
    }
}

/// 当前平台名（用于错误信息）。
#[must_use]
pub fn current_platform() -> &'static str {
    std::env::consts::OS
}
