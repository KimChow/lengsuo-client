//! 非 Windows 平台的设备桩：只在 `#[cfg(not(windows))]` 下编译。
//!
//! 签名与 `device/windows.rs` 逐一对应，方法体只做**平台无关**的参数校验，
//! 随后一律返回 [`Error::Unsupported`]（等价于「运行不可达」的类型化版本，
//! 不用 `unimplemented!` 以免在测试或链路上留下 panic 路径）。
//! 桩不持有任何系统资源，因此不实现 `Drop`；Windows 分支的析构关闭只在那边存在。
//! 这里的存在意义是让 Linux 门禁（check/test/clippy）能编译同一套 API。

use super::{DeviceConfig, Error, LibraryHandle, Result};
use std::time::Duration;

/// 桩库句柄：不加载任何东西，只满足类型签名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Library;

impl Library {
    /// 桩平台拒绝任何注入的库句柄。
    pub fn from_handle(_wintun: LibraryHandle) -> Result<Self> {
        Err(unsupported())
    }

    /// 桩平台没有可定位的 dll，但仍返回按同样规则算出的期望路径，便于日志一致。
    #[must_use]
    pub fn expected_path() -> std::path::PathBuf {
        super::library_path()
    }

    /// 桩平台的检查同样只看路径是否存在；存在时也继续要求宿主注入句柄。
    pub fn locate() -> Result<std::path::PathBuf> {
        Err(unsupported())
    }

    /// 加载提示，与 Windows 分支同文案。
    #[must_use]
    pub fn load_hint() -> String {
        super::library_load_hint().to_string()
    }
}

/// 桩设备：不创建适配器、不开会话、不收发。
#[derive(Debug)]
pub struct Device {
    config: DeviceConfig,
}

impl Device {
    /// 先做配置校验，再返回 [`Error::Unsupported`]，这样跨平台代码在开发期
    /// 也能看见自己的配置错误；设备操作本身在桩上不可达。
    pub fn create(_library: &Library, config: DeviceConfig) -> Result<Self> {
        config.validate()?;
        Err(unsupported())
    }

    /// 打开已存在适配器：桩上不可达。
    pub fn open(_library: &Library, config: DeviceConfig) -> Result<Self> {
        config.validate()?;
        Err(unsupported())
    }

    /// 会话开启：桩上先校验容量再返回不可达错误。
    pub fn start_session(&mut self, capacity: u32) -> Result<()> {
        self.config.validate_ring_capacity(capacity)?;
        Err(unsupported())
    }

    /// 会话关闭：桩上从未开启过会话。
    pub fn end_session(&mut self) -> Result<()> {
        Err(unsupported())
    }

    /// 桩上恒为 `false`。
    #[must_use]
    pub fn has_session(&self) -> bool {
        false
    }

    /// 桩上恒为 `false`：设备从未开启，因此也谈不上已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        false
    }

    /// 配置原样返回，桩与真实分支一致。
    #[must_use]
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// GUID 需要真实适配器，桩上不可达。
    pub fn guid(&self) -> Result<u128> {
        Err(unsupported())
    }

    /// 接口索引需要真实适配器，桩上不可达。
    pub fn interface_index(&self) -> Result<u32> {
        Err(unsupported())
    }

    /// 设置 MTU：桩上只做范围校验，不触碰任何系统状态。
    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        self.config.validate_mtu(mtu)?;
        Err(unsupported())
    }

    /// 读取 MTU：桩上不可达。
    pub fn mtu(&self) -> Result<u16> {
        Err(unsupported())
    }

    /// 接收报文：桩上不等待、不阻塞，直接返回不可达错误。
    pub fn receive(&self, _timeout: Duration) -> Result<Vec<u8>> {
        Err(unsupported())
    }

    /// 发送报文：桩上只做长度校验。
    pub fn send(&self, packet: &[u8]) -> Result<()> {
        self.config.validate_packet_len(packet.len())?;
        Err(unsupported())
    }

    /// 显式关闭：桩上没有可释放的资源。
    pub fn close(&mut self) -> Result<()> {
        Err(unsupported())
    }
}

/// 统一的桩错误：带当前平台名，便于日志里一眼看出是平台门控问题。
fn unsupported() -> Error {
    Error::Unsupported {
        os: std::env::consts::OS,
    }
}
