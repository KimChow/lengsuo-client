//! TUN 设备接入层：Windows 侧封装 wintun 的安全 API，其他平台只提供编译期类型桩。
//!
//! 组织方式：本文件承载**平台无关**部分（类型化错误、配置与参数校验、测试名与 GUID
//! 生成、wintun.dll 路径解析与提示）以及非 Windows 的 `Device`/`Library` 桩；
//! `device/windows.rs` 承载 `#[cfg(windows)]` 的真实实现。两个平台的方法签名一致，
//! Linux 门禁只编译桩分支。
//!
//! 安全边界（逐条核对，勿夸大）：
//! - 本 crate 保持 `#![forbid(unsafe_code)]`，只调用 wintun 绑定的安全 API。
//!   wintun 0.5.1 的 `load` / `load_from_path` / `load_from_library` 全是 `unsafe fn`，
//!   因此**动态库加载不由本仓发起**：宿主在自己 crate 内加载后把句柄交给
//!   [`device::Library::from_handle`]。本层的 [`device::ensure_library`] 只解析并提示
//!   dll 路径（环境变量 [`device::LIBRARY_ENV`]，其次可执行文件同目录），
//!   不下载、不复制、不写入系统目录。
//! - **未做真实 Windows 运行验证**：收发语义、错误分类、会话生命周期与 Drop 防重入
//!   目前只通过 Linux 侧编译与静态检查（含 `--target x86_64-pc-windows-msvc` 的
//!   仅编译检查）。实机验证清单见 `docs/tun-status.md`。
//! - [`device::Device::set_mtu`] 会经 wintun 调用 `netsh` 修改系统接口状态，属于外部
//!   可见变更，只在调用方显式请求时执行，本层不自动调用。

use std::path::PathBuf;
use std::time::Duration;

/// wintun.dll 路径环境变量；未设置或非绝对路径时回退到可执行文件同目录。
pub const LIBRARY_ENV: &str = "LENGSUO_WINTUN_DLL";
/// 动态库文件名，仅用于路径拼接与提示文案。
pub const LIBRARY_FILE: &str = "wintun.dll";
/// 测试专用适配器名前缀，便于与真实适配器区分。
pub const TEST_ADAPTER_PREFIX: &str = "lengsuo-tun-test";
/// 单包字节上限：wintun 的包长度字段为 16 位。
pub const MAX_PACKET_BYTES: usize = u16::MAX as usize;
/// 接收轮询间隔：无报文时最多睡这么久再看下一次。
pub const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// 设备接入层的类型化错误。所有失败路径都返回本枚举：不 panic、不回退明文、不静默丢包。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 当前平台没有设备实现。桩分支上的任何构造与收发都走这里，运行期不可达设备路径。
    #[error("平台不支持：TUN 设备接入层仅在 Windows 实现（当前平台 {os}）")]
    Unsupported { os: &'static str },
    /// 找不到 wintun.dll，附带期望路径与放置提示。
    #[error("未找到 wintun.dll：请把签名的 dll 放到 {expected}，或设置环境变量 {LIBRARY_ENV} 指向绝对路径（本层不写入系统目录）")]
    LibraryMissing { expected: PathBuf },
    /// 本仓零 unsafe，动态库必须由宿主加载后注入句柄。
    #[error("缺少已加载的 wintun 句柄：{}", LIBRARY_HINT)]
    LibraryRequired,
    /// ring 容量越界或不是 2 的幂。
    #[error("ring 容量 {value} 非法：必须是 {min}..={max} 之间的 2 的幂")]
    RingCapacity { value: u32, min: u32, max: u32 },
    /// MTU 越界。
    #[error("MTU {value} 非法：必须在 {min}..={max} 之间")]
    Mtu { value: u16, min: u16, max: u16 },
    /// 适配器名或隧道类型不合法。
    #[error("名称非法：{reason}")]
    InvalidName { reason: String },
    /// 设备已关闭，句柄不可再用。
    #[error("设备已关闭：该句柄不可再用于收发")]
    Closed,
    /// 在给定超时内没有收到报文。
    #[error("接收超时：等待 {waited:?} 后仍无报文")]
    Timeout { waited: Duration },
    /// 报文为空或超过单包上限。
    #[error("报文长度 {value} 非法：单包上限 {max} 字节且不得为空")]
    InvalidPacket { value: usize, max: usize },
    /// 发送环形缓冲无空闲空间。
    #[error("发送缓冲不足：wintun 发送环形缓冲暂无空闲空间")]
    BufferInsufficient,
    /// 会话结束、适配器被移除或驱动撤回。
    #[error("会话已结束：适配器或会话已被关闭")]
    SessionEnded,
    /// 其他来自 wintun 绑定或系统调用的失败，保留原始文案便于实机排障。
    #[error("设备操作失败：{reason}")]
    Device { reason: String },
}

/// 固定提示文案：说明「本层不加载 dll」这一约束，避免错误信息随平台漂移。
const LIBRARY_HINT: &str =
    "请在宿主 crate 内加载 wintun.dll 后用 Library::from_handle 注入（本 crate 禁止 unsafe）";

/// 设备接入层的统一返回类型。
pub type Result<T> = std::result::Result<T, Error>;

/// 创建适配器与开启会话所需的配置。字段全部由调用方控制，本层不隐藏默认值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    /// 适配器名，Windows 上显示为 Friendly Name。
    pub adapter_name: String,
    /// 隧道类型，即 wintun 的池名。
    pub tunnel_type: String,
    /// 适配器 GUID；`None` 表示交由 wintun 生成。
    pub guid: Option<u128>,
    /// 会话环形缓冲字节数，必须是 2 的幂。
    pub ring_capacity: u32,
    /// 适配器 MTU。
    pub mtu: u16,
}

impl DeviceConfig {
    /// wintun 规定的最小 ring 容量（字节）。
    pub const MIN_RING_CAPACITY: u32 = 0x0002_0000;
    /// wintun 规定的最大 ring 容量（字节）。
    pub const MAX_RING_CAPACITY: u32 = 0x400_0000;
    /// 默认隧道类型。
    pub const DEFAULT_TUNNEL_TYPE: &'static str = "Wintun";
    /// 允许的最小 MTU：取 IPv6 最小链路 MTU，同时满足 IPv4。
    pub const MIN_MTU: u16 = 1280;
    /// 允许的最大 MTU：与单包上限一致。
    pub const MAX_MTU: u16 = u16::MAX;
    /// 默认 ring 容量：取最小合法值，生产需调用方显式放大。
    pub const DEFAULT_RING_CAPACITY: u32 = Self::MIN_RING_CAPACITY;
    /// 默认 MTU。
    pub const DEFAULT_MTU: u16 = 1500;
    /// 适配器名长度上限。
    pub const MAX_NAME_LEN: usize = 64;
    /// 池名长度上限：wintun.h 的 MAX_POOL 含结束符为 256。
    pub const MAX_TUNNEL_TYPE_LEN: usize = 255;

    /// 平台无关的配置起点。
    #[must_use]
    pub fn new(adapter_name: impl Into<String>) -> Self {
        Self {
            adapter_name: adapter_name.into(),
            tunnel_type: Self::DEFAULT_TUNNEL_TYPE.to_string(),
            guid: None,
            ring_capacity: Self::DEFAULT_RING_CAPACITY,
            mtu: Self::DEFAULT_MTU,
        }
    }

    /// 测试专用配置：随机前缀名 + 随机 GUID + 最小 ring 容量 + 默认 MTU。
    #[must_use]
    pub fn for_test() -> Self {
        Self {
            guid: Some(test_guid()),
            ..Self::new(test_adapter_name())
        }
    }

    /// 全量校验。桩分支同样先走本函数，因此平台无关的错误在两个平台一致。
    pub fn validate(&self) -> Result<()> {
        validate_name("适配器名", &self.adapter_name, Self::MAX_NAME_LEN)?;
        validate_name("隧道类型", &self.tunnel_type, Self::MAX_TUNNEL_TYPE_LEN)?;
        self.validate_ring_capacity(self.ring_capacity)?;
        self.validate_mtu(self.mtu)?;
        Ok(())
    }

    /// 校验 ring 容量：范围与 2 的幂。
    pub fn validate_ring_capacity(&self, capacity: u32) -> Result<()> {
        if !capacity.is_power_of_two()
            || !(Self::MIN_RING_CAPACITY..=Self::MAX_RING_CAPACITY).contains(&capacity)
        {
            return Err(Error::RingCapacity {
                value: capacity,
                min: Self::MIN_RING_CAPACITY,
                max: Self::MAX_RING_CAPACITY,
            });
        }
        Ok(())
    }

    /// 校验 MTU 范围。
    pub fn validate_mtu(&self, mtu: u16) -> Result<()> {
        if !(Self::MIN_MTU..=Self::MAX_MTU).contains(&mtu) {
            return Err(Error::Mtu {
                value: mtu,
                min: Self::MIN_MTU,
                max: Self::MAX_MTU,
            });
        }
        Ok(())
    }

    /// 校验报文长度：非空，且不超过 MTU 与单包上限；返回本次生效的上限。
    pub fn validate_packet_len(&self, len: usize) -> Result<usize> {
        let max = usize::from(self.mtu).min(MAX_PACKET_BYTES);
        if len == 0 || len > max {
            return Err(Error::InvalidPacket { value: len, max });
        }
        Ok(max)
    }
}

/// 名称规则：非空、长度受限、不含控制字符以及 `netsh` 会误读的引号与路径分隔符。
/// wintun 的 MTU/改名操作把适配器名拼进 `netsh` 参数，因此这里 fail-closed 拒绝，
/// 而不是尝试转顺。
fn validate_name(kind: &str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidName {
            reason: format!("{kind}不得为空"),
        });
    }
    let count = value.chars().count();
    if count > max {
        return Err(Error::InvalidName {
            reason: format!("{kind}长度 {count} 超过上限 {max}"),
        });
    }
    if value
        .chars()
        .any(|c| matches!(c, '"' | '\'' | '\\' | '/') || c.is_control())
    {
        return Err(Error::InvalidName {
            reason: format!("{kind}不得包含引号、路径分隔符或控制字符"),
        });
    }
    Ok(())
}

/// 测试专用适配器名：前缀 + 8 位十六进制散列，避免与真实适配器重名。
#[must_use]
pub fn test_adapter_name() -> String {
    format!("{TEST_ADAPTER_PREFIX}-{:08x}", test_seed() as u32)
}

/// 测试专用 GUID：由时间、进程号与单调计数器散列而来，仅用于隔离测试适配器。
/// 不是密码学随机数，也不承载任何身份或归属含义。
#[must_use]
pub fn test_guid() -> u128 {
    let high = test_seed();
    let low = test_seed();
    (u128::from(high) << 64) | u128::from(low)
}

/// 单调散列种子：计数器每次调用都自增，因此连续两次的结果不同。
fn test_seed() -> u64 {
    use std::hash::{Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    COUNTER.fetch_add(1, Ordering::Relaxed).hash(&mut hasher);
    hasher.finish()
}

/// 解析 wintun.dll 的期望路径：环境变量里的绝对路径优先，其次可执行文件同目录。
/// 只计算路径，不复制、不下载、不写入系统目录。
#[must_use]
pub fn library_path() -> PathBuf {
    if let Some(path) = std::env::var_os(LIBRARY_ENV) {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return path;
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(LIBRARY_FILE)))
        .unwrap_or_else(|| PathBuf::from(LIBRARY_FILE))
}

/// 检查 wintun.dll 是否就位。缺失时返回带放置提示的 [`Error::LibraryMissing`]，
/// 内含期望路径。本函数不尝试加载或安装任何东西。
pub fn ensure_library() -> Result<PathBuf> {
    let path = library_path();
    if path.is_file() {
        Ok(path)
    } else {
        Err(Error::LibraryMissing { expected: path })
    }
}

/// 固定提示文案，供上层日志与错误信息复用。
#[must_use]
pub fn library_load_hint() -> &'static str {
    LIBRARY_HINT
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{Device, Library};

/// 宿主注入的库句柄类型：Windows 上是 wintun 绑定的 `Wintun`（内部 `Arc`），
/// 其他平台是零大小占位类型，好让两个平台的方法签名保持一致。
#[cfg(windows)]
pub type LibraryHandle = wintun::Wintun;

/// 非 Windows 的库句柄占位类型。构造它不会访问任何设备，因为桩的实现
/// 一律返回 [`Error::Unsupported`]。
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibraryHandle;

#[cfg(not(windows))]
mod stub;
#[cfg(not(windows))]
pub use stub::{Device, Library};
