//! 系统路由安装/撤销：平台无关的参数校验与句柄生命周期。
//!
//! 平台分层照抄 [`crate::device`]：本文件承载**平台无关**部分（目标前缀、
//! 安装参数、类型化错误、句柄与 `Drop` 清理），`route/windows.rs` 承载
//! `#[cfg(windows)]` 的真实实现（`netsh interface ipv4/ipv6 ... route`），
//! `route/stub.rs` 是其他平台的编译期桩（`install` 一律返回
//! [`RouteError::Unsupported`]）。
//!
//! 为什么用 `netsh` 而不是 `CreateIpForwardEntry2`：本 crate 顶部是
//! `#![forbid(unsafe_code)]`，而 IP Helper API 需要 `unsafe` FFI 声明或引入新的
//! 绑定 crate；本卡不允许新增依赖。`netsh` 走 `std::process::Command`，不引入
//! `unsafe`，也不新增 crate。代价是错误只能按退出码与消息文本分类，见
//! `route/windows.rs` 的说明。
//!
//! 安全边界：
//! - 所有参数在触碰系统状态**之前**校验；非法参数一律 fail-closed。
//! - 缺省路由（`0.0.0.0/0`、`::/0`）必须由调用方在 [`RouteSpec::allow_default`]
//!   显式置 `true`，否则 [`RouteError::DefaultRouteNotAllowed`]。本层不提供
//!   「跳过校验」的开关，[`RouteManager::dry_run`] 也只跳过系统调用、不跳过校验。
//! - 安装后的路由由 [`RouteHandle`] 持有；显式 [`RouteHandle::remove`]、
//!   [`RouteGuard::release`] 或二者之一的 `Drop` 都会撤销。`Drop` 中撤销失败
//!   只写 stderr，绝不 panic。
//! - 真实实现使用 `store=active`：路由不写入持久存储，重启即消失，避免测试或
//!   异常退出后留下永久路由。

use std::net::IpAddr;

mod destination;

pub use destination::RouteDestination;

/// 允许的最小路由 metric。0 表示「自动 metric」，本层要求调用方给出显式值。
pub const MIN_METRIC: u32 = 1;
/// 允许的最大路由 metric：`netsh` 的 `metric=` 取值上限。
pub const MAX_METRIC: u32 = 9999;

/// 一条待安装路由的全部参数。缺省值刻意不提供：`metric` 与
/// `interface_index` 必须由调用方显式给出。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteSpec {
    /// 目标前缀。
    pub destination: RouteDestination,
    /// 出接口索引；0 不是合法接口。
    pub interface_index: u32,
    /// 路由 metric，范围 `1..=9999`。
    pub metric: u32,
    /// 是否允许安装缺省路由。默认 `false`，必须显式打开。
    pub allow_default: bool,
}

impl RouteSpec {
    /// 构造一条**不允许**缺省路由的安装参数。
    #[must_use]
    pub fn new(destination: RouteDestination, interface_index: u32, metric: u32) -> Self {
        Self {
            destination,
            interface_index,
            metric,
            allow_default: false,
        }
    }

    /// 显式授权安装缺省路由。只有确实要接管整机流量的调用方才应调用。
    #[must_use]
    pub fn with_allow_default(mut self) -> Self {
        self.allow_default = true;
        self
    }

    /// 全量校验。`install` 与 `dry_run` 都在任何系统调用之前执行本函数。
    pub fn validate(&self) -> Result<(), RouteError> {
        self.destination.validate()?;
        if self.interface_index == 0 {
            return Err(RouteError::InvalidInterfaceIndex {
                value: self.interface_index,
            });
        }
        if !(MIN_METRIC..=MAX_METRIC).contains(&self.metric) {
            return Err(RouteError::InvalidMetric {
                value: self.metric,
                min: MIN_METRIC,
                max: MAX_METRIC,
            });
        }
        if self.destination.is_default() && !self.allow_default {
            return Err(RouteError::DefaultRouteNotAllowed);
        }
        Ok(())
    }
}

/// 路由层的类型化错误。所有失败路径都返回本枚举：不 panic、不静默降级。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// 前缀长度超出协议族上限。
    #[error("{family} 前缀长度 {prefix_len} 非法：必须在 0..={max}")]
    InvalidPrefix {
        family: &'static str,
        prefix_len: u8,
        max: u8,
    },
    /// 前缀带有主机位，本层不做静默归一化。
    #[error("目标 {address}/{prefix_len} 含主机位：请传网络地址")]
    HostBitsSet { address: IpAddr, prefix_len: u8 },
    /// 缺省路由未显式授权。
    #[error("拒绝安装缺省路由：必须由调用方显式设置 allow_default=true")]
    DefaultRouteNotAllowed,
    /// 接口索引为 0。
    #[error("接口索引 {value} 非法：0 不是合法出接口")]
    InvalidInterfaceIndex { value: u32 },
    /// metric 越界。
    #[error("metric {value} 越界：必须在 {min}..={max} 之间")]
    InvalidMetric { value: u32, min: u32, max: u32 },
    /// 当前平台没有路由实现（非 Windows 桩）。
    #[error("平台不支持：系统路由安装仅在 Windows 实现（当前平台 {os}）")]
    Unsupported { os: &'static str },
    /// 需要管理员权限（Windows 拒绝访问/要求提升）。
    #[error("{operation}需要管理员权限：{message}")]
    PermissionDenied {
        operation: &'static str,
        message: String,
    },
    /// 系统命令执行失败（非权限问题）。
    #[error("{operation}失败（退出码 {code:?}）：{message}")]
    CommandFailed {
        operation: &'static str,
        code: Option<i32>,
        message: String,
    },
    /// 无法启动系统命令（例如 `netsh` 不在预期位置）。
    #[error("无法启动{operation}所需命令：{message}")]
    SpawnFailed {
        operation: &'static str,
        message: String,
    },
}

/// 已安装（或 dry-run 校验通过）的路由句柄。
///
/// `Drop` 会做最后一次撤销尝试；失败只写 stderr，不 panic。需要确认撤销结果的
/// 调用方应显式调用 [`RouteHandle::remove`]（幂等，可重复调用）或使用
/// [`RouteGuard::release`]。
#[derive(Debug)]
pub struct RouteHandle {
    spec: RouteSpec,
    /// 是否真的下发了系统调用；`dry_run` 构造的句柄为 `false`。
    applied: bool,
    removed: bool,
}

impl RouteHandle {
    /// 构造句柄。仅 `route` 模块内部使用。
    fn new(spec: RouteSpec, applied: bool) -> Self {
        Self {
            spec,
            applied,
            removed: false,
        }
    }

    /// 本句柄对应的安装参数。
    #[must_use]
    pub fn spec(&self) -> &RouteSpec {
        &self.spec
    }

    /// 是否已经撤销（显式撤销成功或 dry-run 句柄撤销后为 `true`）。
    #[must_use]
    pub fn is_removed(&self) -> bool {
        self.removed
    }

    /// 是否是未触碰系统状态的 dry-run 句柄。
    #[must_use]
    pub fn is_simulated(&self) -> bool {
        !self.applied
    }

    /// 撤销路由。**幂等**：重复调用直接返回 `Ok(())`；底层已不存在时也按成功
    /// 处理（`netsh` 的「找不到」被归类为已撤销）。
    pub fn remove(&mut self) -> Result<(), RouteError> {
        if self.removed {
            return Ok(());
        }
        if self.applied {
            platform::revoke(&self.spec)?;
        }
        self.removed = true;
        Ok(())
    }
}

impl Drop for RouteHandle {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            log_remove_failure(&error);
        }
    }
}

/// 路由守卫：`Drop` 时撤销，撤销失败只记录、不 panic。
///
/// 需要在退出前确认撤销结果时用 [`RouteGuard::release`]，它把撤销错误交还给
/// 调用方。
#[derive(Debug)]
pub struct RouteGuard {
    handle: RouteHandle,
}

impl RouteGuard {
    /// 接管一个已安装（或 dry-run）的句柄。
    #[must_use]
    pub fn new(handle: RouteHandle) -> Self {
        Self { handle }
    }

    /// 被守卫的安装参数。
    #[must_use]
    pub fn spec(&self) -> &RouteSpec {
        self.handle.spec()
    }

    /// 显式撤销并返回结果。成功后再 `Drop` 不会重复触碰系统。
    pub fn release(mut self) -> Result<(), RouteError> {
        self.handle.remove()
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        // `RouteHandle::remove` 已保证幂等；这里失败只记录。
        if let Err(error) = self.handle.remove() {
            log_remove_failure(&error);
        }
    }
}

/// 路由表的平台无关入口。
#[derive(Debug, Default, Clone, Copy)]
pub struct RouteManager;

impl RouteManager {
    /// 创建管理器。不读取系统路由表，也不申请任何权限。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 校验参数并安装路由。
    ///
    /// 参数非法时在触碰系统状态之前返回对应错误；非 Windows 平台上的合法参数
    /// 返回 [`RouteError::Unsupported`]（桩不伪装成功）。
    pub fn install(&self, spec: RouteSpec) -> Result<RouteHandle, RouteError> {
        spec.validate()?;
        platform::apply(&spec)?;
        Ok(RouteHandle::new(spec, true))
    }

    /// 只校验参数、不下发系统调用，返回一个 `is_simulated() == true` 的句柄。
    ///
    /// 用于配置预检与契约测试；**不是**安装成功，也不跳过任何校验。调用方若
    /// 需要真实生效，必须走 [`RouteManager::install`]。
    pub fn dry_run(&self, spec: RouteSpec) -> Result<RouteHandle, RouteError> {
        spec.validate()?;
        Ok(RouteHandle::new(spec, false))
    }
}

/// `Drop` 中撤销失败的唯一处理：尽力写 stderr，绝不 panic。
fn log_remove_failure(error: &RouteError) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "lengsuo-tun: 路由撤销失败（仅记录）：{error}");
}

#[cfg(not(windows))]
mod stub;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
use stub as platform;
#[cfg(windows)]
use windows as platform;

#[cfg(test)]
mod tests;
