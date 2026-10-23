//! TUN 生命周期接线：把「设备开启 → 按序安装路由 → 运行 → 逆序撤销路由 →
//! 设备关闭」串成一个对象，统一回滚与 `Drop` 兜底语义。
//!
//! [`crate::device`] 与 [`crate::route`] 各自是独立原语：前者管适配器与会话，
//! 后者管系统路由句柄，此前没有任何对象把二者对齐到同一生命周期。本模块补上
//! 这一薄层，不重写任何平台实现：
//!
//! - [`DeviceOps`] / [`RouteOps`]：最小门面，只抽象 `open`/`close` 与
//!   `install`/`revoke` 语义；真实路由侧直接复用 [`RouteManager`]。
//! - [`TunLifecycle`]：安装顺序 = `specs` 声明顺序；任何一步失败都先把已装
//!   路由逆序撤销（逐条失败继续）、再关设备，绝不留半成品。
//! - 显式 [`TunLifecycle::teardown`] 把失败清单完整交还调用方；未显式收尾时
//!   `Drop` 以相同顺序尽力收尾，失败只写 stderr、绝不 panic（照
//!   `route.rs` 的 `log_remove_failure` 风格）。
//!
//! 边界：本模块不接线到任何二进制入口；非 Windows 平台上
//! [`RouteManager::install`] 依旧返回 [`RouteError::Unsupported`]，本层原样
//! 上抛，不伪装成功。

use crate::route::{RouteError, RouteHandle, RouteManager, RouteSpec};

/// 生命周期各阶段的类型化错误。回滚/收尾阶段逐项收集失败，不因单项失败提前返回。
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    /// 设备开启失败。此时未安装任何路由，也不会调用 close（设备没有开成）。
    #[error("设备开启失败：{detail}")]
    DeviceOpen {
        /// 设备侧给出的失败详情。
        detail: String,
    },
    /// 第 `index` 条路由安装失败。`rollback_failures` 记录回滚阶段自身失败的
    /// 条目（带 `revoke#k:` / `close:` 来源前缀）；回滚失败不掩盖安装错误。
    #[error("第 {index} 条路由安装失败：{source}（回滚失败：{rollback_failures:?}）")]
    RouteInstall {
        /// 失败那条在 `specs` 中的下标（从 0 计）。
        index: usize,
        /// 安装失败的原始路由错误。
        source: RouteError,
        /// 回滚阶段自身失败的条目；空表示回滚完全成功。
        rollback_failures: Vec<String>,
    },
    /// 单条路由撤销失败。收尾汇总时以其 `Display` 文本进入
    /// [`LifecycleError::Teardown`] 的 `route_failures`。
    #[error("第 {index} 条路由撤销失败：{source}")]
    RouteRevoke {
        /// 被撤销那条在 `specs` 中的下标（从 0 计）。
        index: usize,
        /// 撤销失败的原始路由错误。
        source: RouteError,
    },
    /// 设备关闭失败（单点语义，供只关设备的调用方使用）。
    #[error("设备关闭失败：{detail}")]
    DeviceClose {
        /// 设备侧给出的失败详情。
        detail: String,
    },
    /// 收尾（teardown / Drop 路径）未完全成功：路由失败逐条列出，设备失败可选。
    /// 流程一定走完（先撤销全部路由、再关设备），失败只汇总、不中断。
    #[error("收尾未完全成功：路由撤销失败 {route_failures:?}；设备关闭失败 {device:?}")]
    Teardown {
        /// 逆序撤销阶段失败的条目（`LifecycleError::RouteRevoke` 的 `Display` 文本）。
        route_failures: Vec<String>,
        /// 设备关闭失败详情；`None` 表示关闭成功。
        device: Option<String>,
    },
}

/// 设备侧最小门面：生命周期只关心「能开、能关」，不关心平台细节。
///
/// 设备创建（如 `Device::open(library, config)`）仍由各平台模块各自完成；
/// 实现本 trait 的对象应当是**已经创建好**的设备。
pub trait DeviceOps {
    /// 打开/激活设备。
    fn open(&mut self) -> Result<(), String>;
    /// 关闭设备。
    fn close(&mut self) -> Result<(), String>;
}

/// 路由侧最小门面：安装与撤销必须经由此层转发到 `route` 原语，不得另写实现。
pub trait RouteOps {
    /// 安装一条路由并返回句柄。句柄只能来自 `route` 层（`install`/`dry_run`）。
    fn install(&mut self, spec: &RouteSpec) -> Result<RouteHandle, RouteError>;
    /// 撤销一条先前安装的路由。
    fn revoke(&mut self, handle: RouteHandle) -> Result<(), RouteError>;
}

/// 设备 + 路由的联合生命周期。顺序契约（集成测试逐条锁定）：
///
/// 1. [`start`](Self::start) **先**开设备；开失败 ⇒ 不装任何路由、也不关设备。
/// 2. 按 `specs` 声明顺序安装；第 `k` 条失败 ⇒ 对已装的 `0..k` 条**逆序**撤销
///    （逐条失败继续），最后关设备，返回 [`LifecycleError::RouteInstall`]。
/// 3. [`teardown`](Self::teardown) 逆序撤销全部已装路由后关设备；任一失败 ⇒
///    [`LifecycleError::Teardown`]，但流程走完，不提前退出。
/// 4. 未显式收尾时 `Drop` 以相同顺序尽力收尾：忽略全部错误、绝不 panic。
/// 5. 显式 teardown 之后 `Drop` 不做任何事（幂等，由 `torn_down` 标记保证）。
#[derive(Debug)]
pub struct TunLifecycle<D: DeviceOps, R: RouteOps> {
    device: D,
    routes: R,
    handles: Vec<RouteHandle>,
    torn_down: bool,
}

impl<D: DeviceOps, R: RouteOps> TunLifecycle<D, R> {
    /// 开设备、按声明顺序安装全部路由；任何一步失败都回滚到「设备已关」的
    /// 干净状态后返回错误，绝不返回半成品生命周期。
    pub fn start(device: D, routes: R, specs: Vec<RouteSpec>) -> Result<Self, LifecycleError> {
        let mut device = device;
        let mut routes = routes;
        device
            .open()
            .map_err(|detail| LifecycleError::DeviceOpen { detail })?;
        let mut handles = Vec::with_capacity(specs.len());
        for (index, spec) in specs.iter().enumerate() {
            match routes.install(spec) {
                Ok(handle) => handles.push(handle),
                Err(source) => {
                    let rollback_failures =
                        rollback_installed(&mut routes, &mut handles, &mut device);
                    return Err(LifecycleError::RouteInstall {
                        index,
                        source,
                        rollback_failures,
                    });
                }
            }
        }
        Ok(Self {
            device,
            routes,
            handles,
            torn_down: false,
        })
    }

    /// 当前已安装（尚未撤销）的路由条数；`start` 成功后等于 `specs.len()`。
    #[must_use]
    pub fn installed(&self) -> usize {
        self.handles.len()
    }

    /// 只读访问底层设备（运行期读取状态用）。
    #[must_use]
    pub fn device(&self) -> &D {
        &self.device
    }

    /// 可变访问底层设备（运行期读写状态用；不得用它绕过本层另装路由）。
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// 显式收尾：逆序撤销全部已装路由，然后关设备。失败清单经
    /// [`LifecycleError::Teardown`] 交还调用方；无论成败都标记已收尾，之后的
    /// `Drop` 不会二次撤销/关闭。
    pub fn teardown(mut self) -> Result<(), LifecycleError> {
        let outcome = self.shutdown();
        self.torn_down = true;
        outcome
    }

    /// 收尾的主体：撤销全部路由（失败继续收集）→ 关设备 → 汇总结果。
    fn shutdown(&mut self) -> Result<(), LifecycleError> {
        let mut route_failures = Vec::new();
        while let Some(handle) = self.handles.pop() {
            let index = self.handles.len();
            if let Err(source) = self.routes.revoke(handle) {
                route_failures.push(LifecycleError::RouteRevoke { index, source }.to_string());
            }
        }
        let device = self.device.close().err();
        if route_failures.is_empty() && device.is_none() {
            Ok(())
        } else {
            Err(LifecycleError::Teardown {
                route_failures,
                device,
            })
        }
    }
}

impl<D: DeviceOps, R: RouteOps> Drop for TunLifecycle<D, R> {
    fn drop(&mut self) {
        if self.torn_down {
            return;
        }
        if let Err(error) = self.shutdown() {
            log_teardown_failure(&error);
        }
    }
}

/// `start` 失败后的回滚：已装路由逆序撤销（失败逐条收集、继续下一条），
/// 最后关设备（失败同样收集，消息带 `close:` 前缀）。绝不 panic、绝不提前返回。
fn rollback_installed<R: RouteOps, D: DeviceOps>(
    routes: &mut R,
    handles: &mut Vec<RouteHandle>,
    device: &mut D,
) -> Vec<String> {
    let mut failures = Vec::new();
    while let Some(handle) = handles.pop() {
        let index = handles.len();
        if let Err(source) = routes.revoke(handle) {
            failures.push(format!("revoke#{index}: {source}"));
        }
    }
    if let Err(detail) = device.close() {
        failures.push(format!("close: {detail}"));
    }
    failures
}

/// `Drop` 中收尾失败的唯一处理：尽力写 stderr，绝不 panic。
fn log_teardown_failure(error: &LifecycleError) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "lengsuo-tun: 生命周期收尾失败（仅记录）：{error}");
}

/// 真实路由适配器：转发到 `route` 原语。非 Windows 平台
/// `RouteManager::install` 返回 [`RouteError::Unsupported`]，此处原样上抛。
impl RouteOps for RouteManager {
    fn install(&mut self, spec: &RouteSpec) -> Result<RouteHandle, RouteError> {
        // 必须 UFCS：方法语法会解析回本 trait 方法（接收者精确匹配 &mut Self）。
        RouteManager::install(self, *spec)
    }

    fn revoke(&mut self, handle: RouteHandle) -> Result<(), RouteError> {
        let mut handle = handle;
        handle.remove()
    }
}
