//! 非 Windows 的路由桩：只在 `#[cfg(not(windows))]` 下编译。
//!
//! 与 `device/stub.rs` 同一范式：签名与 `route/windows.rs` 对应，安装/撤销一律返回
//! [`RouteError::Unsupported`]，不伪装成功。参数校验已由 `route.rs` 在任何平台
//! 统一完成，因此桩不会改变 fail-closed 的判定顺序。

use super::RouteError;

/// 桩平台不执行任何系统调用。
pub(super) fn apply(_spec: &super::RouteSpec) -> Result<(), RouteError> {
    Err(unsupported())
}

/// 桩平台不执行任何系统调用。
pub(super) fn revoke(_spec: &super::RouteSpec) -> Result<(), RouteError> {
    Err(unsupported())
}

/// 统一的桩错误：带当前平台名，便于日志区分平台门控与真实失败。
fn unsupported() -> RouteError {
    RouteError::Unsupported {
        os: std::env::consts::OS,
    }
}
