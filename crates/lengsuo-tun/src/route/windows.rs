//! Windows 路由实现：`netsh interface ipv4/ipv6 ... route`。
//!
//! 只在 `#[cfg(windows)]` 下编译。平台无关的校验在 `route.rs` 完成，本文件只负责
//! 把已校验的参数拼接成 `netsh` 参数并分类退出结果。
//!
//! 选择 `netsh` 而非 `CreateIpForwardEntry2` 的理由：
//! 1. 本 crate `#![forbid(unsafe_code)]`，IP Helper API 必须经 FFI 声明或新增
//!    绑定 crate，而本卡禁止新增依赖；
//! 2. `std::process::Command` 不经过 shell，参数以数组直传，不存在的注入面；
//!    前缀由 [`RouteDestination::netsh_prefix`] 从已解析的 `IpAddr` 格式化，
//!    接口索引与 metric 都是已校验的纯数字。
//! 3. 代价：失败原因只能按退出码与 `netsh` 消息文本做启发式分类，无法拿到
//!    Win32 错误码。分类结果不改变 fail-closed 语义——无法识别的一律
//!    [`RouteError::CommandFailed`]，绝不当作成功。
//!
//! `store=active`：路由只进活动存储，不写入持久配置；进程异常退出后重启即恢复。

use super::{RouteDestination, RouteError, RouteSpec};
use std::path::PathBuf;
use std::process::Command;

/// 解析 `netsh.exe` 的绝对路径：只信 `%SystemRoot%\System32`，不沿 PATH 搜索。
///
/// 本层可能运行在提权进程里；Windows 的可执行搜索顺序包含当前目录，沿 PATH
/// 找 `netsh` 会把「当前目录投放同名 exe」变成提权面。`SystemRoot` 缺失或
/// `System32\netsh.exe` 不存在时按 [`RouteError::SpawnFailed`] fail-closed。
fn netsh_path(operation: &'static str) -> Result<PathBuf, RouteError> {
    let root = std::env::var_os("SystemRoot").ok_or_else(|| RouteError::SpawnFailed {
        operation,
        message: "环境变量 SystemRoot 未设置，拒绝沿 PATH 搜索 netsh".to_string(),
    })?;
    let path = PathBuf::from(root).join("System32").join("netsh.exe");
    if path.is_file() {
        Ok(path)
    } else {
        Err(RouteError::SpawnFailed {
            operation,
            message: format!("{} 不存在，拒绝沿 PATH 搜索 netsh", path.display()),
        })
    }
}

/// 执行一条 `netsh interface <family> <verb> route ...` 命令。
fn run_netsh(
    operation: &'static str,
    family: &'static str,
    arguments: &[String],
) -> Result<(), RouteError> {
    let program = netsh_path(operation)?;
    let output = Command::new(program)
        .arg("interface")
        .arg(family)
        .args(arguments)
        .output()
        .map_err(|error| RouteError::SpawnFailed {
            operation,
            message: error.to_string(),
        })?;
    if output.status.success() {
        return Ok(());
    }
    let message = combined_output(&output);
    Err(classify(operation, output.status.code(), message))
}

/// 合并 stdout/stderr；Windows 控制台代码页可能不是 UTF-8，用有损转换保留可读内容。
fn combined_output(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = format!("{} {}", stdout.trim(), stderr.trim());
    let trimmed = text.trim();
    if trimmed.is_empty() {
        "（netsh 无输出）".to_string()
    } else {
        trimmed.to_string()
    }
}

/// 按消息文本的常见多语言片段分类失败原因。
///
/// 这只是排障提示，**不参与放行判断**：任何非零退出都属于失败。
fn classify(operation: &'static str, code: Option<i32>, message: String) -> RouteError {
    // Win32 ERROR_ACCESS_DENIED = 5；有的系统把它直接作为 netsh 退出码。
    if code == Some(5) {
        return RouteError::PermissionDenied { operation, message };
    }
    let lowered = message.to_lowercase();
    const PERMISSION: [&str; 8] = [
        "access is denied",
        "requires elevation",
        "elevation required",
        "拒绝访问",
        "管理员",
        "提升",
        "zugriff verweigert",
        "erfordert",
    ];
    if PERMISSION.iter().any(|needle| lowered.contains(needle)) {
        return RouteError::PermissionDenied { operation, message };
    }
    RouteError::CommandFailed {
        operation,
        code,
        message,
    }
}

/// 安装一条路由。
pub(super) fn apply(spec: &RouteSpec) -> Result<(), RouteError> {
    let family = family_name(spec.destination);
    let arguments = vec![
        "add".to_string(),
        "route".to_string(),
        format!("prefix={}", spec.destination.netsh_prefix()),
        format!("interface={}", spec.interface_index),
        format!("metric={}", spec.metric),
        "store=active".to_string(),
    ];
    run_netsh("安装路由", family, &arguments)
}

/// 撤销一条路由。底层已不存在时按成功处理，使 [`super::RouteHandle::remove`] 幂等。
pub(super) fn revoke(spec: &RouteSpec) -> Result<(), RouteError> {
    let family = family_name(spec.destination);
    let arguments = vec![
        "delete".to_string(),
        "route".to_string(),
        format!("prefix={}", spec.destination.netsh_prefix()),
        format!("interface={}", spec.interface_index),
        "store=active".to_string(),
    ];
    match run_netsh("撤销路由", family, &arguments) {
        Ok(()) => Ok(()),
        Err(RouteError::CommandFailed { message, .. }) if already_absent(&message) => Ok(()),
        Err(error) => Err(error),
    }
}

/// 删除时报「找不到元素」即视为已撤销（幂等的另一半）。
fn already_absent(message: &str) -> bool {
    let lowered = message.to_lowercase();
    const ABSENT: [&str; 6] = [
        "not found",
        "element not found",
        "cannot find",
        "找不到",
        "未找到",
        "不存在",
    ];
    ABSENT.iter().any(|needle| lowered.contains(needle))
}

/// `netsh` 的协议族关键字。
fn family_name(destination: RouteDestination) -> &'static str {
    match destination {
        RouteDestination::V4 { .. } => "ipv4",
        RouteDestination::V6 { .. } => "ipv6",
    }
}
