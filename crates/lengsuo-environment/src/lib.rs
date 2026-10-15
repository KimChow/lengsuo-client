//! 浏览器环境到出口设备的路由核心（纯内存、纯 Rust，不使用 unsafe）。
//!
//! 职责边界：
//! - 只维护「环境身份 -> 出口设备 + 代次(epoch)」的映射与设备在线状态。
//! - 域名不参与身份判定：[`Router::resolve`] 的入参只有 [`EnvironmentId`]，
//!   域名分流属于上层策略，不属于本 crate 的权威状态。
//! - 不实现平台 TUN，不读取系统进程信息，不接触真实设备或生产配置。
//! - 设备在线状态由调用方（出口运行时）显式上报，默认一律视为离线。
//!
//! 一致性约定（由 `tests/router.rs` 与 `src/router.rs` 单元测试实测覆盖）：
//! - 每次成功 `bind` 都消耗全局严格递增的 epoch；计数器溢出时拒绝并保持原状态。
//! - `remove` 不回收、不复用任何历史 epoch。
//! - 设备离线时其在途绑定全部失效，重新上线不会恢复旧 lease，必须显式重绑。
//! - 认证/解析失败一律 fail-closed（返回 `Err`），不做静默回退。

#![forbid(unsafe_code)]

mod router;

pub use router::{Binding, DeviceId, EnvironmentId, Lease, Router, RouterError};
