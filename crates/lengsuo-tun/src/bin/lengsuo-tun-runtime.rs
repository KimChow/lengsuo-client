//! TUN 运行时入口：把本 crate 的库能力接成**可运行的进程入口**。
//!
//! 本文件是 `[[bin]]` 的 crate root（建议段落见 `docs/tun-runtime-entry.md`）：
//! 「设备 → 报文校验 → 归因 → 路由/出口决策 → 用户态 TCP 栈 → 写回设备」整链。
//!
//! # 分层
//!
//! - [`config`]：配置形态、校验与命令行解析（**先校验再碰平台**）。
//! - [`device`]：设备抽象、类型化错误、非 Linux 平台的显式不支持桩。
//! - [`linux`]：Linux 上的真实 TUN 设备 —— **本卡唯一含 `unsafe` 的模块**。
//! - [`runtime`]：事件循环、统计与可观测点。
//! - [`entry`]：进程入口与演示接线。
//!
//! # 复用既有模块（不重写）
//!
//! 报文校验 `checksum::verify`、收包抽象 `ingress::PacketSource`、归因
//! `ingress::Classifier`、出口决策 `egress::EgressSelector`、出接口路由表
//! `tcp::connector::RouteTable`、前缀校验 `route::RouteDestination`、用户态 TCP 栈
//! `tcp::listener::TcpListener` —— 全部复用，本 crate root 不重写。
//!
//! # unsafe 边界
//!
//! Linux 的 TUN 设备必须经 `/dev/net/tun` 的 `TUNSETIFF` ioctl 挂载，标准库没有
//! 该 API，因此**本 crate root 是本卡唯一含 `unsafe` 的地方**：unsafe 全部收敛在
//! [`linux`] 模块内的裸 FFI 包装里，对外的 `TunDevice` / `Runtime` / `run_entry`
//! 都是安全函数。库侧 `src/lib.rs` 保持 `#![forbid(unsafe_code)]`；`forbid` 不能被
//! `#[allow]` 覆盖，所以本文件刻意**不进库**，而是以 bin crate root 的身份持有
//! 这段 unsafe。
//!
//! # 平台
//!
//! Linux 上是真实 TUN 设备；其它平台 `open_device` 显式返回
//! `DeviceError::Unsupported`，**不返回空设备**。

#[path = "runtime_entry/config.rs"]
mod config;
#[path = "runtime_entry/device.rs"]
mod device;
#[path = "runtime_entry/entry.rs"]
mod entry;
#[path = "runtime_entry/linux.rs"]
#[cfg(target_os = "linux")]
mod linux;
#[path = "runtime_entry/linux_ffi.rs"]
#[cfg(target_os = "linux")]
mod linux_ffi;
#[path = "runtime_entry/runtime.rs"]
mod runtime;

pub use config::{
    parse_args, ConfigError, RawConfig, RouteRule, RuntimeConfig, DEFAULT_READ_TIMEOUT_MS,
    DEFAULT_SESSION_CAPACITY, DEFAULT_SESSION_TTL_MS, MAX_DEVICE_NAME_LEN, MAX_MTU, MIN_MTU,
};
pub use device::{
    current_platform, open_device, DeviceError, PlatformDevice, TunDevice, UnsupportedDevice,
};
pub use entry::{
    main_with_args, run_entry, run_with_config, DemoOutbound, EntryError, EntryOutcome,
    StaticAuthority, StaticClassifier, StaticWiring,
};
pub use runtime::{Limits, OutboundExchange, RunOutcome, Runtime, RuntimeStats, Step, StopReason};

/// 进程主函数。
///
/// 只在**真正的 bin 目标**里存在：`tests/runtime_entry/` 用 `#[path]` 把本文件
/// 直接包含进测试 crate，那里有测试 harness 自己的入口，不需要（也不允许）第二个
/// `main`。
#[cfg(not(test))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(main_with_args(args));
}
