//! TUN 运行时入口的端到端用例。
//!
//! # 性质（重要，勿误读）
//!
//! 本套件**不接真实 TUN 设备、不建真实 socket、不与任何外部实现互通**：
//! 设备是内存替身，出口运行时是内存替身。因此它证明的是**入口的接线语义**
//! （配置校验 → 读循环 → 校验 → 归因 → 路由/出口决策 → 写回），**不是**
//! 「TUN 已实机可用」的证据。
//!
//! # 被测代码就是生产代码
//!
//! 本文件用 `#[path]` 直接把 `src/bin/lengsuo-tun-runtime.rs` 包含进来，因此**跑的就是
//! bin crate root 那份源码**，不存在「测试替身另写一份逻辑」的问题。
//!
//! # 分组
//!
//! - [`config`]：配置校验与命令行解析。
//! - [`device`]：设备层与「平台不支持必须显式报错」。
//! - [`runtime`]：事件循环、完整闭环与 fail-closed 语义。
//! - [`entry`]：进程入口与静态接线的自洽性。
//! - [`linux_device`]：真实 TUN 设备（`#[ignore]`，需 `CAP_NET_ADMIN`）。
//! - [`support`]：内存替身与报文构造器。

// The included file is a bin crate root: it has its own `main` behind
// `#[cfg(not(test))]`, so the test harness entry point stays unique.
//
// `unused_imports` 在这里必须放行：crate root 的 `pub use` 清单是**bin 目标的对外
// 契约**（本卡要求不得缩水），但在测试 crate 里这些重导出并非每个都被用到。
#[path = "../src/bin/lengsuo-tun-runtime.rs"]
#[allow(dead_code, unused_imports)]
mod runtime_entry;

#[path = "runtime_entry/config.rs"]
mod config;
#[path = "runtime_entry/device.rs"]
mod device;
#[path = "runtime_entry/entry.rs"]
mod entry;
#[path = "runtime_entry/linux_device.rs"]
#[cfg(target_os = "linux")]
mod linux_device;
#[path = "runtime_entry/runtime.rs"]
mod runtime;
#[path = "runtime_entry/support.rs"]
pub mod support;

use lengsuo_tun::egress::DenyReason;
use lengsuo_tun::tcp::segment::Flags;

use support::tcp_packet;

/// 拒绝原因走既有枚举，不靠自由文本：本卡不新增「第三种直连」结果。
#[test]
fn denial_reasons_use_the_existing_enumeration() {
    // 出口层已有的拒绝原因枚举在本卡复用，未新增「未命中就直连」。
    assert_eq!(DenyReason::NoRoute.as_str(), "no-route");
    assert_eq!(DenyReason::NoAttribution.as_str(), "no-attribution");
}

/// 入站报文必须能通过 `checksum::verify`——这是入口 ① 步的准入口径。
///
/// 本组用例构造的报文若过不了校验，后续断言（写回、交付）都会变成假绿；这里
/// 单独钉住这个前提。
#[test]
fn inbound_packets_pass_the_library_checksum_verifier() {
    let packet = tcp_packet(1000, 0, Flags::SYN, &[]);
    let info = lengsuo_tun::checksum::verify(&packet).expect("构造的报文应通过校验");
    assert_eq!(info.source, std::net::IpAddr::V4(support::REMOTE));
    assert_eq!(info.destination, std::net::IpAddr::V4(support::LOCAL));
    assert_eq!(info.source_port, support::REMOTE_PORT);
    assert_eq!(info.destination_port, support::LOCAL_PORT);
}
