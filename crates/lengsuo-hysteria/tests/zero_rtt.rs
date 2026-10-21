//! 0-RTT（quinn `into_0rtt`）纯逻辑用例 + Xray 参考实跑。
//!
//! 默认套件（非 ignore）只测逻辑面：配置开关、三态映射、非幂等 fail-closed、
//! 会话缓存容量/LRU/未命中、以及「服务端拒绝时回退 1-RTT 且只交付一次」的
//! 假连接桩。`xray_0rtt_second_connection` 是 `#[ignore]`，必须用
//! `LENGSUO_XRAY=... -- --ignored` 实跑。
//!
//! 安全：0-RTT 数据可被重放，因此只有幂等操作允许出现在早数据路径；
//! 拒绝路径必须由调用方显式观测并经 `fallback` 重放，绝不静默当 1-RTT。

// 用例按主题拆到 `tests/zero_rtt/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod support;

use lengsuo_hysteria::quic::{
    configure_tls, run_early, EarlyDataConfig, EarlyDataError, EarlyError, MemorySessionCache,
    OperationKind, SessionCache, ZeroRttOutcome, ZeroRttRejected, ZeroRttStatus,
};

// 参考实跑子模块：原为**内联** `mod xray { ... }`，现搬到 `zero_rtt/xray.rs`
// （模块名仍是 `xray` ⇒ 用例全限定名 `xray::xray_0rtt_second_connection` 不变）。
// crate root 是 `tests/zero_rtt.rs`，裸 `mod xray;` 会去找 `tests/xray.rs`，
// 故用 `#[path]` 显式指到子目录。
#[path = "zero_rtt/xray.rs"]
mod xray;

include!("zero_rtt/config.rs");
include!("zero_rtt/outcome.rs");
include!("zero_rtt/early.rs");
include!("zero_rtt/cache.rs");
include!("zero_rtt/replay.rs");
