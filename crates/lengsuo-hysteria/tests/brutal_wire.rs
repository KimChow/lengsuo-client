//! Brutal 拥塞控制**接线实跑取证**（本仓客户端 ↔ 本仓服务端闭环）。
//!
//! 负例随 `cargo test` 默认跑；带 `#[ignore]` 的是实跑吞吐用例，需
//! `--ignored --nocapture`。
//!
//! # 测量口径（为什么不能只计 `write_all`）
//!
//! quinn 的 `SendStream::write` 只把数据交给**连接级发送缓冲**，真正的
//! QUIC 发送受两道闸门约束：拥塞窗口（`window()`）与 pacer（按
//! `window / RTT` 放行）。因此：
//!
//! - **写端**在配额耗尽前会很快返回（数据进了发送缓冲），**不能**用它
//!   计时 —— 必须等「对端确认收到全部字节」，才说明闭环真的走完；
//! - **回程**必须与上传**并发**排空：目标端在读满请求后才开始回灌，
//!   若先等上传结束再读，目标端的写缓冲会被回压，测出的就不再是
//!   Brutal 的速率。
//!
//! 判定口径（宽松区间 + 总超时，避免抖动假失败）：
//! - 上界：实测吞吐 ≤ 协商值 × 3；下界：≥ 协商值 / 8；
//! - 对照组：同一场景、`congestion` 为空（quinn 默认 CUBIC）时**必须**超出
//!   上界 —— 证明瓶颈确为注入的 Brutal，而非装置本身。
//!
//! 只走回环地址、系统分配端口、openssl 现场自签证书与假凭据。

// 用例按主题拆到 `tests/brutal_wire/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

mod support;

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lengsuo_congestion::brutal::ConfigError;
use lengsuo_congestion::Mode;
use lengsuo_hysteria::congestion::{
    client_rate, inject, parse_announce, parse_mode, server_send_rate, Bandwidth, CcHeader,
    CongestionConfig, CongestionError, CongestionMode,
};
use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig, ServerError};
use lengsuo_hysteria::quic::{ClientConfig, ConnectError, HysteriaClient};

const AUTH: &str = "lengsuo-brutal-wire";
/// 单个实跑场景的总预算（超时即失败）。
const BUDGET: Duration = Duration::from_secs(300);
/// 请求载荷：远大于 Brutal 窗口下的在途上限，保证流控不先行限制。
const REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// 目标端回灌量。
const RESPONSE_BYTES: usize = 64 * 1024;
/// 单次回程读取的等待上限。
const READ_LIMIT: Duration = Duration::from_secs(120);

include!("brutal_wire/harness.rs");
include!("brutal_wire/throughput.rs");
include!("brutal_wire/negatives.rs");
