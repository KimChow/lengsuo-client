//! VLESS 异常矩阵补缺：**超时**（timeout）与**清理**（cleanup）两格。
//!
//! 背景：`docs/audit-all1.md` §3 的异常路径矩阵里，VLESS 的「超时」是 △
//! （只证明了「对端沉默时不会永久挂住」，没有证明「超时窗口到达后连接被
//! 明确判为超时失败」），「清理」是 ❌（没有任何连接资源回收断言）。
//! 本文件把这两格补成**具名用例 + 明确断言**的证据。
//!
//! 覆盖面：
//! - **超时**（`exception_matrix/timeout.rs`）：协议层握手对端沉默（客户端
//!   方向 + 服务端方向）、REALITY 传输层握手对端沉默、响应头不匹配判协议
//!   错、响应头截断判 I/O 错、超时后仍可用；
//! - **清理**（`exception_matrix/cleanup/`）：正常收尾后的流级回收、对端
//!   异常断开（RST）后的回收、Mux 会话表回收、Mux 承载连接读任务结束。
//!
//! **口径**：本文件全部是**本仓 Rust↔Rust 回环**与**协议层故障注入**，
//! **没有**做参考侧（Xray）取证；不得把它当作「与参考互通」的证据。
//!
//! 硬约束：只用回环地址、临时端口与运行时生成的假凭据；每个网络操作都有
//! 截止时间；日志与断言文本不出现任何密钥或明文口令。

mod support;

#[path = "exception_matrix/cleanup/mod.rs"]
mod cleanup;
#[path = "exception_matrix/reality_fixture.rs"]
mod reality_fixture;
#[path = "exception_matrix/timeout.rs"]
mod timeout;

use std::time::Duration;

use lengsuo_vless::header::{Command, Request};
use ss_core::target::TargetAddr;

/// 整条用例的截止时间（最外层兜底；用例内任何挂起都会在这里失败）。
pub const DEADLINE: Duration = Duration::from_secs(30);
/// 单次网络操作的观察上限（复用既有夹具 `tests/support/mod.rs` 的常量）。
pub const WAIT: Duration = support::WAIT;
/// 假凭据（16 字节；复用既有夹具的常量，不输出到任何日志）。
pub const KEY: [u8; 16] = support::KEY;

/// 一条普通的 VLESS TCP 请求（目标为回环地址，不会真的被连接）。
pub fn request() -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], 9),
    }
}
