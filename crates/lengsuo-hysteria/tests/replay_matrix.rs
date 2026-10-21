//! Hysteria 异常矩阵补缺：**重放格**（`docs/audit-all1.md` §3）。
//!
//! 审计原文：Hysteria 的「重放」格是 △ ——「仅 0-RTT
//! `accepted_early_data_is_not_replayed`」⇒ 只证明了 0-RTT 的早数据不被
//! 重放，**没有覆盖常规会话（非 0-RTT）的重放**。本卡补这一格。
//!
//! （半关闭 / 清理两格已由 `w4-hysteria-lifecycle` 覆盖，见
//! `tests/lifecycle.rs`；本卡**不重做**它们。）
//!
//! # 语义分层（本卡的核心）
//!
//! 「重放」在 Hysteria2 上有两个**层次**，行为完全不同，必须分开断言：
//!
//! | 层次 | 重放物 | 谁来挡 | 结论 |
//! |---|---|---|---|
//! | **传输层** | 抓到的 **QUIC 数据报** | QUIC 包号 + AEAD + 连接 ID | 重复包号被丢弃；换连接则连接 ID/密钥不匹配被丢弃 |
//! | **协议层** | 一段**应用层帧字节**（如 TCP 请求） | 无 | 帧格式里没有序号/随机数 ⇒ 被当成**新请求**处理 |
//!
//! 协议层的结论来自参考实现（固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`proxy/hysteria/protocol.go`：
//! TCPRequest = 地址长度 + 地址 + padding 长度 + padding，**没有序号/时间戳/
//! 随机数**）⇒ 参考实现**本身**也不提供常规会话的应用层防重放。
//!
//! # 用例分组（每个用例都有外层 `timeout(...)` 兜底）
//!
//! - `frame_level`：同会话内逐字节重放、跨会话重放；
//! - `packet_level`：QUIC 数据报级重放（抓包重放）、跨连接重放；
//! - `isolation`：重放**不得污染后续会话**；
//! - `zero_rtt`：0-RTT 既有判据**不回归**（语义等价于
//!   `tests/zero_rtt.rs` 的 `accepted_early_data_is_not_replayed`，
//!   但**本卡不改那个文件**，在本文件里独立复刻语义）；
//! - `xray_reference`：`#[ignore]`，用 `LENGSUO_XRAY` 指向的**参考 Xray**
//!   做真实互通（抓包 → 重放 → 观察参考服务端是否重复投递）。
//!
//! # 硬约束
//!
//! - 只用回环地址、临时端口、**运行时生成**的假口令；口令不进日志；
//! - 认证/解码失败必须 fail-closed；
//! - 异步读写一律套 `tokio::time::timeout`；
//! - `read_to_end` 前确保写端关闭（`finish()`）。
//!
//! 子目录模块（`tests/replay_matrix/`）：crate root 是 `tests/replay_matrix.rs`，
//! 裸 `mod xxx;` 会去找 `tests/xxx.rs`，故用 `#[path]` 显式指到子目录。
#[path = "replay_matrix/support.rs"]
mod support;

#[path = "replay_matrix/frame_level.rs"]
mod frame_level;
#[path = "replay_matrix/isolation.rs"]
mod isolation;
#[path = "replay_matrix/packet_level.rs"]
mod packet_level;
#[path = "replay_matrix/relay.rs"]
mod relay;
#[path = "replay_matrix/xray_reference.rs"]
mod xray_reference;
#[path = "replay_matrix/zero_rtt.rs"]
mod zero_rtt;
