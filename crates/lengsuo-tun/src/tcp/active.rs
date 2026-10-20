//! 主动打开（主动 `connect`）状态机：纯内存、无 IO、不建 socket。
//!
//! 与 [`crate::tcp::state`] 的被动打开内核互为镜像：`state.rs` 走 `Listen →
//! SynReceived → Established`（被动方向），本模块走 `SynSent → SynReceived →
//! Established`（主动方向），两者共用 [`crate::tcp::segment`] 的段解析与构造原语。
//!
//! 主动打开的两条路径（RFC 9293 §3.5 / §3.6）：
//! - **常规**：发 SYN → 收 SYN+ACK（**确认号必须等于 ISN+1**，否则 fail-closed 回
//!   RST 并失败）→ 发 ACK → `Established`。
//! - **同时打开**：发 SYN → 收**裸 SYN**（对端也在主动打开）→ 回 SYN+ACK →
//!   `SynReceived` → 收 ACK → `Established`。
//!
//! 重传：未收到 SYN-ACK 时按 RTO 退避重传 SYN；达到 `max_retries` 上限后
//! **fail-closed 报错并释放连接**，绝不无限重传。
//!
//! 初始序号由 `iss_seed` 确定性推导：**不是密码学随机**，只为让用例可复现；生产部署
//! 必须由上层换用不可预测的 ISN（RFC 9293 §3.4.1 的防伪造要求不在本模块范围内）。
//!
//! 子模块分工：[`types`] 放类型定义，`option` 放 MSS 选项原语，`connect` 放状态机
//! 骨架与三条入口，`handshake` 放各状态的入向处理，`access` 放只读访问器。
//! 有意不实现的项见文件末尾「偏离清单」。

pub mod access;
pub mod connect;
pub mod handshake;
pub mod option;
pub mod types;

pub use connect::ActiveConnection;
pub use option::{mss_option, parse_mss_option, MSS_OPTION_KIND, MSS_OPTION_LEN};
pub use types::{ActiveConfig, ActiveError, ActiveOutcome, ActiveState, OutboundSegment};

// ---- 与 RFC 9293 / Linux 的有意差异（逐条列出）----
//
// 1. 重传算法是**固定退避的 SYN 重传**（RTO 每次翻倍，上限 `max_rto_ms`），没有
//    Linux 的 RTT 估计（`tcp_rto_min`/`SRTT`）、没有 Karn 算法、没有「RTO 随拥塞
//    窗口调整」，也不重传数据段：只重传握手用的 SYN。
// 2. 只在 `SynSent` 计时；握手完成后重传定时器被撤销，超时回收由上层负责。
// 3. 不做 TIME-WAIT：`close()` 发 FIN 后不进入 FIN-WAIT/TIME-WAIT 状态机。
// 4. 不做拥塞控制与慢启动：`send()` 直接按生效 MSS 切段发出，无 cwnd/ssthresh。
// 5. 不实现窗口缩放（RFC 7323）与 SACK（RFC 2018）：窗口恒为 16 位原始值。
// 6. 入向数据只支持**严格按序**：乱序段按 `OutOfWindow` 丢弃，不做重排缓存。
// 7. 纯 ACK 不回 ACK：避免 ACK 乒乓，也就不实现延迟 ACK 合并（RFC 9293 §3.8.4）。
// 8. ISN 非密码学随机（见模块头说明），生产部署须由上层注入不可预测的 ISN。
// 9. 不与真实网卡交互：本模块只产出段字节与状态，不打开设备、不读写 socket。
