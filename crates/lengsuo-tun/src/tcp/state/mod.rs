//! 单连接 TCP 状态机内核：纯内存、无 IO、不建 socket。
//!
//! 只实现 RFC 9293 的**被动打开**路径：`Listen` 收 SYN → 回 SYN-ACK → 收 ACK 进
//! `Established`。调用方把已校验的 [`crate::tcp::segment::Segment`] 依次喂给
//! [`Connection::advance`]，并按返回的 [`Outcome`] 发包；本模块不构造 IP 头部、
//! 不写网卡。序号比较一律 32 位回绕安全（[`seq_lt`]/[`seq_ge`]，即 RFC 9293 §3.4 的
//! `SEG.LT` 系列）。初始序号来自确定性发生器 [`Connection::set_iss_seed`]：**不是密码学
//! 随机**，只为让用例可复现；生产部署必须由上层换用不可预测的 ISN（RFC 9293 §3.4.1 的
//! 防伪造要求不在本模块范围内）。有意不实现的项见文件末尾「偏离清单」。

mod config;
mod connection;
mod seq;

#[cfg(test)]
mod tests;

pub use config::Config;
pub use connection::{Connection, DiscardReason, Outcome, SendSegment, State};
pub use seq::{seq_ge, seq_in, seq_lt};

// ---- 与 RFC 9293 的有意差异（本卡范围内的取舍，逐条列出）----
//
// 1. 不做半连接队列分级：`SynReceived` 即一个真实连接，没有 SYN 队列/accept 队列。
// 2. 不做 TIME-WAIT：`LastAck` 收到最终 ACK 后直接 `Closed`，不保留 2MSL 静默期。
// 3. 不做延迟 ACK 合并：每个需要确认的段立即回一个 ACK，不等待第二个段或 200ms。
// 4. 不做 challenge ACK，也不实现 RFC 5961 的 RST 速率限制：RST 一律立即生效。
// 5. 不实现窗口缩放（RFC 7323）：窗口字段恒为 16 位原始值，无移位。
// 6. 不实现 SACK（RFC 2018）：乱序只做单段重排，无选择确认。
// 7. 不实现拥塞控制与慢启动：`snd_nxt` 只随发送推进，无 cwnd/ssthresh/RTT 估计。
// 8. 主动关闭不引入 FIN-WAIT-1/FIN-WAIT-2 分解：`close()` 统一停到 `LastAck`；
//    若对端尚未 FIN，仍由上层继续喂入对端 FIN 后才可能被最终 ACK 收尾。
// 9. 不做重传与超时管理：本内核不持有定时器（故 `clock` 入参在本卡内未被消费），
//    重传由上层按 `Outcome` 自行决定。
