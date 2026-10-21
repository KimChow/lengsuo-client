//! Trojan **重放**异常矩阵（ALL-1 审计 §3 缺格）——参考行为复核 + 本仓行为取证。
//!
//! 本卡不实现重放防护。参考基线 Xray v26.3.27（commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）的 trojan 是**无状态**协议：
//! 请求头只有「密码哈希 + CRLF + 命令 + 目标地址 + CRLF」，**没有任何一次性字段**
//! （无 nonce、无时间戳、无会话标识、无序号），服务端也没有重放缓存。因此
//! 「参考不防护重放」是参考自身的设计选择，不是实现缺陷。
//!
//! 本文件把三件事拆开、各自带独立观测面：
//!
//! 1. **参考是否有一次性字段**（`reference_cases.rs`）：实跑参考客户端，捕获它
//!    写出的请求头原始字节，断言**两次独立会话的头逐字节相同** ⇒ 头部里没有
//!    nonce/时间戳/会话标识 ⇒ 同一段字节天然可重放。
//! 2. **参考是否拒绝重放**（`reference_cases.rs`）：实跑参考服务端，把同一段
//!    头在新连接上重放，断言它**被当作新请求接受**（业务目标被再次连接）。
//! 3. **本仓是否与参考一致**（`local_cases.rs`）：本仓服务端在同样输入下的
//!    真实行为，逐条断言「当前真实行为」而不是「希望的行为」。
//!
//! 判定纪律：
//! - 拒绝必须有独立观测面（业务目标 accept 计数 / 对端主动结束连接），
//!   **不把「我方读超时」当拒绝**。
//! - 断言写的是**实测行为**；若与参考不同，在本文件与
//!   `docs/trojan-replay.md` 偏离清单里如实记为差异。
//! - 只用回环地址、临时端口与假凭据；不打印密码、哈希或载荷内容。
//! - 每个异步读写都带超时；`read_to_end` 之前先关闭写端。

#[path = "replay_matrix/capture.rs"]
mod capture;
#[path = "replay_matrix/harness.rs"]
mod harness;
#[path = "replay_matrix/local_cases.rs"]
mod local_cases;
#[path = "replay_matrix/reference_cases.rs"]
mod reference_cases;
#[path = "replay_matrix/reference_cases_more.rs"]
mod reference_cases_more;
#[path = "replay_matrix/sha224.rs"]
mod sha224;
mod support;
