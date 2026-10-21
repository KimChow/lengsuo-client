//! Trojan 服务端**完整异常矩阵**（非忽略）——每条都有明确判据与超时。
//!
//! 判定纪律：**不把“我方读操作超时”当“被拒绝”**。每条拒绝都要求
//! （a）对端在观察上限内**主动结束连接**（读到 `Ok(0)`/`Err`），且
//! （b）本仓服务端处理任务返回**可判别的错误变体**（不是 panic、不是挂起）。
//!
//! 覆盖面：
//! - 错密码（含“正确密码对照组”证明观测面有效）；
//! - 截断请求头的**每一部分**：哈希 / 哈希后 CRLF / 命令 / 地址（IPv4 各前缀）/
//!   尾 CRLF；
//! - 篡改 SHA224 摘要（首字节、末字节、全零）；
//! - 重放同一请求头（记录参考与实现行为）；
//! - 半关闭：客户端 `shutdown(Write)` 后仍读完响应；服务端关闭后客户端 EOF 不挂死；
//! - 超时与资源清理：连接被拒/超时后**无悬挂任务**（任务计数回到基线）。
//!
//! 结构：本文件是**入口**，只留共享的导入与常量；
//! **测试脚手架**（身份、夹具、断言辅助）在 `exception_matrix/scaffold.rs`，
//! 用例分两组 —— 认证面（错密码 / 截断 / 篡改）在
//! `exception_matrix/cases_auth.rs`，会话面（重放 / 半关闭 / 资源清理）在
//! `exception_matrix/cases_session.rs`。三者都以 `include!` 拼回**本模块**
//! （而不是另起子模块），因此用例的全限定名与拆分前完全一致
//! （`wrong_password_rejected_and_target_untouched` 等，不带任何模块前缀）。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient};
use lengsuo_trojan::codec;
use lengsuo_trojan::server::{Error, Inbound, Server, Timeouts, Validator};
use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const PASSWORD: &str = "exception-matrix-good-password";
const BAD_PASSWORD: &str = "exception-matrix-wrong-password";
const PAYLOAD: &[u8] = b"exception-matrix-payload";
/// 回显后端按 `PAYLOAD.len()` 读取并原样回写，故回程等于 PAYLOAD。
const REPLY: &[u8] = PAYLOAD;
/// 参考默认握手截止 60s 太长；本文件用 2s 观测“写一半后静默”的有界拒绝，
/// 并确保 `CLOSE_BOUND` 明显大于它且又远小于总预算。
const HANDSHAKE: Duration = Duration::from_secs(2);
/// 单次读/写/任务回收的观察上限。
const WAIT: Duration = Duration::from_secs(8);
const CLOSE_BOUND: Duration = Duration::from_secs(8);
const TOTAL: Duration = Duration::from_secs(45);

include!("exception_matrix/scaffold.rs");
include!("exception_matrix/cases_auth.rs");
include!("exception_matrix/cases_session.rs");
