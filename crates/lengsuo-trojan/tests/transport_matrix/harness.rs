//! 外层传输矩阵的**共享骨架**：外层档位、动作、测试身份、回环业务目标、
//! 有界 IO 与客户端动作。
//!
//! 与外层无关的 trojan 侧逻辑（写头、写载荷、关写端、读回程）全部集中在这里；
//! 逐外层的差异只体现在两处：
//!
//! 1. **怎么建流**：TLS 之后套 `ws` / `httpupgrade` 升级，或直接用裸 TLS 流；
//! 2. **怎么关写端**：WS 走 `Close` 帧（`ws::Connection::poll_shutdown`），
//!    TCP / HTTPUpgrade 走底层 FIN（`AsyncWriteExt::shutdown`）。
//!
//! 观测面只有一个：**回环业务目标的 accept 计数**。它证明“trojan 头部与载荷
//! 确实穿过外层传输抵达了业务”，也是所有拒绝类用例的唯一“未泄漏”判据。
//! 不用“我方读操作超时”当拒绝证据（沿用 `tests/exception_matrix.rs` 的纪律）。
//!
//! 结构：本文件是**入口**，只留共享的导入与 `WAIT` 转出；实体按职责拆到
//! `harness/model.rs`（档位 / 动作 / 观测结果 / 常量）、
//! `harness/identity.rs`（测试身份与回环业务目标）、
//! `harness/client.rs`（trojan 侧动作与有界 IO）与 `harness/verdict.rs`
//! （服务端处理判定变体）。四者都以 `include!` 拼回**本模块**，
//! 因此 `harness::` 下的可见性与拆分前完全一致。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient, TlsServer};
use lengsuo_trojan::server::Error as ServerError;
use lengsuo_trojan::stream::send_request;
use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

pub use super::support::WAIT;

include!("harness/model.rs");
include!("harness/identity.rs");
include!("harness/client.rs");
include!("harness/verdict.rs");
