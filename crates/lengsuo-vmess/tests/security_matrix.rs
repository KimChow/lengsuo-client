//! VMess **多安全档异常矩阵**：3 档 × 7 类异常，逐条有明确断言。
//!
//! 档位（`SecurityOption`）：`None` / `Aes128Gcm` / `ChaCha20Poly1305`。
//! 异常类别：
//! 1. **错密码**（cmd key 不匹配）⇒ AuthID 校验失败（`InvalidUser`）。
//! 2. **截断**（头部 / 长度段 / 载荷段各截一处）⇒ `Truncated` / `Io`，
//!    绝不 panic、绝不返回明文。
//! 3. **篡改**（AAD / nonce / tag 各改一处）⇒ `AuthFailed`。
//! 4. **重放**（同一 AuthID 重发）⇒ `Replay`。
//! 5. **半关闭**（写端关闭后读端 EOF 边界）⇒ 读到 EOF 帧或干净关闭。
//! 6. **超时**（对端不响应）⇒ 读端在上限内返回，不无限挂起。
//! 7. **清理**（连接结束后资源释放、无后台任务残留）⇒ 帧上下文无残留状态。
//!
//! 全部用例都带**总超时**（`tokio::time::timeout`），避免 CI 上挂死。
//! 全部只用回环地址、临时端口、假凭据；日志不输出密钥/明文/口令。
//!
//! 协议事实（见 `docs/vmess-status.md`）：安全档只作用于**数据段**；请求头与
//! 响应头两段 AEAD 恒为 AES-128-GCM。因此「篡改 AAD / nonce」在头部用例里
//! 对两档是同一条路径，在数据段用例里才分档。
//!
//! **文件结构**：本文件是测试目标入口（原 622 行超限文件）。用例按主题拆到
//! `tests/security_matrix/` 下：
//! - `common.rs`：共享常量（`CASE_TIMEOUT` / `CMD_KEY` / `BODY_KEY` / `BODY_IV` /
//!   `NOW` / `TIERS`）与助手（`suite_of` / `plan_header` / `seal_request` /
//!   `accept_session`）。
//! - `header_auth.rs`：头部异常（错密码 / 截断 / 篡改 / 重放）。
//! - `body_crypto.rs`：数据段密码学（篡改检出 / none 档明文 / 长度段形态 /
//!   掩码流推进）。
//! - `body_stream.rs`：数据段流生命周期（EOF 帧 / 半帧截断 / 跨连接状态）。
//! - `half_close_timeout.rs`：传输层半关闭与超时上限。
//! - `tier_policy.rs`：档位 fail-closed 语义（哨兵档 / 未知字节 / 头部解析）。
//!
//! 拆法用 `include!` **文本并入**同一模块（不是 `mod` 子模块）——这样用例名
//! **不带模块前缀**，与拆分前逐字一致（`mod` 方案会把名字变成 `header_auth::xxx`，
//! 属于改名）。代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use std::time::Duration;

use lengsuo_vmess::aead::{self, HeaderSuite};
use lengsuo_vmess::bodyframe::{BodyCipher, BodyFrame, BodySuite, SizeMode};
use lengsuo_vmess::chunkframe::DataSizeParser;
use lengsuo_vmess::consts::{SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE};
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use lengsuo_vmess::server::decode::{decode_request_header, HeaderDecodeError, HeaderSecurity};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

include!("security_matrix/common.rs");
include!("security_matrix/header_auth.rs");
include!("security_matrix/body_crypto.rs");
include!("security_matrix/body_stream.rs");
include!("security_matrix/half_close_timeout.rs");
include!("security_matrix/tier_policy.rs");
