//! VMess **多安全档异常矩阵（补缺）**：逐档具名用例 + 档位不一致 fail-closed
//! + 弱档显式区分 + 档位枚举越界显式拒绝。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! 与既有 `tests/security_matrix.rs` 的分工：
//! - 既有文件：3 档 × 7 类异常的**循环**写法（一条用例覆盖三档）。**⛔ 不改**。
//! - 本文件：同一组场景的**逐档具名**写法（`tier_none_*` / `tier_aes128gcm_*` /
//!   `tier_chacha20poly1305_*`），外加既有文件**没有**的三条安全关键路径：
//!   1. 档位不一致（客户端声明档 ≠ 实际产出数据段的档）⇒ 必须 fail-closed；
//!   2. 弱档（`none` / `zero`）行为必须**显式区分**（不得声称已禁用而实际可用）；
//!   3. 档位枚举越界（不存在的档位编号）⇒ 必须**显式拒绝**。
//!
//! 协议事实（参考固定 commit `d2758a02`）：
//! - 安全档只作用于**数据段**（`proxy/vmess/encoding/server.go:264` 的
//!   `switch request.Security`）；请求头与响应头两段 AEAD 恒为 AES-128-GCM
//!   （`proxy/vmess/aead/encrypt.go` 两侧写死 `crypto.NewAesGcm`）。
//! - 服务端的数据段套件**由请求头的 security 字节决定**
//!   （`server.go:203` 的 `parseSecurityType`），参考入站**不钉档位**
//!   （`proxy/vmess/inbound/inbound.go` 全文无 `Security` 引用）。
//! - `SecurityType_NONE` 走 `buf.NewReader` / `NoOpAuthenticator`
//!   （`server.go:265-283`）⇒ **无 AEAD、无认证**。
//! - `SecurityType_ZERO` 头阶段放行（`server.go:114-124` 的 `parseSecurityType`
//!   认得 6），体阶段落到 `default:` ⇒ `invalid option: Security`
//!   （`server.go:323`）。
//! - 未知/哨兵档位（`UNKNOWN`=0、`AUTO`=2）头阶段即拒
//!   （`server.go:242-243`：`unknown security type`）。
//!
//! 全部用例只用回环地址、临时端口、假凭据；日志不输出密钥/明文/口令。
//! 全部异步用例带总超时（`tokio::time::timeout`）。

#[path = "security_matrix_extra/common.rs"]
mod common;
#[path = "security_matrix_extra/mismatch.rs"]
mod mismatch;
#[path = "security_matrix_extra/reference_interop.rs"]
mod reference_interop;
#[path = "security_matrix_extra/refhelpers.rs"]
mod refhelpers;
#[path = "security_matrix_extra/tier_cases.rs"]
mod tier_cases;
#[path = "security_matrix_extra/tier_policy.rs"]
mod tier_policy;
