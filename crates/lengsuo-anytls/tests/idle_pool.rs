//! AnyTLS v2 空闲会话复用池的端到端用例。
//!
//! 本仓没有客户端出站运行时（`src/` 只有纯状态机），故夹具在测试内组装一个
//! 最小客户端会话来扮演「客户端运行时」：认证 → Settings → 每条流 SYN+PUSH →
//! 按流编号分发回程数据。夹具见 `idle_pool/harness.rs`。
//!
//! 子用例按主题拆分：
//! - `pool_semantics`：复用命中、超时回收、最小保留数、容量上限、关闭注销；
//! - `driver`：回收驱动的定时行为与有界等待；
//! - `stress`：N ≥ 32 条并发流压在一条**复用**出来的连接上，断言无串包、无死锁。
//!
//! 用例只使用回环地址、临时端口与测试专用假凭据；口令不进入任何日志或断言文本。

#[path = "idle_pool/driver.rs"]
mod driver;
#[path = "idle_pool/harness.rs"]
mod harness;
#[path = "idle_pool/pool_semantics.rs"]
mod pool_semantics;
#[path = "idle_pool/stress.rs"]
mod stress;
