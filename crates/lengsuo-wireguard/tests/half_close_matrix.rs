//! WireGuard 异常路径矩阵补缺：半关闭 / 超时 / 清理。
//!
//! 覆盖 `docs/audit-all1.md` §3 中 WireGuard 的三格：
//! - 半关闭 ❌（此前只有半包拒绝）→ 本文件 `half_close` 子模块；
//! - 超时 △（此前只有 keepalive 定时器）→ 本文件 `timeout` 子模块；
//! - 清理 △（此前只有 peers/allowedips 静态移除）→ 本文件 `cleanup` 子模块。
//!
//! 全部用例只使用回环地址、临时端口与假凭据；日志与断言都不输出密钥/明文。
//! 认证或解码失败一律 fail-closed。
//!
//! 本卡是 Rust↔Rust 方向，只补「异常路径矩阵」这一维，**不**声称完成与
//! wireguard-go 参考实现的互通。

#[path = "half_close_matrix/cleanup.rs"]
mod cleanup;
#[path = "half_close_matrix/fixture.rs"]
mod fixture;
#[path = "half_close_matrix/half_close.rs"]
mod half_close;
#[path = "half_close_matrix/timeout.rs"]
mod timeout;
