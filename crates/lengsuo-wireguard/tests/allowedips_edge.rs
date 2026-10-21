//! allowedIPs 路由表的**边界**用例：非规范前缀、缺省路由、/0 与 /32 边界、
//! IPv6 前缀、peer 移除后的 fail-closed、多 peer 路由隔离。
//!
//! 参考：wireguard-go `device/allowedips.go`（commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）。
//!
//! 断言的期望值取自参考实现的**真实行为**：在参考仓内直接调用
//! `device.AllowedIPs` 回放同一串操作、取回 lookup 的归属 peer，再逐条比对；
//! 不是用自家 roundtrip 反推期望值。
//!
//! 本文件只做**路由表**层面的边界验证，不涉及握手/传输层，也不做真实
//! socket 互通；互通由 `tests/wireguard_go.rs` 负责。
//!
//! 全部用例只使用假地址与假 peer 编号，不含任何真实凭据。

#[path = "allowedips_edge/canonical.rs"]
mod canonical;
#[path = "allowedips_edge/default_route.rs"]
mod default_route;
#[path = "allowedips_edge/fixture.rs"]
mod fixture;
#[path = "allowedips_edge/peer_scope.rs"]
mod peer_scope;
