#![forbid(unsafe_code)]
//! `lengsuo-ipc` — 本地网关客户端（桌面壳与移动端共用）。
//!
//! 协议形态（与 `agent-gateway` 的既有契约一致，**不改**）：
//! - 握手：读 `%LOCALAPPDATA%/lengsuo/gateway.json` = `{port, pid, token}`，
//!   ACL 限当前用户，退出即失效；
//! - RPC：`POST /rpc`，`{action:"<域>:<动作>", payload}` → `{code, msg, data}`；
//! - 事件：`GET /events`（WebSocket），一行一 JSON。
//!
//! 为什么要独立成 crate：这段客户端原本住在 `lengsuo-agent` 的
//! `crates/lengsuo-shell/src/gateway/`（约 1150 行）。桌面壳仓
//! （`lengsuo-desktop`）要接本地网关，若直接依赖整个 agent 仓偏重；
//! 移动端若要连本机网关也用得上。抽出来 ⇒ **一份实现，多端共用**。
//!
//! 本 crate 只做**客户端**；服务端在 `lengsuo-agent` 的 `agent-gateway`。

/// 骨架占位：随首批卡逐块填充。保持 crate 可编译、可被下游引用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_constructible() {
        assert_eq!(Placeholder, Placeholder);
    }
}
