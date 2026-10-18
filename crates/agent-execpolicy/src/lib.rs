//! 工具调用的策略判定层（对照 参考实现 的 execpolicy crate）。
//!
//! 职责边界：
//! - 纯逻辑、零平台依赖：不触碰文件系统、进程或网络，只对上层提交的
//!   [`AccessRequest`] 给出 [`Decision`]；执行与强制由后续 agent-sandbox 负责。
//! - 依赖只有 std + serde + serde_json。
//!
//! 判定语义：按类别取规则段，逐条匹配，**首个命中生效**；无命中返回
//! [`Decision::Ask`]（fail-closed 倾向：拿不准就问）。
//!
//! 规则文件形态（照 参考端 tsbx_rules.json，[`Policy::from_json_str`]）：顶层
//! `file` / `process` / `network` 三段，每条规则 = `pattern` + `match`
//! （`glob` 或 `prefix`）+ `decision`（`allow`/`deny`/`ask`）+ 可选 `reason`。
//! 缺段视为空数组；未知字段报错（拼写错误不静默吞掉）。
//!
//! [`Policy::security_baseline`]（即 `Default`）硬编码安全基线：
//! - Deny 全操作（含读取）：`.ssh/**`、`.gnupg/**`；
//! - Allow 包管理器缓存目录（`.cargo/`、`.npm/` 等前缀）；
//! - 其余默认 Ask。自定义策略可整体替换基线。
//!
//! 目标串约定：归一化后的字符串（家目录相对路径、域名或命令串）；
//! 归一化与越权检测属执行层职责，本 crate 只判。

#![forbid(unsafe_code)]

mod matcher;
mod policy;
mod types;

pub use policy::Policy;
pub use types::{AccessKind, AccessRequest, Assessment, Decision, Matcher, Rule};

/// 对一次访问请求做出策略判定。
///
/// 首个命中的规则生效；无任何规则命中 ⇒ `Ask`（fail-closed）。
/// 纯函数：不修改策略，不产生副作用。
pub fn assess(policy: &Policy, request: &AccessRequest) -> Assessment {
    policy
        .rules_for(request.kind)
        .iter()
        .find(|rule| rule.matches(&request.target))
        .map_or_else(Assessment::default_ask, Assessment::matched)
}
