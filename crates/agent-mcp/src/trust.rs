//! TrustGate：MCP 工具调用的纯内存授权原语（fail-closed）。
//!
//! 本模块只做判定，不接进程、不接 Runtime，也不读写配置：它只是
//! 「现在是否允许调用某个工具」这一问题的权威回答者，供上层持有。
//!
//! 判定规则：`can_call(tool)` 当且仅当三个条件同时成立——
//! 1. 该 server 处于 trusted 状态（[`TrustGate::set_trusted`]，默认不可信）；
//! 2. server 总开关启用（[`TrustGate::set_server_enabled`]）；
//! 3. 该工具被**显式**登记为启用（[`TrustGate::set_tool_enabled`]）。
//!
//! 关键不变量：server 启用与工具登记都不授予 trust。未登记的工具一律拒绝，
//! 撤销 trust 立即让所有调用被拒，且不影响既有 trust 之外的登记状态。

use std::collections::HashMap;

/// 单个 MCP server 的工具调用信任门（进程内、非线程安全）。
///
/// 类型是纯数据，不含锁与异步；并发场景由上层独占持有或包一层同步原语，
/// 语义上每次判定都是对当前状态的读取。
#[derive(Debug, Clone, Default)]
pub struct TrustGate {
    trusted: bool,
    server_enabled: bool,
    /// 工具名 → 是否显式启用。只记录被登记过的工具；缺键即「未登记」，拒绝。
    tools: HashMap<String, bool>,
}

impl TrustGate {
    /// 新建默认门：不可信、server 未启用、无任何工具登记。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 授予或撤销 trust。撤销后所有 [`TrustGate::can_call`] 立即返回 `false`；
    /// 重新授予时其他状态（server 开关与工具登记）保持不变。
    pub fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }

    /// 当前是否处于 trusted 状态。
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.trusted
    }

    /// 启用或停用 server 总开关。停用只切断调用通路，不撤销 trust，
    /// 也不擦除工具登记；重新启用后两者仍然生效。
    pub fn set_server_enabled(&mut self, enabled: bool) {
        self.server_enabled = enabled;
    }

    /// 当前 server 总开关状态。
    #[must_use]
    pub fn is_server_enabled(&self) -> bool {
        self.server_enabled
    }

    /// 显式登记某个工具的启用状态。以 `false` 登记表示「已登记但禁用」，
    /// 与「未登记」在判定结果上同样拒绝，但语义不同：登记动作本身不构成授权。
    pub fn set_tool_enabled(&mut self, name: &str, enabled: bool) {
        self.tools.insert(name.to_string(), enabled);
    }

    /// 某个工具是否被显式登记为启用（不检查 trust 与 server 开关）。
    #[must_use]
    pub fn is_tool_enabled(&self, name: &str) -> bool {
        self.tools.get(name).is_some_and(|enabled| *enabled)
    }

    /// 是否允许调用该工具：trust、server 启用、工具显式启用三者缺一不可。
    /// 未登记的工具走 `HashMap::get` 的 `None` 分支，同样拒绝（fail-closed）。
    #[must_use]
    pub fn can_call(&self, name: &str) -> bool {
        self.trusted && self.server_enabled && self.is_tool_enabled(name)
    }
}

#[cfg(test)]
mod tests {
    use super::TrustGate;

    #[test]
    fn default_is_fully_denied() {
        let gate = TrustGate::new();
        assert!(!gate.is_trusted());
        assert!(!gate.is_server_enabled());
        assert!(!gate.can_call("read_file"));
    }

    #[test]
    fn all_three_conditions_are_required() {
        let mut gate = TrustGate::new();
        gate.set_trusted(true);
        gate.set_server_enabled(true);
        gate.set_tool_enabled("read_file", true);
        assert!(gate.can_call("read_file"));

        gate.set_tool_enabled("read_file", false);
        assert!(!gate.can_call("read_file"));

        gate.set_tool_enabled("read_file", true);
        gate.set_server_enabled(false);
        assert!(!gate.can_call("read_file"));

        gate.set_server_enabled(true);
        gate.set_trusted(false);
        assert!(!gate.can_call("read_file"));
    }
}
