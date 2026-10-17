//! TrustGate 纯内存信任门验收（先失败后实现，TDD 红灯锚点）。
//!
//! 只测授权原语本身：默认不可信、撤销即全拒、未登记工具拒绝、
//! server 启用不等于授予 trust。不接进程、不接 Runtime。

#![forbid(unsafe_code)]

use agent_mcp::TrustGate;

#[test]
fn default_gate_is_untrusted_and_denies_everything() {
    let mut gate = TrustGate::new();
    gate.set_server_enabled(true);
    gate.set_tool_enabled("read_file", true);
    // server 启用与工具登记都不等于授予 trust：默认不可信必须全拒。
    assert!(!gate.is_trusted());
    assert!(!gate.can_call("read_file"));
    assert!(!gate.can_call("anything"));
}

#[test]
fn can_call_requires_trust_server_enabled_and_explicit_tool() {
    let mut gate = TrustGate::new();
    gate.set_trusted(true);
    gate.set_server_enabled(true);
    gate.set_tool_enabled("read_file", true);
    assert!(gate.can_call("read_file"));

    // 三条件任一缺失都拒绝。
    // 从未登记过的工具必须拒绝，即使其余两个条件都成立。
    assert!(!gate.can_call("never_registered"));

    let mut no_server = TrustGate::new();
    no_server.set_trusted(true);
    no_server.set_tool_enabled("read_file", true);
    assert!(!no_server.can_call("read_file"), "server 未启用必须拒绝");

    let mut no_tool = TrustGate::new();
    no_tool.set_trusted(true);
    no_tool.set_server_enabled(true);
    assert!(!no_tool.can_call("read_file"), "工具未显式启用必须拒绝");
}

#[test]
fn revoking_trust_denies_immediately_and_completely() {
    let mut gate = TrustGate::new();
    gate.set_trusted(true);
    gate.set_server_enabled(true);
    gate.set_tool_enabled("read_file", true);
    gate.set_tool_enabled("write_file", true);
    assert!(gate.can_call("read_file"));

    gate.set_trusted(false);
    assert!(!gate.can_call("read_file"));
    assert!(!gate.can_call("write_file"));

    // 撤销后重新授予，既有登记保持有效（撤销是开关语义，不擦除登记）。
    gate.set_trusted(true);
    assert!(gate.can_call("read_file"));
}

#[test]
fn disabling_server_denies_without_affecting_trust_or_registry() {
    let mut gate = TrustGate::new();
    gate.set_trusted(true);
    gate.set_server_enabled(true);
    gate.set_tool_enabled("read_file", true);
    assert!(gate.can_call("read_file"));

    gate.set_server_enabled(false);
    assert!(!gate.can_call("read_file"));
    assert!(gate.is_trusted(), "关闭 server 不得撤销 trust");

    gate.set_server_enabled(true);
    assert!(
        gate.can_call("read_file"),
        "重新启用 server 后登记与 trust 仍在"
    );
}

#[test]
fn tool_level_disable_and_reenable_is_per_tool() {
    let mut gate = TrustGate::new();
    gate.set_trusted(true);
    gate.set_server_enabled(true);
    gate.set_tool_enabled("read_file", true);
    gate.set_tool_enabled("exec", true);

    gate.set_tool_enabled("exec", false);
    assert!(!gate.can_call("exec"));
    assert!(gate.can_call("read_file"), "单工具禁用不得波及其他工具");

    gate.set_tool_enabled("exec", true);
    assert!(gate.can_call("exec"));
}

#[test]
fn set_tool_enabled_registers_tool_without_enabling_it() {
    let mut gate = TrustGate::new();
    gate.set_trusted(true);
    gate.set_server_enabled(true);
    gate.set_tool_enabled("read_file", false);
    assert!(
        !gate.can_call("read_file"),
        "以 false 登记不得被视作显式启用"
    );
    assert!(gate.is_trusted());
}
